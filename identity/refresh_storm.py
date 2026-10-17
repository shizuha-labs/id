"""
Population-wide refresh-storm detection (ADR-PLAT-002 §5-INV-2).

This module implements the *signal* side of the refresh-storm invariant: a
sliding-window counter over JWT refresh volume across the entire user
population, with rising-edge debouncing so that a single sustained storm emits
at most one audit signal per window rather than one per request.

Scope (per Sora's architecture call on PLAT-55, 2026-06-03):
  - §5-INV-2 ONLY: population-wide detection. There is NO per-upstream
    ``upstream_id`` attribution on shizuha-id's core refresh path — that lives
    on the auth-proxy sidecar's refresh-grant event (PLAT-43).
  - The ``WindowStrategy`` abstraction is the M-C strategy-interface hook. At
    M-A/M-B the only strategy is ``PopulationWideStrategy``; its
    ``attribution_summary`` is the degenerate single-bucket sentinel
    ``{"shizuha-id": <count>}`` that keeps the field present for M-C without
    pretending shizuha-id can attribute by upstream IdP.

M-C config-switch path (AC5) — swapping the window strategy is a *config*
change, not a code change. ``get_strategy()`` dispatches on the
``REFRESH_STORM_WINDOW_STRATEGY`` setting against ``_STRATEGY_REGISTRY``. To
land per-upstream partitioning at M-C:
  1. add a ``PerUpstreamPartitionStrategy(WindowStrategy)`` impl in this module;
  2. register it: ``_STRATEGY_REGISTRY["per-upstream"] = PerUpstreamPartitionStrategy``;
  3. set ``REFRESH_STORM_WINDOW_STRATEGY=per-upstream`` (env).
No emission code (``storm_views``/``audit``) or call site changes — the swap is
purely the setting + a new registry entry.

The Redis sliding-window log + edge-debounce is performed in a single atomic
Lua script to avoid races under concurrent refreshes.
"""
from __future__ import annotations

import abc
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import redis
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# Fixed local-IdP bucket label. shizuha-id cannot attribute refreshes to an
# upstream IdP (that is the sidecar's job, PLAT-43); every refresh it sees is,
# by definition, "shizuha-id-issued". This sentinel keeps
# ``upstream_attribution_summary`` shaped correctly for the M-C interface.
LOCAL_IDP_BUCKET = "shizuha-id"

# Redis keys (single global namespace — this is a *population-wide* window).
_EVENTS_KEY = "refresh_storm:events"
_ACTIVE_KEY = "refresh_storm:active"

# Atomic sliding-window-log + rising-edge debounce.
#   KEYS[1] = events sorted-set (score = event ms, member = unique id)
#   KEYS[2] = storm-active flag (armed across a storm, disarmed below threshold)
#   ARGV[1] = now_ms
#   ARGV[2] = window_ms
#   ARGV[3] = threshold
#   ARGV[4] = unique member id
#   ARGV[5] = active-flag safety TTL (ms)
# Returns {count, emit} where emit == 1 only on the rising edge of a storm.
#
# Hysteresis (AC2): the active flag is a *latch*, not a time-gate. It is armed
# (SET NX) only on the below->at-or-above-threshold transition — that single
# crossing is the one emit. While the count stays at/above threshold the latch
# stays set and SET NX fails, so a sustained storm emits exactly once no matter
# how long it lasts. The instant the count falls below threshold the latch is
# DELed, re-arming the detector so the *next* genuine crossing emits again. The
# safety TTL only guards against a permanently-stuck latch if the process dies
# mid-storm with no further records to disarm it; it is deliberately much longer
# than the window so it never expires under sustained load (which would
# re-fire — the bug this replaces).
_WINDOW_LUA = """
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, tonumber(ARGV[1]) - tonumber(ARGV[2]))
local count = redis.call('ZCARD', KEYS[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
local emit = 0
if count >= tonumber(ARGV[3]) then
  if redis.call('SET', KEYS[2], '1', 'NX', 'PX', tonumber(ARGV[5])) then
    emit = 1
  end
else
  redis.call('DEL', KEYS[2])
end
return {count, emit}
"""


@dataclass(frozen=True)
class StormDecision:
    """Outcome of recording a single refresh event against the window."""

    count: int
    threshold: int
    window_s: int
    should_emit: bool
    attribution_summary: dict = field(default_factory=dict)


def _config_threshold() -> int:
    return int(getattr(settings, "REFRESH_STORM_THRESHOLD", 20))


def _config_window_s() -> int:
    return int(getattr(settings, "REFRESH_STORM_WINDOW_S", 10))


def _config_active_ttl_s() -> int:
    # Safety TTL for the storm-active latch. Only relevant if the process dies
    # mid-storm leaving the latch armed with no record() left to disarm it.
    # Must be >> the window so it never expires under sustained load.
    return int(getattr(settings, "REFRESH_STORM_ACTIVE_TTL_S", 3600))


class WindowStrategy(abc.ABC):
    """
    Strategy interface for refresh-storm windowing (the M-C hook).

    A strategy owns (a) how a refresh event is recorded into a window and the
    threshold-crossing decision, and (b) how the observed volume is attributed
    into buckets for the audit signal. M-A/M-B ship exactly one strategy
    (population-wide); M-C may introduce partitioned strategies without
    touching the call site.
    """

    @abc.abstractmethod
    def record(self, *, now_ms: Optional[int] = None) -> StormDecision:
        """Record one refresh event and return the resulting decision."""

    @abc.abstractmethod
    def attribution_summary(self, count: int) -> dict:
        """Bucket the observed count for the audit signal's attribution field."""


class PopulationWideStrategy(WindowStrategy):
    """
    §5-INV-2 population-wide window: one global sliding window over all refresh
    volume, threshold ``T`` over window ``W`` seconds, rising-edge debounced.
    """

    def __init__(
        self,
        client: redis.Redis,
        *,
        threshold: Optional[int] = None,
        window_s: Optional[int] = None,
        active_ttl_s: Optional[int] = None,
    ) -> None:
        self._client = client
        self._threshold = threshold if threshold is not None else _config_threshold()
        self._window_s = window_s if window_s is not None else _config_window_s()
        self._active_ttl_s = (
            active_ttl_s if active_ttl_s is not None else _config_active_ttl_s()
        )
        self._script = client.register_script(_WINDOW_LUA)

    def record(self, *, now_ms: Optional[int] = None) -> StormDecision:
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        window_ms = self._window_s * 1000
        active_ttl_ms = self._active_ttl_s * 1000
        member = f"{now_ms}:{uuid.uuid4().hex}"
        count, emit = self._script(
            keys=[_EVENTS_KEY, _ACTIVE_KEY],
            args=[now_ms, window_ms, self._threshold, member, active_ttl_ms],
        )
        count = int(count)
        return StormDecision(
            count=count,
            threshold=self._threshold,
            window_s=self._window_s,
            should_emit=bool(int(emit)),
            attribution_summary=self.attribution_summary(count),
        )

    def attribution_summary(self, count: int) -> dict:
        # Degenerate single-bucket sentinel: shizuha-id has no upstream IdP
        # attribution. Present purely as the M-C interface hook.
        return {LOCAL_IDP_BUCKET: count}


# Registry of selectable window strategies (the AC5 / M-C config-switch surface).
# ``get_strategy()`` dispatches on the ``REFRESH_STORM_WINDOW_STRATEGY`` setting;
# M-C adds ``PerUpstreamPartitionStrategy`` here without touching the call site.
_STRATEGY_REGISTRY: dict = {
    "population-wide": PopulationWideStrategy,
}

_client_lock = threading.Lock()
# Separate lock for strategy init: get_strategy() must not hold _client_lock
# while calling _get_client() (which also takes _client_lock) — threading.Lock
# is not reentrant, so sharing one lock across both would self-deadlock.
_strategy_lock = threading.Lock()
_client: Optional[redis.Redis] = None
_strategy: Optional[WindowStrategy] = None


def _get_client() -> redis.Redis:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                url = getattr(
                    settings,
                    "REFRESH_STORM_REDIS_URL",
                    getattr(settings, "CELERY_BROKER_URL", "redis://localhost:6379/2"),
                )
                _client = redis.Redis.from_url(url, decode_responses=True)
    return _client


def get_strategy() -> WindowStrategy:
    """Return the process-wide window strategy.

    Selected by the ``REFRESH_STORM_WINDOW_STRATEGY`` setting (default
    ``"population-wide"``). Adding a new strategy at M-C is a registry entry +
    a setting change — no edit to this function.
    """
    global _strategy
    if _strategy is None:
        with _strategy_lock:
            if _strategy is None:
                name = getattr(
                    settings, "REFRESH_STORM_WINDOW_STRATEGY", "population-wide"
                )
                try:
                    strategy_cls = _STRATEGY_REGISTRY[name]
                except KeyError:
                    raise ImproperlyConfigured(
                        f"REFRESH_STORM_WINDOW_STRATEGY={name!r} is not registered; "
                        f"valid options: {sorted(_STRATEGY_REGISTRY)}"
                    )
                _strategy = strategy_cls(_get_client())
    return _strategy


def set_strategy(strategy: Optional[WindowStrategy]) -> None:
    """Override the active strategy (used by tests / future M-C wiring)."""
    global _strategy
    _strategy = strategy
