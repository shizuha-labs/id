"""
Step-up re-authentication core (HIVE-6 / HLD page 7197343e, v1.0).

Producer side of the destructive-action step-up gate. This module owns the
factor-invariant machinery behind the three endpoints (begin / answer / verify,
wired in ``stepup_views`` + ``internal_urls``):

  * the §4.2 action -> minimum-factor-strength policy registry (config-driven,
    mirroring ``REFRESH_STORM_WINDOW_STRATEGY``);
  * the pluggable ``SecondFactor`` interface + the ``TOTPSecondFactor`` (v1
    floor) and a dev/CI-only ``PasswordSecondFactor`` that is fail-closed in
    prod;
  * RS256 step-up-token mint/verify (reusing ``oauth_keys.get_signing_material``);
  * the Redis single-use jti deny-list and the TOTP single-mint marker (§8).

The wire contract (shapes, claims, scope tuple) is frozen by the HLD; this
module is the faithful producer implementation, nothing more.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta, timezone as dt_timezone
from typing import Optional

import jwt as pyjwt
import redis
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from .oauth_keys import get_signing_material

logger = logging.getLogger(__name__)

TOKEN_SCOPE = 'step_up'

# Factor strength ordering (HLD §4.2): a presented factor weaker than the
# action's floor is refused at mint time. Prod forbids `password` satisfying any
# destructive action's floor (fail-closed health check, see prod_gate_ok).
FACTOR_STRENGTH = {
    'password': 1,
    'totp': 2,
    'webauthn': 3,
    'recovery': 1,
}

# Irreversible actions additionally bind the minted token to the originating
# session via cnf.ath (A7 option (a)). Reversible actions omit cnf.
IRREVERSIBLE_ACTIONS = {'hard-delete'}


# ---------------------------------------------------------------------------
# §2 / §4.2 — action policy: TTLs and minimum factor strength.
#
# Both are operator data, dialled via settings (env), not hardcoded — the
# STEP_UP_ACTION_POLICY mapping mirrors the refresh-storm config-registry
# precedent. Each entry: {"ttl_s": int, "min_factor": "totp"|...}.
# ---------------------------------------------------------------------------
_DEFAULT_ACTION_POLICY = {
    'hard-delete': {'ttl_s': 60, 'min_factor': 'totp'},
    'export': {'ttl_s': 300, 'min_factor': 'totp'},
    'rename': {'ttl_s': 60, 'min_factor': 'totp'},
    'dashboard': {'ttl_s': 300, 'min_factor': 'totp'},
}


def get_action_policy() -> dict:
    """Return the action -> {ttl_s, min_factor} policy (settings-overridable)."""
    return getattr(settings, 'STEP_UP_ACTION_POLICY', _DEFAULT_ACTION_POLICY)


def action_ttl_s(action: str) -> Optional[int]:
    policy = get_action_policy().get(action)
    return policy['ttl_s'] if policy else None


def action_min_factor(action: str) -> Optional[str]:
    policy = get_action_policy().get(action)
    return policy['min_factor'] if policy else None


def is_known_action(action: str) -> bool:
    return action in get_action_policy()


def factor_meets_floor(presented_factor: str, action: str) -> bool:
    """True iff the presented factor's strength >= the action's §4.2 floor."""
    floor = action_min_factor(action)
    if floor is None:
        return False
    return FACTOR_STRENGTH.get(presented_factor, 0) >= FACTOR_STRENGTH.get(floor, 0)


def prod_gate_ok(backend_name: str, action: str) -> bool:
    """Fail-closed prod gate (HLD §4 Option A): in prod the password backend may
    never satisfy a destructive action's floor.

    Mirrors HIVE-4 §9.1 stub-gating: dev/CI may select ``password`` for local
    flows, but a prod deployment that tries to gate a destructive action with
    password-only is rejected (the caller refuses to mint).
    """
    if backend_name != 'password':
        return True
    return bool(getattr(settings, 'DEBUG', False)) or bool(
        getattr(settings, 'STEP_UP_ALLOW_PASSWORD_BACKEND', False)
    )


# ---------------------------------------------------------------------------
# Pluggable SecondFactor interface (HLD §4) — registry-selected, mirroring
# REFRESH_STORM_WINDOW_STRATEGY. TOTP is the v1 concrete; password is dev/CI
# only; WebAuthn is the L2 (HIVE-20) addition with no contract change.
# ---------------------------------------------------------------------------
class SecondFactor:
    """A second factor that can verify a challenge answer.

    ``name`` is the factor identifier used in the wire ``factor`` field and the
    §4.2 strength lookup. ``verify`` returns True iff the supplied answer is
    valid for ``device`` *and* records any single-use marker the factor needs.
    """
    name: str = ''

    def verify(self, *, device, answer, challenge) -> bool:
        raise NotImplementedError


class TOTPSecondFactor(SecondFactor):
    """RFC 6238 TOTP (``pyotp``), the v1 step-up floor (HLD §4 Option B).

    Skew is ±1 time-step max (§8). A given code is consumable once per
    ``(device, time_step)`` — the first successful answer marks that step used in
    Redis (§8a), so the same code cannot mint a second token within its window.
    """
    name = 'totp'

    def verify(self, *, device, answer, challenge) -> bool:
        import pyotp
        if not device or not device.confirmed or not answer:
            return False
        totp = pyotp.TOTP(device.secret)
        # valid_window=1 -> ±1 step (Akira §8: skew ±1 step max).
        if not totp.verify(answer, valid_window=1):
            return False
        # §8a single-mint: pin the exact matched time-step and SET NX it.
        step = _matched_time_step(totp, answer, window=1)
        if step is None:
            return False
        if not _claim_totp_step(device.id, step):
            # Code already minted within this window — reject the replay.
            return False
        return True


class RecoveryCodeSecondFactor(SecondFactor):
    """Single-use recovery-code login factor (PLAT-493)."""

    name = 'recovery'

    def verify(self, *, device, answer: str, challenge) -> bool:
        from .models import RecoveryCode

        return RecoveryCode.consume(challenge.user, answer)


class PasswordSecondFactor(SecondFactor):
    """Account-password re-entry. **Dev/CI only** — fail-closed in prod.

    Never satisfies a destructive action's floor in a prod deployment (see
    ``prod_gate_ok``); selectable for local/test flows so the wire contract can
    be exercised without provisioning TOTP.
    """
    name = 'password'

    def verify(self, *, device, answer, challenge) -> bool:
        if not answer:
            return False
        return challenge.user.check_password(answer)


class WebAuthnSecondFactor(SecondFactor):
    """WebAuthn/passkey assertion backend (HIVE-20 L2).

    Uses Yubico's ``python-fido2`` ``Fido2Server``. The frozen step-up wire
    contract is unchanged: ``begin`` returns a factor-specific challenge and
    ``answer`` submits an ``assertion`` object to this backend.
    """
    name = 'webauthn'

    def verify(self, *, device, answer, challenge) -> bool:
        if not device or not device.confirmed or not answer:
            return False
        credential = webauthn_credential_from_device(device)
        if credential is None or not challenge.webauthn_state:
            return False
        try:
            updated = _webauthn_server().authenticate_complete(
                challenge.webauthn_state, [credential], answer,
            )
        except Exception:
            logger.exception('WebAuthn assertion verification failed')
            return False
        if updated is not None:
            device.webauthn_credential_data = _encode_webauthn_credential(updated)
            device.save(update_fields=['webauthn_credential_data', 'updated_at'])
        return True


_FACTOR_REGISTRY: dict = {
    'totp': TOTPSecondFactor,
    'password': PasswordSecondFactor,
    'webauthn': WebAuthnSecondFactor,
    'recovery': RecoveryCodeSecondFactor,
}


def get_factor(name: str) -> SecondFactor:
    """Instantiate the registered second factor by name."""
    try:
        return _FACTOR_REGISTRY[name]()
    except KeyError:
        raise ImproperlyConfigured(
            f'step-up factor {name!r} is not registered; '
            f'valid options: {sorted(_FACTOR_REGISTRY)}'
        )


def _matched_time_step(totp, code: str, window: int) -> Optional[int]:
    """Return the absolute time-step index the code matched within ±window."""
    now = int(time.time())
    interval = totp.interval
    base_step = now // interval
    for offset in range(-window, window + 1):
        if totp.verify(code, for_time=(base_step + offset) * interval, valid_window=0):
            return base_step + offset
    return None


def verify_provisional_totp_device(*, device, answer: str) -> bool:
    """Verify a live TOTP against a not-yet-confirmed enrollment device.

    Enrollment confirmation must prove the owner scanned the newly provisioned
    secret before the device is marked confirmed. ``TOTPSecondFactor.verify``
    intentionally rejects unconfirmed devices, so the confirmation path uses this
    narrower helper while preserving the same ±1 step skew and single-mint claim.
    """
    import pyotp

    if not device or device.confirmed or not answer:
        return False
    totp = pyotp.TOTP(device.secret)
    if not totp.verify(answer, valid_window=1):
        return False
    step = _matched_time_step(totp, answer, window=1)
    if step is None:
        return False
    return _claim_totp_step(device.id, step)


# ---------------------------------------------------------------------------
# WebAuthn/passkey ceremony helpers (HIVE-20).
# ---------------------------------------------------------------------------
def _webauthn_server():
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity

    rp_id = getattr(settings, 'WEBAUTHN_RP_ID', 'localhost')
    rp_name = getattr(settings, 'WEBAUTHN_RP_NAME', 'Shizuha ID')

    def verify_origin(origin: str) -> bool:
        return webauthn_origin_allowed(origin)

    return Fido2Server(
        PublicKeyCredentialRpEntity(id=rp_id, name=rp_name),
        verify_origin=verify_origin,
    )


def webauthn_origin_allowed(origin: str) -> bool:
    """Fail-closed WebAuthn clientData.origin allowlist check.

    WebAuthn origin verification must never wildcard-open because of malformed
    or empty deployment settings. If ``WEBAUTHN_ALLOWED_ORIGINS`` derives to an
    empty list (for example a blank/path-only frontend URL, or an explicit empty
    override), every origin is rejected until the configuration is fixed.
    """
    allowed_origins = {
        item for item in getattr(settings, 'WEBAUTHN_ALLOWED_ORIGINS', [])
        if item
    }
    return bool(origin and allowed_origins and origin in allowed_origins)


def _encode_webauthn_credential(credential) -> str:
    from fido2.utils import websafe_encode
    return websafe_encode(bytes(credential))


def webauthn_credential_from_device(device):
    if not getattr(device, 'webauthn_credential_data', ''):
        return None
    from fido2.utils import websafe_decode
    from fido2.webauthn import AttestedCredentialData
    return AttestedCredentialData(websafe_decode(device.webauthn_credential_data))


def _jsonable_webauthn_state(state: dict) -> dict:
    return {
        key: (value.value if hasattr(value, 'value') else value)
        for key, value in state.items()
    }


def webauthn_registration_begin(user, *, existing_devices=None):
    from fido2.webauthn import (
        PublicKeyCredentialUserEntity,
        UserVerificationRequirement,
    )

    credentials = [
        credential for credential in (
            webauthn_credential_from_device(device)
            for device in (existing_devices or [])
        )
        if credential is not None
    ]
    options, state = _webauthn_server().register_begin(
        PublicKeyCredentialUserEntity(
            id=str(user.pk).encode('utf-8'),
            name=getattr(user, 'email', '') or getattr(user, 'username', str(user.pk)),
            display_name=getattr(user, 'username', '') or getattr(user, 'email', str(user.pk)),
        ),
        credentials=credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return dict(options), _jsonable_webauthn_state(state)


def webauthn_registration_complete(device, attestation_response):
    auth_data = _webauthn_server().register_complete(
        device.webauthn_state, attestation_response,
    )
    credential = auth_data.credential_data
    if credential is None:
        raise ValueError('WebAuthn registration response did not include credential data')
    from fido2.utils import websafe_encode
    device.webauthn_credential_data = _encode_webauthn_credential(credential)
    device.secret = websafe_encode(credential.credential_id)
    device.webauthn_state = {}
    device.save(update_fields=[
        'webauthn_credential_data', 'secret', 'webauthn_state', 'updated_at',
    ])
    return credential


def webauthn_authentication_begin(device):
    from fido2.webauthn import UserVerificationRequirement

    credential = webauthn_credential_from_device(device)
    if credential is None:
        raise ValueError('device has no WebAuthn credential data')
    options, state = _webauthn_server().authenticate_begin(
        [credential],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return dict(options), _jsonable_webauthn_state(state)

# ---------------------------------------------------------------------------
# Redis markers (HLD §8) — jti deny-list + TOTP single-mint. Reuses the
# refresh-storm Redis URL convention (DB 2).
# ---------------------------------------------------------------------------
_client_lock = threading.Lock()
_client: Optional[redis.Redis] = None

# Clock-skew margin (seconds) added to the jti deny-list TTL so a replay
# arriving just after exp within skew still hits the deny-list (Sora A4).
_SKEW_MARGIN_S = 30


def _get_client() -> redis.Redis:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                url = getattr(
                    settings,
                    'STEP_UP_REDIS_URL',
                    getattr(
                        settings,
                        'REFRESH_STORM_REDIS_URL',
                        getattr(settings, 'CELERY_BROKER_URL', 'redis://localhost:6379/2'),
                    ),
                )
                _client = redis.Redis.from_url(url, decode_responses=True)
    return _client


def _claim_totp_step(device_id: int, time_step: int) -> bool:
    """Atomically claim a (device, time_step) for single-mint (§8a).

    Returns True if this caller won the claim (first mint), False if the step was
    already consumed within its validity window.
    """
    key = f'stepup:totp:{device_id}:{time_step}'
    # one time-step (30s) + skew; the marker only needs to outlive the code.
    ttl = 30 + _SKEW_MARGIN_S
    try:
        return bool(_get_client().set(key, '1', nx=True, ex=ttl))
    except Exception:  # noqa: BLE001 — Redis hiccup must fail closed
        logger.exception('TOTP single-mint claim failed (failing closed)')
        return False


def claim_jti(jti: str, remaining_ttl_s: int) -> bool:
    """Atomically add a jti to the single-use deny-list at verify time (§6/§8).

    Returns True if this verify won the claim (token now spent), False if the jti
    was already consumed (replay / double-spend). TTL = remaining token lifetime
    + skew margin so a replay just past exp still collides.
    """
    key = f'stepup:used:{jti}'
    ttl = max(1, remaining_ttl_s + _SKEW_MARGIN_S)
    return bool(_get_client().set(key, '1', nx=True, ex=ttl))


# ---------------------------------------------------------------------------
# Token mint / verify (HLD §5.2 / §5.3 / §6) — RS256 via oauth_keys.
# ---------------------------------------------------------------------------
@dataclass
class StepUpScope:
    owner_id: int
    resource_id: str
    action: str

    def as_dict(self) -> dict:
        return {
            'owner_id': self.owner_id,
            'resource_id': self.resource_id,
            'action': self.action,
        }


@dataclass
class VerifyResult:
    valid: bool
    scope: Optional[dict] = None
    reason: str = ''
    factor: str = ''


def access_token_ath(access_token: str) -> str:
    """RFC 9449 ``ath``: base64url(SHA-256(access_token)), no padding (A7 (a)).

    NEVER the raw bearer token — only the hash. Used both to populate ``cnf.ath``
    at mint and to recompute the binding the consumer forwards as
    ``session_binding`` at verify.
    """
    digest = hashlib.sha256(access_token.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


def mint_step_up_token(scope: StepUpScope, *, ttl_s: int,
                       session_ath: str = '', factor: str = '') -> tuple[str, str, int]:
    """Mint a one-shot step-up JWT (RS256) for ``scope``.

    Returns ``(token, jti, exp_epoch)``. For irreversible actions a ``cnf.ath``
    claim binds the token to the originating session (A7 (a)); reversible actions
    omit ``cnf``. ``factor`` is recorded as a private proof-strength claim so
    consumers such as factor re-enrollment can reject a token minted with a
    weaker enrolled factor even when the action's static policy floor is lower.
    """
    now = timezone.now()
    exp = now + timedelta(seconds=ttl_s)
    jti = uuid.uuid4().hex
    payload = {
        'sub': str(scope.owner_id),  # JWT registered claim — must be a string
        'res': scope.resource_id,   # private claim, NOT aud (A5)
        'act': scope.action,
        'jti': jti,
        'iat': int(now.timestamp()),
        'exp': int(exp.timestamp()),
        'scope': TOKEN_SCOPE,
    }
    if factor:
        payload['fac'] = factor
    if scope.action in IRREVERSIBLE_ACTIONS:
        # cnf.ath binds to the minting session; never the raw token (pin 1).
        payload['cnf'] = {'ath': session_ath}

    material = get_signing_material()
    token = pyjwt.encode(
        payload, material['private_pem'], algorithm='RS256',
        headers={'kid': material['kid']},
    )
    return token, jti, int(exp.timestamp())


def verify_step_up_token(token: str, expected_scope: dict,
                         session_binding: str = '',
                         min_factor: str = '') -> VerifyResult:
    """Validate + atomically consume a step-up token (HLD §5.3 / §6).

    Single-use is enforced here, not at mint: the first successful verify claims
    the jti (Redis SET NX), so a concurrent double-spend resolves to one winner.
    For irreversible actions the token's ``cnf.ath`` is compared constant-time
    against the consumer-forwarded ``session_binding`` (pin 2); a mismatch — or a
    rotated access token whose recomputed ath no longer matches — fails closed
    (pin 3) -> ``binding_mismatch``.

    ``min_factor`` optionally requires the token's private factor proof claim
    to be at least that strength. Missing/weak factor proof fails closed.

    ``valid:false`` reasons: expired | scope_mismatch | factor_below_floor |
    replayed | unknown | binding_mismatch.
    """
    material = get_signing_material()
    try:
        payload = pyjwt.decode(
            token, material['public_pem'], algorithms=['RS256'],
            options={'require': ['exp', 'jti']},
        )
    except pyjwt.ExpiredSignatureError:
        return VerifyResult(valid=False, reason='expired')
    except pyjwt.InvalidTokenError:
        return VerifyResult(valid=False, reason='unknown')

    if payload.get('scope') != TOKEN_SCOPE:
        return VerifyResult(valid=False, reason='unknown')

    try:
        token_owner_id = int(payload.get('sub'))
    except (TypeError, ValueError):
        return VerifyResult(valid=False, reason='unknown')
    token_scope = {
        'owner_id': token_owner_id,
        'resource_id': payload.get('res'),
        'action': payload.get('act'),
    }
    if (
        token_scope['owner_id'] != expected_scope.get('owner_id')
        or token_scope['resource_id'] != expected_scope.get('resource_id')
        or token_scope['action'] != expected_scope.get('action')
    ):
        return VerifyResult(valid=False, reason='scope_mismatch')

    factor = payload.get('fac') or ''
    if min_factor and (
        FACTOR_STRENGTH.get(factor, 0) < FACTOR_STRENGTH.get(min_factor, 0)
    ):
        return VerifyResult(valid=False, reason='factor_below_floor')

    # Session binding for irreversible actions (A7 (a) / §8b).
    cnf = payload.get('cnf') or {}
    if 'ath' in cnf:
        token_ath = cnf.get('ath') or ''
        if not session_binding or not hmac.compare_digest(token_ath, session_binding):
            return VerifyResult(valid=False, reason='binding_mismatch')

    # Single-use: claim the jti atomically *after* all stateless checks pass.
    remaining = max(0, int(payload['exp']) - int(time.time()))
    if not claim_jti(payload['jti'], remaining):
        return VerifyResult(valid=False, reason='replayed')

    return VerifyResult(valid=True, scope=token_scope, factor=factor)
