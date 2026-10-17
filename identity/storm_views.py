"""
Storm-aware JWT refresh endpoint (ADR-PLAT-002 §5-INV-2).

Wraps SimpleJWT's ``TokenRefreshView`` so that every successful refresh is
recorded into the population-wide sliding window. Detection and emission are
best-effort and MUST NOT affect the auth response: a Redis hiccup degrades the
signal, it never breaks token refresh.
"""
from __future__ import annotations

import logging

from django.conf import settings
from rest_framework import status
from rest_framework_simplejwt.views import TokenRefreshView

from .views import _ClaimRefreshingTokenRefreshSerializer
from .audit import emit_refresh_storm
from .invariants import record_token_event
from .refresh_storm import get_strategy

logger = logging.getLogger(__name__)


class StormAwareTokenRefreshView(TokenRefreshView):
    """``TokenRefreshView`` that feeds the §5-INV-2 refresh-storm signal."""

    # Use Shizuha's custom refresh serializer, not SimpleJWT's stock HS256-only
    # serializer. Agent password login issues RS256 refresh tokens; the stock
    # serializer rejects those fresh tokens immediately as token_not_valid.
    serializer_class = _ClaimRefreshingTokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        # PLAT-1278: this is the ROUTED refresh view (urls.py `refresh/`), so the
        # token-outcome counter must live here — the instrumented
        # views.TokenRefreshView is not wired to any route. Fail-open: the metric
        # must never break token refresh. An invalid/expired refresh raises
        # (InvalidToken -> 401); count that as a failure, then re-raise.
        try:
            response = super().post(request, *args, **kwargs)
        except Exception:
            record_token_event('refresh', 'failure')
            raise
        record_token_event('refresh', outcome='success' if response.status_code < 400 else 'failure')

        if not getattr(settings, "REFRESH_STORM_ENABLED", True):
            return response

        # Only count actually-issued refreshes (rotations), not rejected ones.
        if response.status_code == status.HTTP_200_OK:
            try:
                decision = get_strategy().record()
                if decision.should_emit:
                    emit_refresh_storm(decision)
            except Exception:  # noqa: BLE001 — signal must never break auth
                logger.exception("refresh-storm detection failed (non-fatal)")

        return response
