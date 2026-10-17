"""
Authentication views for Shizuha ID (Identity Service).

Merged from shizuha-pulse/tasks/auth_views.py and shizuha-notify/authentication/views.py
"""
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework import status, permissions, viewsets, serializers
from rest_framework.exceptions import APIException
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView
from rest_framework_simplejwt.views import TokenVerifyView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.exceptions import TokenError

from .invariants import record_membership_projection_event, record_token_event
from allauth.socialaccount.models import SocialApp
from drf_spectacular.utils import extend_schema, extend_schema_view
import logging
import os
import requests as _admin_req

from .membership_v2 import (
    AssertionEmissionUnavailable,
    v2_enabled as _membership_v2_enabled,
    v2_request_headers as _membership_v2_request_headers,
)
# PLAT-5334: bind the exception classes at import. `_admin_req` is the
# requests module itself, so tests that patch it make every attribute a
# MagicMock -- and `except <MagicMock>` raises TypeError. Referencing
# _admin_req.Timeout in an except clause broke
# test_required_org_projection_rejects_admin_timeout, which configures
# .RequestException but not .Timeout. These names are patch-proof.
from requests import RequestException as _AdminRequestError
from requests import Timeout as _AdminTimeout
import secrets
import uuid
from urllib.parse import urlencode
from django.core.cache import cache, caches
from django.shortcuts import redirect
import time

from datetime import timedelta

from .canonicalization import normalize_email, normalize_username, validate_username_policy
from .avatars import assign_default_avatar
from .models import UserProfile, Tool, ToolCall, ToolResponse, PasswordResetToken, ServiceAccessRequest, PushToken, TOTPDevice, RecoveryCode
from .serializers import (
    UserSerializer, UserUpdateSerializer, UserProfileSerializer, ProfileUpdateSerializer,
    ToolSerializer, ToolCallSerializer, ToolResponseSerializer,
    LoginSerializer, RegisterSerializer, PasswordChangeSerializer,
    AuthResponseSerializer, TokenSerializer,
    PasswordResetRequestSerializer, PasswordResetValidateSerializer, PasswordResetConfirmSerializer,
    ServiceWithStatusSerializer, ServiceAccessRequestCreateSerializer,
    ServiceAccessRequestListSerializer, ServiceAccessRequestReviewSerializer,
    AdminServiceUpdateSerializer, AdminUserServiceGrantSerializer,
    UserApprovalReviewSerializer,
)
from .services import (
    send_account_approved_email, send_account_denied_email,
    get_effective_services, EmailServiceError,
)
from .audit import emit_mint_attestation_rejection, emit_profile_update_event
from .audit import emit_qa_e2e_session_mint
from .admin_audit import (
    audited_access_request_review,
    audited_admin_set_password,
    audited_service_catalog_update,
    audited_user_approval,
    audited_user_services_change,
    audited_admin_policy_denied,
)
from . import login_2fa, login_password, password_reset_security, signup_abuse, stepup
from . import list_rate_limit
from .stepup_throttles import Login2FAThrottle
from .k8s_agent_attestation import MintAttestationError, verify_agent_service_account_token
from .authentication import (
    RS256OAuthBearerAuthentication,
    UserViewScopedCompositeAuthentication,
)
from .permissions import IsStaffAdmin, IsSuperUserAdmin
from .billing import account_payload, ensure_free_v1_for_user

logger = logging.getLogger(__name__)


class MembershipProjectionUnavailable(APIException):
    """Fail token issuance closed when Admin cannot return the full RBAC view."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_code = 'membership_projection_unavailable'
    wait = 1

    def __init__(self):
        super().__init__({
            'error': self.default_code,
            'detail': (
                'Organization and project memberships are temporarily unavailable. '
                'No token was issued; retry shortly.'
            ),
        })


def _strict_input_enforced():
    """ID-56 feature flag for deny-by-default on the login/register/password-change
    views. Defaults to ENFORCE (``ID_STRICT_INPUT_ENFORCE=1``): unknown keys on
    these platform-critical auth paths are rejected with 400. Set to ``shadow``
    or ``0`` to log-only (for debugging/compat-bake). Kai's live client-compat
    audit cleared the risk — the only legitimate extra field (``intent`` on
    register) is declared on the serializer.
    """
    return os.environ.get('ID_STRICT_INPUT_ENFORCE', '1').strip().lower() not in {
        '0', 'false', 'off', 'shadow', 'shadow-only', 'disabled',
    }


def _reject_or_log_unknown_input(request, serializer_cls, view_name):
    """ID-56 deny-by-default gate for the raw auth views. Returns a 400 Response
    when enforce mode is on and the request carries keys not declared on the
    view's (StrictInputMixin) serializer; in shadow mode it only logs them and
    returns None so the view behaves exactly as today. Isolated to the
    unknown-key check — the views keep doing their own required/format
    validation, so this adds ONLY deny-by-default with zero behaviour change in
    shadow."""
    data = getattr(request, 'data', None)
    if not isinstance(data, dict):
        return None
    allowed = set(serializer_cls().fields)
    unknown = sorted(k for k in data if k not in allowed)
    if not unknown:
        return None
    if _strict_input_enforced():
        return Response(
            {k: ['Unexpected field (deny-by-default input validation, ID-56).'] for k in unknown},
            status=status.HTTP_400_BAD_REQUEST,
        )
    logger.warning(
        'ID-56 shadow: %s received undeclared input field(s) %s — would 400 under '
        'ID_STRICT_INPUT_ENFORCE=1 (declare it on the serializer if legitimate)',
        view_name, unknown,
    )
    return None


def _break_glass_enabled(value):
    """Return True only for explicit break_glass=true-style values."""
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() in {'true', '1', 'yes'}
    return False


def _break_glass_reason(request):
    if not _break_glass_enabled(request.data.get('break_glass')):
        return ''
    reason = str(request.data.get('break_glass_reason') or request.data.get('reason') or '').strip()
    return reason


def _break_glass_allowed(request, *, action):
    reason = _break_glass_reason(request)
    if not reason:
        return ''
    # ID-36: break-glass is deliberately narrow: only an already-superuser actor
    # may use it, and every use records the mandatory reason in AdminAuditEvent.
    if not getattr(request.user, 'is_superuser', False):
        return ''
    return reason


def _deny_admin_attempt(*, request, target, reason_code, attempted_action, attempted=None, status_code=403):
    audited_admin_policy_denied(
        actor=request.user,
        target_type='user',
        target_id=getattr(target, 'id', ''),
        target_repr=getattr(target, 'username', ''),
        reason_code=reason_code,
        attempted_action=attempted_action,
        attempted=attempted or {},
        request=request,
    )
    return Response({'error': reason_code}, status=status_code)


def _privileged_service(tool):
    return bool(tool.requires_approval or tool.requires_superuser or tool.slug in {'admin', 'books-admin', 'payments-admin'})
User = get_user_model()

# Mail domain for Shizuha platform
MAIL_DOMAIN = 'shizuha.com'


def _qa_e2e_session_mint_signal(request, user, tokens, mint_path):
    """ID-85/ID-86: typed, class-scoped audit signal for dedicated QA e2e mints.

    ren's sign-off (PLAT-1247 gate, condition A1): logins of the dedicated QA
    e2e principal class emit a typed ``qa_e2e_session_mint`` audit signal —
    ``principal`` / ``actor`` / ``mint_path`` / ``session_id`` (the ID-70 sid)
    / ``timestamp`` — so an anomaly watchdog can filter mint-rate spikes and
    off-surface usage for this credential class.

    C1 (load-bearing): the settings allowlist is the ONLY class check. Nothing
    is opened here — the normal login flow already serves every principal
    (SESSION_LOGIN False; browser sessions are the login-response JWT cookies);
    this is additive observability scoped to the allowlisted class alone.
    """
    try:
        allowed = getattr(settings, 'QA_E2E_PRINCIPALS', ()) or ()
        if not allowed:
            return
        username = str(getattr(user, 'username', '') or '')
        if username.lower() not in {str(a).strip().lower() for a in allowed}:
            return
        sid = ''
        try:
            import jwt as _pyjwt
            unverified = _pyjwt.decode(
                str(tokens.get('refresh', '') or ''), options={'verify_signature': False},
            )
            sid = str(unverified.get('sid') or '')[:64]
        except Exception:
            sid = ''
        actor = 'anonymous:' + (request.META.get('REMOTE_ADDR') or 'unknown')
        req_user = getattr(request, 'user', None)
        if req_user is not None and getattr(req_user, 'is_authenticated', False):
            actor = str(
                getattr(req_user, 'username', '') or getattr(req_user, 'email', '') or actor
            )[:150]
        emit_qa_e2e_session_mint(
            principal=username[:150],
            actor=actor,
            mint_path=mint_path,
            session_id=sid,
            ts=timezone.now().isoformat(),
        )
    except Exception:
        logger.exception('qa_e2e_session_mint signal emission failed')


def _set_jwt_auth_cookies(response, tokens):
    """Expose the Shizuha-ID browser session to server-rendered sibling apps."""
    rest_auth = getattr(settings, 'REST_AUTH', {})
    access_name = rest_auth.get('JWT_AUTH_COOKIE', 'shizuha-access-token')
    refresh_name = rest_auth.get('JWT_AUTH_REFRESH_COOKIE', 'shizuha-refresh-token')
    secure = bool(rest_auth.get('JWT_AUTH_SECURE', not getattr(settings, 'DEBUG', False)))
    httponly = bool(rest_auth.get('JWT_AUTH_HTTPONLY', True))
    samesite = rest_auth.get('JWT_AUTH_SAMESITE', 'Lax')
    # Scoped to .shizuha.com in prod so first-party sibling hosts (e.g.
    # origin.shizuha.com/deploy-status) can authenticate the browser session;
    # empty keeps the host-only default (dev/localhost).
    domain = rest_auth.get('JWT_AUTH_COOKIE_DOMAIN') or None
    access_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('ACCESS_TOKEN_LIFETIME', timedelta(hours=24))
    refresh_lifetime = getattr(settings, 'SIMPLE_JWT', {}).get('REFRESH_TOKEN_LIFETIME', timedelta(days=30))
    response.set_cookie(
        access_name,
        tokens['access'],
        max_age=int(access_lifetime.total_seconds()),
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        path='/',
        domain=domain,
    )
    response.set_cookie(
        refresh_name,
        tokens['refresh'],
        max_age=int(refresh_lifetime.total_seconds()),
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        path='/',
        domain=domain,
    )
    return response


def get_email_prefix(email):
    """
    Extract the email prefix (local part) from an email address.
    This is used to determine the mail account name.
    """
    return email.split('@')[0].lower() if email else ''


def check_email_prefix_conflict(email, exclude_user_id=None):
    """
    Check if the email prefix would conflict with an existing user's mail account.

    Returns (has_conflict, conflicting_email) tuple.
    """
    prefix = get_email_prefix(email)
    if not prefix:
        return False, None

    # Find any existing user with the same email prefix
    # Include pending users (exclude only denied users) to prevent prefix conflicts
    existing_users = User.objects.exclude(
        is_active=False, profile__approval_status='denied'
    )
    if exclude_user_id:
        existing_users = existing_users.exclude(id=exclude_user_id)

    for user in existing_users:
        existing_prefix = get_email_prefix(user.email)
        if existing_prefix == prefix:
            return True, user.email

    return False, None


def _agent_account_email_domain() -> str:
    """Service-account email domain for agent accounts (PLAT-671). Configurable so
    a non-prod deployment can use its own domain."""
    return getattr(settings, 'AGENT_ACCOUNT_EMAIL_DOMAIN', 'agents.shizuha.io')


def _is_agent_user(user) -> bool:
    """Whether a user is an AI agent / service account.

    True if EITHER the profile ``account_type`` is ``'agent'`` OR the account's
    email is in the agent service-account domain (``@agents.shizuha.io``,
    configurable). The email-domain fallback is defense-in-depth (PLAT-671): an
    agent account provisioned WITHOUT ``account_type='agent'`` (older / edge flow)
    must still be protected from human password-reset / 2FA sweeps — otherwise a
    sweep desyncs its container ``AGENT_PASSWORD`` and 401s the fleet (the
    2026-06-16 outage). Returns False on any error / for humans — safe default.
    """
    try:
        profile = getattr(user, 'profile', None)
        if profile is not None and getattr(profile, 'account_type', None) == 'agent':
            return True
        email = (getattr(user, 'email', '') or '').strip().lower()
        domain = _agent_account_email_domain().lstrip('@').lower()
        return bool(email) and bool(domain) and email.endswith('@' + domain)
    except Exception:
        return False


def _reject_agent_password_reset(user, *, is_provisioning=False):
    """PLAT-556 stopgap: a HUMAN security sweep must NOT reset an agent/service
    account's password through the human auth paths (admin reset, forgot-password).

    An agent's credential is provisioned in a single write to BOTH the broker-scoped
    credential AND this account (PLAT-558); a human-side reset of only the account
    desyncs the two and 401s the agent fleet-wide (the 2026-06-16 outage, where a
    platform-wide password change reset agent account passwords away from the
    baked-in container ``AGENT_PASSWORD``).

    ``is_provisioning=True`` is the deliberate single-write provisioning / drift
    self-heal path — the legitimate writer of an agent's password — so it is
    allowed (it writes both sides together and cannot drift).

    Returns a 409 ``Response`` to short-circuit the caller for a human reset of an
    agent account, or ``None`` (allowed) for human accounts and provisioning.
    Durable fix: PLAT-555 Phase 2 (k8s SA token exchange, no stored password).
    """
    if is_provisioning:
        return None
    if _is_agent_user(user):
        return Response(
            {
                'error': 'agent_service_account',
                'detail': (
                    'Agent service accounts are managed by provisioning, not '
                    'password reset. Resetting desyncs the container credential '
                    'and breaks the running agent (PLAT-556). Re-provision the '
                    'agent to rotate its credential.'
                ),
            },
            status=status.HTTP_409_CONFLICT,
        )
    return None



def _record_projection(outcome, *, required):
    """PLAT-5334 P2-1 (@reika): the projection counter measures the MINT path.

    Both fetchers have non-mint callers. `internal_urls.py:252` and `:259` —
    the latter inside a per-candidate loop in the same-org directory filter —
    deliberately pass `required=False` because that path wants
    fail-closed-and-continue, not a raise. Recording them made ONE directory
    listing by a non-staff caller increment `id_membership_projection_total`
    `1 + N` times from a path that mints nothing, so an `authoritative_empty`
    spike could be an admin listing org-less users rather than a mint stamping
    an ambiguous projection — diluting exactly the signal PLAT-5334 exists to
    create.

    The mint contract IS the required path: `_fetch_membership_projection`
    passes `required=True` to both families. Scoping telemetry to it leaves the
    one-bit invariant untouched (`authoritative_empty` still only from a
    well-formed empty 200) and removes the pollution. It also makes the
    non-required fallback's stated rationale true: with recording gated, the
    `{}` returned there really is an unrecorded conservative substitute.

    Directory-path visibility, if wanted later, needs its own label value or
    metric — not a shared counter.
    """
    if not required:
        return
    record_membership_projection_event(outcome)


def _fetch_org_memberships(user, *, required=False) -> dict:
    """
    Ask shizuha-admin for the user's active OrganizationMemberships and return
    as `{org_id_str: role}` — the claim shape consumed by every federated
    service that resolves tenant-scoped RBAC (pulse, connect, wiki, drive).

    The claim is evaluated per-request at the federated service, so we
    favor freshness at mint time over cache tricks. Token issuance calls this
    with ``required=True`` so an Admin outage produces a typed 503 instead of
    an authorization-poisoned token with fabricated empty grants. Non-mint
    directory checks retain the conservative empty-set fallback.
    """
    base = os.environ.get('SHIZUHA_ADMIN_API_URL') or 'http://shizuha-admin:8003/api'
    url = f"{base}/internal/users/{user.id}/memberships/"
    params = {}
    if getattr(user, 'email', None):
        params['email'] = user.email
    # Pass the display name so admin can name the auto-provisioned personal
    # workspace "<User>'s Workspace" (operator 2026-07-11) rather than a generic
    # fallback. Admin get-or-creates it here so the claim is never empty.
    _wsname = (getattr(user, 'first_name', '') or getattr(user, 'username', '') or '').strip()
    if _wsname:
        params['name'] = _wsname
    try:
        # Slightly wider budget than a pure read: the first mint for a brand-new
        # user does one INSERT (personal workspace). Still fail-open to {} on
        # timeout — the next mint self-heals.
        resp = _admin_req.get(url, params=params, timeout=1.0)
        if resp.status_code == 200:
            data = resp.json()
            mem = data.get('memberships') or {}
            if isinstance(mem, dict):
                # PLAT-5334: the only path that may report an empty projection
                # as AUTHORITATIVE — a 200 whose payload parsed to a dict. Every
                # other exit below is a failure and reports a distinct outcome
                # alongside a raise, so `authoritative_empty` and "we could not
                # determine" are separable in production rather than both
                # arriving as {}.
                _mem_empty = not mem
                _record_projection(
                    'authoritative_empty' if _mem_empty else 'success',
                    required=required,
                )
                if _mem_empty and required:
                    # PLAT-8236 corollary (id#100 leg): name the
                    # empty-returning population from ID logs at projection
                    # timestamps. Numeric user id only — never the JWT or the
                    # payload (PLAT-5104 boundary); the counter deliberately
                    # carries no user label (cardinality). Admin's
                    # get-or-create contract says the personal workspace exists
                    # "so the claim is never empty" — a required mint landing
                    # here is that contract failing and mints a claim-less
                    # token every federated consumer 401s.
                    logger.warning(
                        "PLAT-8236: mint-path org-membership projection landed authoritative_empty for user %s — claim-less token minted",
                        user.id,
                    )
                return mem
            _record_projection('invalid_payload', required=required)
            if required:
                raise MembershipProjectionUnavailable()
        else:
            _record_projection('non_200', required=required)
            if required:
                raise MembershipProjectionUnavailable()
    except MembershipProjectionUnavailable:
        raise
    except _AdminTimeout as exc:
        _record_projection('timeout', required=required)
        logger.warning(f"Failed to fetch org memberships for user {user.id}: {exc}")
        if required:
            raise MembershipProjectionUnavailable() from exc
    except _AdminRequestError as exc:
        _record_projection('request_error', required=required)
        logger.warning(f"Failed to fetch org memberships for user {user.id}: {exc}")
        if required:
            raise MembershipProjectionUnavailable() from exc
    # Non-required fallback only. Deliberately NOT recorded as
    # authoritative_empty: reaching here means a failure already recorded its
    # own outcome above, and this {} is a conservative substitute, not a
    # measurement.
    return {}


def provision_personal_workspace(user_id, email=None, display_name=None) -> bool:
    """Eagerly create a user's free personal workspace at ACTIVATION time.

    Every new account must get "<User>'s Workspace" the moment it becomes active
    — signup guarantees it rather than relying on a later token-mint self-heal
    (operator 2026-07-11: a Google-OAuth signup slipped through the lazy path and
    landed on the home page with "no organization"). Hits the same admin endpoint
    the mint path uses (which get-or-creates the workspace), but with a WIDER
    budget: first creation does real work (org + default services + founder
    profile) that can exceed the 1.0s per-request mint timeout. Best-effort — a
    failure is logged and the mint/org-list self-heal still backstops it — so a
    transient admin blip never blocks activation. Idempotent server-side.
    """
    base = os.environ.get('SHIZUHA_ADMIN_API_URL') or 'http://shizuha-admin:8003/api'
    url = f"{base}/internal/users/{user_id}/memberships/"
    params = {}
    if email:
        params['email'] = email
    name = (display_name or '').strip()
    if name:
        params['name'] = name
    try:
        resp = _admin_req.get(url, params=params, timeout=6.0)
        if resp.status_code == 200:
            logger.info("provisioned personal workspace for newly-active user %s", user_id)
            return True
        logger.warning(
            "personal-workspace provision for user %s returned HTTP %s (mint self-heal will retry)",
            user_id, resp.status_code,
        )
    except _admin_req.RequestException as exc:
        logger.warning(
            "personal-workspace provision for user %s failed: %s (mint self-heal will retry)",
            user_id, exc,
        )
    return False


def _fetch_project_memberships_v2(user, *, required=False) -> tuple[list[int], dict[str, str]]:
    """PLAT-5343 slice 1: the acyclic v2 projection path (HLD §4.1/§4.3).

    POSTs Admin's v2 composition route with ID's dedicated service credential
    and the subject assertion minted from the already-authenticated principal.
    Same outcome vocabulary and fail-closed semantics as the v1 fetcher; the
    mint budget is unchanged (Admin composes from one local query + one Pulse
    v2 call inside the same 1.0 s envelope).
    """
    base = os.environ.get('SHIZUHA_ADMIN_API_URL') or 'http://shizuha-admin:8003/api'
    url = f"{base}/internal/v2/project-memberships:resolve"
    try:
        headers = _membership_v2_request_headers(user)
    except AssertionEmissionUnavailable as exc:
        _record_projection('v2_emission_unavailable', required=required)
        logger.error(
            "v2 membership projection selected but assertion material missing (%s); "
            "refusing to mint a projection", exc,
        )
        if required:
            raise MembershipProjectionUnavailable() from exc
        return [], {}
    try:
        resp = _admin_req.post(url, json={}, headers=headers, timeout=1.0)
        if resp.status_code == 200:
            data = resp.json()
            # Strict declared-shape check: both keys must be PRESENT with the
            # right types. Unlike the v1 fetcher's `or {}` coercion, a 200
            # missing a key is invalid_payload (fail closed), never an
            # authoritative empty — the PLAT-5338 fabrication class.
            roles = data.get('project_memberships')
            ids = data.get('project_ids')
            if isinstance(roles, dict) and isinstance(ids, list):
                _v2_empty = not ids and not roles
                _record_projection(
                    'authoritative_empty' if _v2_empty else 'success',
                    required=required,
                )
                if _v2_empty and required:
                    # PLAT-8236 corollary (id#100 leg): see
                    # _fetch_org_memberships for the boundary rationale —
                    # numeric user id only, mint path only.
                    logger.warning(
                        "PLAT-8236: mint-path project-memberships(v2) projection landed authoritative_empty for user %s",
                        user.id,
                    )
                return ids, roles
            _record_projection('invalid_payload', required=required)
            if required:
                raise MembershipProjectionUnavailable()
        else:
            _record_projection('non_200', required=required)
            if required:
                raise MembershipProjectionUnavailable()
    except MembershipProjectionUnavailable:
        raise
    except _AdminTimeout as exc:
        _record_projection('timeout', required=required)
        logger.warning(f"v2 project-memberships fetch timed out for user {user.id}: {exc}")
        if required:
            raise MembershipProjectionUnavailable() from exc
    except _AdminRequestError as exc:
        _record_projection('request_error', required=required)
        logger.warning(f"v2 project-memberships fetch failed for user {user.id}: {exc}")
        if required:
            raise MembershipProjectionUnavailable() from exc
    # Non-required fallback only — NOT authoritative; see the org fetcher.
    return [], {}


def _fetch_project_memberships(user, *, required=False) -> tuple[list[int], dict[str, str]]:
    """
    Ask shizuha-admin for the user's active ProjectMemberships and return
    (project_ids_list, {project_id_str: role}) — the claim shapes stamped
    into JWTs as `project_ids` and `project_roles` (SCS-31 / SCS-20).

    Consumed by SCS to validate project-scoped requests from the token alone.
    Token issuance calls this with ``required=True`` and refuses to mint unless
    both project claim shapes are authoritative.

    PLAT-5343 slice 1: when the v2 path is selected (flag + assertion material
    provisioned), the acyclic Admin v2 composition route is used instead of
    the circular v1 proxy. There is no runtime fallback from a selected v2 to
    v1 — a v2 failure fails the mint closed exactly like a v1 failure.
    """
    if _membership_v2_enabled():
        return _fetch_project_memberships_v2(user, required=required)
    base = os.environ.get('SHIZUHA_ADMIN_API_URL') or 'http://shizuha-admin:8003/api'
    url = f"{base}/internal/users/{user.id}/project-memberships/"
    params = {}
    if getattr(user, 'email', None):
        params['email'] = user.email
    # Pass the display name so admin can name the auto-provisioned personal
    # workspace "<User>'s Workspace" (operator 2026-07-11) rather than a generic
    # fallback. Admin get-or-creates it here so the claim is never empty.
    _wsname = (getattr(user, 'first_name', '') or getattr(user, 'username', '') or '').strip()
    if _wsname:
        params['name'] = _wsname
    try:
        # Slightly wider budget than a pure read: the first mint for a brand-new
        # user does one INSERT (personal workspace). Still fail-open to {} on
        # timeout — the next mint self-heals.
        resp = _admin_req.get(url, params=params, timeout=1.0)
        if resp.status_code == 200:
            data = resp.json()
            roles = data.get('project_memberships') or {}
            ids = data.get('project_ids') or []
            if isinstance(roles, dict) and isinstance(ids, list):
                # PLAT-5334: authoritative only on a 200 whose payload parsed to
                # the declared shapes. See _fetch_org_memberships for the rule.
                _v1_empty = not ids and not roles
                _record_projection(
                    'authoritative_empty' if _v1_empty else 'success',
                    required=required,
                )
                if _v1_empty and required:
                    # PLAT-8236 corollary (id#100 leg): see
                    # _fetch_org_memberships for the boundary rationale —
                    # numeric user id only, mint path only.
                    logger.warning(
                        "PLAT-8236: mint-path project-memberships(v1) projection landed authoritative_empty for user %s",
                        user.id,
                    )
                return ids, roles
            _record_projection('invalid_payload', required=required)
            if required:
                raise MembershipProjectionUnavailable()
        else:
            _record_projection('non_200', required=required)
            if required:
                raise MembershipProjectionUnavailable()
    except MembershipProjectionUnavailable:
        raise
    except _AdminTimeout as exc:
        _record_projection('timeout', required=required)
        logger.warning(f"Failed to fetch project memberships for user {user.id}: {exc}")
        if required:
            raise MembershipProjectionUnavailable() from exc
    except _AdminRequestError as exc:
        _record_projection('request_error', required=required)
        logger.warning(f"Failed to fetch project memberships for user {user.id}: {exc}")
        if required:
            raise MembershipProjectionUnavailable() from exc
    # Non-required fallback only — NOT authoritative; see the org fetcher.
    return [], {}


def _fetch_membership_projection(user) -> tuple[dict, list[int], dict[str, str]]:
    """Read the complete Admin projection before mutating any token state."""
    memberships = _fetch_org_memberships(user, required=True)
    project_ids, project_roles = _fetch_project_memberships(user, required=True)
    return memberships, project_ids, project_roles


def _current_token_version(user) -> int:
    """ID-1 §3.1 / PLAT-5996: the subject's current monotonic token_version.

    Read from the profile (default 0 when the profile does not exist yet — a
    fresh user has never been revoked). The revoke path increments this in the
    same atomic transaction as the access_revoked_before cutoff, so a token
    minted before a logout carries a strictly smaller version than the current
    one and is rejected by every consumer.
    """
    try:
        return getattr(user, 'profile', None).token_version or 0
    except Exception:
        return 0


def _populate_standard_claims(refresh_or_access, user, *, membership_projection=None):
    """Populate the shared claim set on a RefreshToken/AccessToken for `user`.

    Used by every token-emission site in this file so claims stay consistent:
    email, username, first/last name, is_staff/is_superuser, is_agent,
    enabled_services, organization_memberships.
    """
    refresh_or_access['email'] = user.email
    refresh_or_access['username'] = user.username
    profile = getattr(user, 'profile', None)
    if profile is not None:
        if getattr(profile, 'timezone', None):
            refresh_or_access['timezone'] = profile.timezone
        currency = (getattr(profile, 'display_currency', '') or 'USD').upper()
        refresh_or_access['display_currency'] = currency
    refresh_or_access['first_name'] = getattr(user, 'first_name', '') or ''
    refresh_or_access['last_name'] = getattr(user, 'last_name', '') or ''
    refresh_or_access['is_staff'] = getattr(user, 'is_staff', False)
    refresh_or_access['is_superuser'] = getattr(user, 'is_superuser', False)
    # ID-1 §3.1 / PLAT-5996: stamp the subject's monotonic token_version so
    # every RS256 verifier can reject a replayed pre-revocation token even when
    # the OAuth-store row is gone. Read from the profile (default 0 when the
    # profile does not exist yet — a fresh user has never been revoked).
    refresh_or_access['token_version'] = _current_token_version(user)
    # is_agent drives is_agent behavior in shizuha-connect's unified consumer:
    # downstream messages get sender_is_agent=True, and stream_event frames
    # are accepted on the inbound WebSocket.
    if _is_agent_user(user):
        refresh_or_access['is_agent'] = True
    # Tenant-scoped RBAC claim — consumed by federated services to resolve
    # org-admin / owner elevations at L1 of the permission resolver without
    # a per-request round-trip to shizuha-admin. Shape: {"1": "admin", ...}.
    projection = membership_projection or _fetch_membership_projection(user)
    memberships, project_ids, project_roles = projection
    refresh_or_access['organization_memberships'] = memberships
    # Project-scoped access control (SCS-31): stamp project_ids and project_roles
    # so SCS can validate X-Project-ID requests from the JWT claim without a
    # per-request round-trip to admin. Degrades gracefully on admin outage.
    refresh_or_access['project_ids'] = project_ids
    refresh_or_access['project_roles'] = project_roles
    # Named-group RBAC claim (CTX-168 / CTX-218): emit the user's Django group
    # names as a flat `groups` claim so claim-only verifiers can grant scoped
    # access without a DB round-trip — e.g. cortex's IsQAReadOnly checks
    # `'cortex-qa' in groups` to allow read-only access to /v1/admin/nodes and
    # /v1/admin/backends. Emitted ONLY when the user belongs to ≥1 group, so the
    # vast majority of tokens (agents and humans alike) are byte-for-byte
    # unchanged. Additive: existing verifiers ignore unknown claims.
    try:
        group_names = sorted(user.groups.values_list('name', flat=True)) if getattr(user, 'pk', None) else []
    except Exception:
        # Federated/synthetic users may lack a groups relation — degrade silently.
        group_names = []
    if group_names:
        refresh_or_access['groups'] = group_names


def record_active_session(user_id, sid):
    """Record that ``sid`` was issued by this service (ID-70 P1 #1 allow-list).

    The session-revocation gate fails closed on an unknown sid, so every sid we
    mint MUST have an ``ActiveSession`` row or the very token we just issued
    would be rejected on its next use. Best-effort on the write: a transient DB
    failure must not break minting, but the fail-closed gate will then reject
    the unpersisted sid (secure default).
    """
    if not user_id or not sid:
        return
    try:
        from .models import ActiveSession
        ActiveSession.objects.get_or_create(user_id=user_id, sid=sid)
    except Exception:
        logger.exception('record_active_session failed for sid=%s', sid)


def get_tokens_for_user(user, *, amr=None):
    """
    Generate JWT tokens for a user with custom claims.

    The tokens include email and username claims so that federated services
    (Notes, Pulse, Admin) can identify users without requiring them to exist
    in the local database.

    All users receive RS256-signed tokens (PLAT-1179 / PLAT-555 P1) verifiable
    via the JWKS endpoint. Agent accounts keep the broker-relay audience;
    human/browser accounts use the first-party wildcard audience.
    """
    membership_projection = _fetch_membership_projection(user)
    if _is_agent_user(user):
        from .agent_tokens import AgentRefreshToken
        refresh = AgentRefreshToken.for_user(user)
    else:
        from .agent_tokens import PlatformRefreshToken
        refresh = PlatformRefreshToken.for_user(user)
    # ID-70: one opaque session-family id per interactive login. SimpleJWT's
    # rotation changes only ``jti``/timestamps, so this claim remains stable.
    refresh['sid'] = str(uuid.uuid4())
    # ID-70 P1 #1: the revocation gate fails closed on an unknown sid, so the
    # minted sid must be persisted to the ActiveSession allow-list.
    record_active_session(user.id, refresh['sid'])

    # Add custom claims to the access token for federated authentication
    _populate_standard_claims(
        refresh,
        user,
        membership_projection=membership_projection,
    )

    # INV-5: canonical effective-service computation (ID-11)
    refresh['enabled_services'] = get_effective_services(user)
    if amr:
        refresh['amr'] = list(amr)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


def revoke_all_user_tokens(user):
    """Revoke ALL outstanding refresh tokens for `user` across both token systems (ID-7).

    1. simplejwt: blacklist every `OutstandingToken` — the standard login/refresh
       flow checks `BlacklistedToken` on the refresh grant, so this makes every
       prior refresh token rejected.
    2. OAuth: write `RevokedToken` jti rows + set `IssuedRefreshToken.revoked_at`
       — the OAuth refresh grant consults `RevokedToken`.

    Best-effort per system (one failing must not block the other). Returns the
    count of simplejwt tokens newly blacklisted.

    ID-13: stateless ACCESS tokens are now also killed here — we bump the user's
    `UserProfile.access_revoked_before` cutoff to now(), and the access-token
    validation path (identity/authentication.py) rejects any access token whose
    iat is <= that cutoff on the next request. This closes the stale-token gap
    (a logged-out / password-changed user's access token was otherwise valid up
    to its full TTL). The short access TTL is now defense-in-depth, not the
    guarantee — the cutoff is.
    """
    revoked = 0
    now = timezone.now()

    # ID-13: bump the user-level access-token revocation cutoff. Single-field
    # write (no read-modify-write race). Done FIRST so that even if the refresh
    # blacklisting below partially fails, access tokens are still cut off.
    #
    # FAIL-CLOSED (review: ichi): this bump is the PRIMARY access-token revocation
    # guarantee, so a failure here MUST propagate to the caller (logout /
    # password-change returns an error) — NOT be swallowed. Swallowing it would
    # report a successful logout while the user's access tokens stayed valid up to
    # their full TTL, which is exactly the gap ID-13 closes. (The refresh-token
    # blacklisting further below stays best-effort and is intentionally guarded.)
    from .models import UserProfile, PushToken
    from django.db import transaction
    # ID-21 (HLD 815412d1 §3.6): purge the user's push tokens in the SAME atomic
    # transaction as the access-cutoff bump, so a revoked session (logout /
    # password-change / family revocation) can no longer receive pushes — with no
    # partial state (§8 atomicity). Deactivate rather than delete (matches the
    # logout DELETE endpoint, preserves the device row for clean re-registration);
    # the push-send fan-out only delivers to is_active=True. Fail-closed with the
    # cutoff: if either write fails the whole revoke rolls back and the caller
    # (logout/password-change) errors, rather than reporting success while a
    # revoked session keeps its push channel. No token VALUE is logged (INV-4).
    with transaction.atomic():
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.access_revoked_before = now
        # ID-1 §3.1 / PLAT-5996: increment the monotonic token_version in the
        # SAME transaction as the cutoff bump, so every access token minted
        # before this revoke carries a strictly smaller version and is rejected
        # by consumers even if the OAuth-store row is gone (revive-by-replay).
        # F() avoids a read-modify-write race between concurrent revokes.
        from django.db.models import F
        profile.token_version = F('token_version') + 1
        profile.save(update_fields=['access_revoked_before', 'token_version'])
        pushes_purged = PushToken.objects.filter(user=user, is_active=True).update(is_active=False)
    if pushes_purged:
        logger.info(f"revoke_all_user_tokens: deactivated {pushes_purged} push token(s) for user {user.id}")
    # Write-through the cache so enforcement is immediate, not gated on TTL expiry.
    from .authentication import prime_user_access_cutoff_cache
    prime_user_access_cutoff_cache(user.id, now)
    try:
        from rest_framework_simplejwt.token_blacklist.models import (
            OutstandingToken, BlacklistedToken,
        )
        # Only still-valid (non-expired) tokens need blacklisting — expired ones
        # are already rejected by their `exp`. Filtering by expires_at avoids
        # sweeping a user's entire historical token set (live data shows users
        # accumulate tens of thousands of OutstandingToken rows over time).
        active = OutstandingToken.objects.filter(user=user, expires_at__gt=now)
        already = set(
            BlacklistedToken.objects.filter(token__in=active).values_list('token_id', flat=True)
        )
        to_block = [BlacklistedToken(token=ot) for ot in active.iterator() if ot.id not in already]
        if to_block:
            BlacklistedToken.objects.bulk_create(to_block, ignore_conflicts=True)
        revoked = len(to_block)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"revoke_all_user_tokens: simplejwt blacklist failed for user {user.id}: {exc}")

    try:
        from .models import IssuedRefreshToken, RevokedToken
        outstanding = IssuedRefreshToken.objects.filter(
            user=user, revoked_at__isnull=True, expires_at__gt=now,
        )
        existing = set(RevokedToken.objects.filter(
            jti__in=outstanding.values_list('jti', flat=True)
        ).values_list('jti', flat=True))
        new_rows = [
            RevokedToken(jti=irt.jti, token_type='refresh', user=user, client_id=irt.client_id)
            for irt in outstanding.iterator() if irt.jti not in existing
        ]
        if new_rows:
            RevokedToken.objects.bulk_create(new_rows, ignore_conflicts=True)
        # Mark every still-active OAuth refresh token revoked (bulk).
        IssuedRefreshToken.objects.filter(
            user=user, revoked_at__isnull=True,
        ).update(revoked_at=now)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"revoke_all_user_tokens: OAuth revoke failed for user {user.id}: {exc}")

    return revoked


# ---------------------------------------------------------------------------
# PLAT-7641: multi-class token verification for /api/auth/verify/
# ---------------------------------------------------------------------------
# The stock TokenVerifyView (PLAT-166) validates tokens through the GLOBAL
# simplejwt backend only (SIMPLE_JWT['ALGORITHM'] = HS256 / SIGNING_KEY).
# Since PLAT-255 / PLAT-1179 every interactive login mints RS256 tokens via
# AgentRefreshToken / PlatformRefreshToken (custom backends, aud='*' or
# 'shizuha:broker-relay'), so the stock verify path signature-checks an
# RS256 token as HS256 and false-rejects 100% of live tokens with 401
# token_not_valid — while the authentication path accepts the same token
# because AUTH_TOKEN_CLASSES tries the RS256 classes after the stock one.
#
# The fix keeps the PLAT-166 contract (signature+expiry verify only —
# revocation semantics stay with the authentication path) but validates the
# token under the SAME token classes the authenticator accepts: every class
# in SIMPLE_JWT['AUTH_TOKEN_CLASSES'] plus the refresh counterparts minted
# by this service. 200 = some class verifies it; 401 = none does (fail-closed,
# identical response shape to the stock view).
def _verify_candidate_token_classes() -> list:
    """Token classes /verify/ must accept: AUTH_TOKEN_CLASSES + refresh kin."""
    from django.utils.module_loading import import_string
    from rest_framework_simplejwt.settings import api_settings as jwt_api_settings

    classes = [
        import_string(path) if isinstance(path, str) else path
        for path in jwt_api_settings.AUTH_TOKEN_CLASSES
    ]
    # Refresh counterparts: the stock view accepted any decodable simplejwt
    # token (UntypedToken), so the migrated surface must keep accepting the
    # refresh tokens this service mints (stock HS256 + RS256 families).
    classes.append(RefreshToken)
    from .agent_tokens import AgentRefreshToken, PlatformRefreshToken
    classes.extend([AgentRefreshToken, PlatformRefreshToken])
    # De-duplicate while preserving order (a class may appear in both sets).
    seen = set()
    ordered = []
    for cls in classes:
        if cls not in seen:
            seen.add(cls)
            ordered.append(cls)
    return ordered


class MultiClassTokenVerifySerializer(serializers.Serializer):
    """PLAT-7641: verify the token under every token class the auth path accepts."""

    token = serializers.CharField(write_only=True)

    def validate(self, attrs):
        raw_token = attrs["token"]
        from django.conf import settings as django_settings
        from rest_framework_simplejwt.settings import api_settings as jwt_api_settings
        blacklist_active = (
            "rest_framework_simplejwt.token_blacklist" in django_settings.INSTALLED_APPS
            and jwt_api_settings.BLACKLIST_AFTER_ROTATION
        )
        for cls in _verify_candidate_token_classes():
            try:
                token = cls(raw_token)
            except TokenError as exc:
                # BlacklistMixin-bearing classes (the refresh kin) raise the
                # stock blacklist error during construction — preserve the
                # stock 400 "Token is blacklisted" shape instead of letting
                # it collapse into the generic 401.
                if "blacklist" in str(exc).lower():
                    raise serializers.ValidationError("Token is blacklisted") from exc
                continue
            # Signature + expiry verified under this class's own backend.
            # Preserve the stock blacklist behaviour (BLACKLIST_AFTER_ROTATION):
            # a jti present in the simplejwt blacklist is reported as before.
            if blacklist_active and jwt_api_settings.JTI_CLAIM:
                from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
                jti = token.get(jwt_api_settings.JTI_CLAIM)
                if jti and BlacklistedToken.objects.filter(token__jti=jti).exists():
                    raise serializers.ValidationError("Token is blacklisted")
            return {}
        # Fail closed with the exact stock response shape (TokenViewBase
        # catches TokenError -> InvalidToken -> 401 token_not_valid).
        raise TokenError("Token is invalid")


class MultiClassTokenVerifyView(TokenVerifyView):
    """PLAT-7641: /verify/ surface migrated to the service's token classes.

    Same request/response contract as the stock view (PLAT-166 / ADR-PLAT-002
    §5.2): POST {"token": <jwt>} -> 200 {} when the token verifies (signature
    + expiry) under ANY token class the authentication path accepts, 401
    token_not_valid when none does. Revocation (ID-13 cutoffs, session/sid,
    client cutoffs) remains the authentication path's concern, exactly as
    before — this endpoint never treated revocation as part of its contract.
    """

    serializer_class = MultiClassTokenVerifySerializer


class _ClaimRefreshingTokenRefreshSerializer(TokenRefreshSerializer):
    """
    On every token refresh, repopulate dynamic claims on the new access
    token from fresh sources — `organization_memberships` especially.

    SimpleJWT's default behavior is to keep refresh-token claims frozen
    for the life of the refresh token (7 days). That means a user who
    gets promoted from member → admin today won't see the claim in their
    JWT until they re-login. That's the wrong tradeoff for us: agents
    can't re-login on their own, so stale claims would linger across
    restarts forever until the refresh token itself expired.

    Trade-off choice: we pay one admin-service call per refresh (~15 min
    of access-token TTL) to keep org memberships fresh. Static claims
    (user_id, email, is_agent, is_staff, is_superuser) stay copied from
    the refresh token.
    """
    def validate(self, attrs):
        refresh_str = attrs.get('refresh', '')

        # Peek at the JWT header (no signature check) to choose the right
        # token backend. RS256 tokens are platform tokens (PLAT-1179) and must
        # be decoded with AgentRefreshToken or PlatformRefreshToken; HS256 is a
        # legacy human refresh token and is upgraded to RS256 below.
        import jwt as _pyjwt_header
        try:
            _alg = _pyjwt_header.get_unverified_header(refresh_str).get('alg', 'HS256')
        except Exception:
            _alg = 'HS256'

        if _alg == 'RS256':
            return self._validate_rs256_platform(attrs, refresh_str)

        # --- HS256 path (legacy human refresh tokens) ---
        # Validate the legacy refresh token, then return a fresh RS256
        # access+refresh pair so existing browser/daemon sessions migrate
        # without a forced re-login.
        from rest_framework_simplejwt.tokens import RefreshToken as _RT
        try:
            refresh = _RT(attrs['refresh'])
        except Exception:
            data = super().validate(attrs)
            return data

        user_id = refresh.get('user_id')
        from .authentication import _enforce_session_revocation
        _enforce_session_revocation(user_id, refresh.get('sid'), TokenError)

        if not user_id:
            return super().validate(attrs)

        try:
            user = User.objects.filter(pk=user_id).first()
            if not user:
                return super().validate(attrs)
        except Exception:
            return super().validate(attrs)

        if _is_agent_user(user):
            from .agent_tokens import AgentRefreshToken as _RefreshClass
        else:
            from .agent_tokens import PlatformRefreshToken as _RefreshClass
        membership_projection = _fetch_membership_projection(user)
        new_refresh = _RefreshClass.for_user(user)
        new_refresh['sid'] = refresh.get('sid') or str(uuid.uuid4())
        # ID-70 P1 #1: a sid minted here (legacy sid-less token upgraded to a
        # new-style family) must be persisted or the fail-closed gate would
        # reject the rotated token on its next use.
        record_active_session(user_id, new_refresh['sid'])
        for key in ('organization_id', 'amr'):
            if key in refresh:
                new_refresh[key] = refresh[key]
        _populate_standard_claims(
            new_refresh,
            user,
            membership_projection=membership_projection,
        )
        new_refresh['enabled_services'] = get_effective_services(user)
        data = {
            'access': str(new_refresh.access_token),
            'refresh': str(new_refresh),
        }
        try:
            refresh.blacklist()
        except AttributeError:
            pass
        return data

    def _validate_rs256_platform(self, attrs, refresh_str):
        """Refresh path for RS256-signed platform tokens (PLAT-255/1179).

        super().validate() hard-codes simplejwt's HS256 RefreshToken class so
        we handle the RS256 path entirely here, replicating the claim-refresh
        logic with the correct Agent* or Platform* token classes.
        """
        from .agent_tokens import (
            AgentRefreshToken, AgentAccessToken,
            BROKER_RELAY_AUD, PlatformRefreshToken, PlatformAccessToken,
        )
        from rest_framework_simplejwt.settings import api_settings as _jwt_settings
        from rest_framework_simplejwt.exceptions import TokenError

        import jwt as _pyjwt_unverified
        try:
            unverified = _pyjwt_unverified.decode(refresh_str, options={'verify_signature': False})
        except Exception:
            unverified = {}
        is_agent_aud = unverified.get('aud') == BROKER_RELAY_AUD
        RefreshClass = AgentRefreshToken if is_agent_aud else PlatformRefreshToken
        AccessClass = AgentAccessToken if is_agent_aud else PlatformAccessToken

        try:
            refresh = RefreshClass(refresh_str)
        except TokenError as exc:
            raise exc

        from .authentication import _enforce_session_revocation
        _enforce_session_revocation(
            refresh.get('user_id'), refresh.get('sid'), TokenError,
        )

        data = {'access': str(refresh.access_token)}

        # Rebuild fresh access token with updated dynamic claims.
        user_id = refresh.get('user_id')
        if not user_id:
            return data
        try:
            user = User.objects.filter(pk=user_id).first()
        except Exception:
            return data
        if not user:
            return data

        membership_projection = _fetch_membership_projection(user)
        new_access = AccessClass()
        for key in ('user_id', 'email', 'username', 'first_name', 'last_name',
                    'is_staff', 'is_superuser', 'is_agent', 'organization_id', 'amr', 'sid'):
            if key in refresh:
                new_access[key] = refresh[key]
        _populate_standard_claims(
            new_access,
            user,
            membership_projection=membership_projection,
        )
        # INV-5: re-read live grant state so revocations propagate on refresh (ID-11).
        new_access['enabled_services'] = get_effective_services(user)

        data['access'] = str(new_access)
        # Rotate only after the complete authoritative projection has been
        # stamped. A transient Admin failure must not consume the caller's
        # still-valid refresh token.
        if _jwt_settings.ROTATE_REFRESH_TOKENS:
            if _jwt_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    refresh.blacklist()
                except AttributeError:
                    pass
            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()
            data['refresh'] = str(refresh)
        return data


class TokenRefreshView(BaseTokenRefreshView):
    """SimpleJWT refresh view that repopulates dynamic claims on each refresh."""
    serializer_class = _ClaimRefreshingTokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        # PLAT-1278: count refresh outcomes on the write path so Prometheus can
        # alert on failure-rate spikes without polling auth logs.
        try:
            response = super().post(request, *args, **kwargs)
        except Exception:
            record_token_event('refresh', 'failure')
            raise
        record_token_event('refresh', outcome='success' if response.status_code < 400 else 'failure')
        return response


def _twofa_mode() -> str:
    mode = getattr(settings, 'TWOFA_LOGIN_ENFORCEMENT', 'off').lower()
    return mode if mode in {'off', 'nudge', 'enforce'} else 'off'


def _confirmed_login_factors(user):
    devices = list(TOTPDevice.objects.filter(user=user, confirmed=True).order_by('-created_at'))
    factors = []
    seen = set()
    for device in devices:
        if device.device_type not in seen:
            factors.append(device.device_type)
            seen.add(device.device_type)
    if RecoveryCode.remaining_for_user(user) > 0:
        factors.append('recovery')
    return factors, devices


def _user_twofa_enrolled(user) -> bool:
    factors, _devices = _confirmed_login_factors(user)
    return bool(factors)


def _user_must_enroll_2fa(user) -> bool:
    if _twofa_mode() != 'enforce':
        return False
    profile, _ = UserProfile.objects.get_or_create(user=user)
    if profile.twofa_enforced:
        return True
    return bool(profile.twofa_enforcement_deadline and timezone.now() >= profile.twofa_enforcement_deadline)


def _pending_2fa_response(user):
    factors, devices = _confirmed_login_factors(user)
    token, _jti, expires_at = login_2fa.mint_pending_login_token(user)
    return Response({
        'status': '2fa_required',
        'pending_token': token,
        'expires_at': expires_at,
        'factors': factors,
        'webauthn_available': any(d.device_type == TOTPDevice.DEVICE_WEBAUTHN for d in devices),
    }, status=status.HTTP_202_ACCEPTED)


@extend_schema(tags=['Authentication'])
class LoginView(APIView):
    """
    Login with username/email and password.
    Returns JWT access and refresh tokens.
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(request=LoginSerializer, responses={200: AuthResponseSerializer})
    def post(self, request):
        _rej = _reject_or_log_unknown_input(request, LoginSerializer, 'LoginView')
        if _rej is not None:
            return _rej
        username = (request.data.get('username', '') or '').strip()
        password = request.data.get('password', '')
        lookup = normalize_email(username) if '@' in username else normalize_username(username)

        if not username or not password:
            return Response(
                {'error': 'Username and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        login_throttle_id = login_password.account_identifier(lookup)

        if login_password.is_locked(request, login_throttle_id):
            return Response(
                {
                    'error': 'too_many_login_attempts',
                    'retry_after': login_password.lockout_remaining(request, login_throttle_id),
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # Try to authenticate with username
        user = authenticate(request, username=lookup, password=password)

        # If failed, try with email
        if not user:
            try:
                user_obj = User.objects.get(email__iexact=lookup)
                user = authenticate(request, username=user_obj.username, password=password)
            except User.DoesNotExist:
                pass

        if not user:
            # Check if user exists but is inactive (pending/denied approval)
            try:
                inactive_user = User.objects.get(username__iexact=lookup)
            except User.DoesNotExist:
                try:
                    inactive_user = User.objects.get(email__iexact=lookup)
                except User.DoesNotExist:
                    inactive_user = None

            if inactive_user and not inactive_user.is_active and inactive_user.check_password(password):
                try:
                    profile = inactive_user.profile
                    if profile.approval_status == 'pending':
                        return Response(
                            {'error': 'Your account is pending admin approval.', 'code': 'pending_approval'},
                            status=status.HTTP_403_FORBIDDEN
                        )
                    elif profile.approval_status == 'denied':
                        return Response(
                            {'error': 'Your registration has been denied.', 'code': 'approval_denied'},
                            status=status.HTTP_403_FORBIDDEN
                        )
                except UserProfile.DoesNotExist:
                    pass
                return Response(
                    {'error': 'Account is disabled'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            failures, lockout_s = login_password.record_failure(request, login_throttle_id)
            body = {'error': 'Invalid credentials'}
            if lockout_s:
                body = {'error': 'too_many_login_attempts', 'retry_after': lockout_s}
                return Response(body, status=status.HTTP_429_TOO_MANY_REQUESTS)
            return Response(body, status=status.HTTP_401_UNAUTHORIZED)

        login_password.clear(request, login_throttle_id)

        if not user.is_active:
            return Response(
                {'error': 'Account is disabled'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if _twofa_mode() != 'off':
            if _user_twofa_enrolled(user):
                logger.info("User %s password verified; login 2FA required", user.username)
                return _pending_2fa_response(user)
            if _user_must_enroll_2fa(user):
                return Response({
                    'error': '2fa_enrollment_required',
                    'detail': 'Two-factor enrollment is required before login can complete.',
                }, status=status.HTTP_403_FORBIDDEN)

        tokens = get_tokens_for_user(user, amr=['pwd'])
        record_token_event('password', 'success')
        _qa_e2e_session_mint_signal(request, user, tokens, '/id/api/auth/login/')
        logger.info(f"User {user.username} logged in successfully")

        response_data = {
            'user': UserSerializer(user).data,
            'tokens': tokens,
        }
        if _twofa_mode() == 'nudge' and not _user_twofa_enrolled(user):
            response_data['twofa_nudge'] = {'enroll': True}
        return _set_jwt_auth_cookies(Response(response_data), tokens)


class _Login2FAChallenge:
    def __init__(self, user, webauthn_state=None):
        self.user = user
        self.webauthn_state = webauthn_state or {}


@extend_schema(tags=['Authentication'])
class Login2FAView(APIView):
    """Complete login after password auth with TOTP, WebAuthn, or recovery code."""
    permission_classes = [permissions.AllowAny]
    throttle_classes = [Login2FAThrottle]

    def post(self, request):
        pending_token = request.data.get('pending_token') or ''
        factor_name = (request.data.get('factor') or '').strip().lower()
        answer = request.data.get('answer')
        pending = login_2fa.load_pending_login_token(pending_token)
        if not pending:
            return Response({'error': 'invalid_pending_token'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(pk=pending.user_id, is_active=True)
        except User.DoesNotExist:
            return Response({'error': 'invalid_pending_token'}, status=status.HTTP_400_BAD_REQUEST)

        if login_2fa.attempts_exhausted(pending):
            return Response({'error': 'second_factor_locked'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        if factor_name not in {'totp', 'webauthn', 'recovery'}:
            login_2fa.record_failure(pending)
            return Response({'error': 'unsupported_factor'}, status=status.HTTP_400_BAD_REQUEST)

        if factor_name == 'webauthn':
            return self._webauthn(request, pending, user)

        if factor_name == 'totp':
            device = TOTPDevice.objects.filter(
                user=user, device_type=TOTPDevice.DEVICE_TOTP, confirmed=True,
            ).order_by('-created_at').first()
            if device is None:
                login_2fa.record_failure(pending)
                return Response({'error': 'factor_unavailable'}, status=status.HTTP_400_BAD_REQUEST)
            ok = stepup.get_factor('totp').verify(device=device, answer=answer or '', challenge=_Login2FAChallenge(user))
        else:
            ok = stepup.get_factor('recovery').verify(device=None, answer=answer or '', challenge=_Login2FAChallenge(user))

        if not ok:
            failures = login_2fa.record_failure(pending)
            if failures >= login_2fa.max_attempts():
                return Response({'error': 'second_factor_locked'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
            return Response({'error': 'invalid_second_factor'}, status=status.HTTP_403_FORBIDDEN)
        return self._complete(user, pending, factor_name)

    def _webauthn(self, request, pending, user):
        device_id = request.data.get('device_id')
        qs = TOTPDevice.objects.filter(user=user, device_type=TOTPDevice.DEVICE_WEBAUTHN, confirmed=True)
        if device_id:
            qs = qs.filter(pk=device_id)
        device = qs.order_by('-created_at').first()
        if device is None:
            login_2fa.record_failure(pending)
            return Response({'error': 'factor_unavailable'}, status=status.HTTP_400_BAD_REQUEST)

        response = request.data.get('answer') or request.data.get('response')
        cache_key = login_2fa.challenge_cache_key(pending, device.id)
        if not response:
            options, state = stepup.webauthn_authentication_begin(device)
            from django.core.cache import cache, caches
            cache.set(cache_key, state, login_2fa.pending_ttl_seconds())
            return Response({
                'status': 'webauthn_challenge',
                'device_id': device.id,
                'challenge': options,
            }, status=status.HTTP_202_ACCEPTED)

        from django.core.cache import cache, caches
        state = cache.get(cache_key)
        if not state:
            return Response({'error': 'webauthn_challenge_required'}, status=status.HTTP_400_BAD_REQUEST)
        challenge = _Login2FAChallenge(user, webauthn_state=state)
        ok = stepup.get_factor('webauthn').verify(device=device, answer=response, challenge=challenge)
        if not ok:
            failures = login_2fa.record_failure(pending)
            if failures >= login_2fa.max_attempts():
                return Response({'error': 'second_factor_locked'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
            return Response({'error': 'invalid_second_factor'}, status=status.HTTP_403_FORBIDDEN)
        cache.delete(cache_key)
        return self._complete(user, pending, 'webauthn')

    def _complete(self, user, pending, factor_name):
        if not login_2fa.consume_pending_login_token(pending):
            return Response({'error': 'invalid_pending_token'}, status=status.HTTP_400_BAD_REQUEST)
        login_2fa.clear_failures(pending)
        tokens = get_tokens_for_user(user, amr=['pwd', factor_name])
        record_token_event('twofa', 'success')
        _qa_e2e_session_mint_signal(self.request, user, tokens, '/id/api/auth/login/2fa/')
        logger.info("User %s completed login 2FA with %s", user.username, factor_name)
        payload = {
            'user': UserSerializer(user).data,
            'tokens': tokens,
            'amr': ['pwd', factor_name],
        }
        if factor_name == 'recovery' and RecoveryCode.remaining_for_user(user) <= getattr(settings, 'TWOFA_RECOVERY_CODE_LOW_WATERMARK', 2):
            payload['recovery_codes_low'] = True
        return _set_jwt_auth_cookies(Response(payload), tokens)


@extend_schema(tags=['Authentication'])
class ServiceTokenView(APIView):
    """
    Create a long-lived service token for an agent/service account.

    Used by the daemon to provision tokens for agents. The caller must be
    a superuser (admin). The target user is specified by email.

    Service tokens have longer lifetimes than regular login tokens:
    - Access token: 30 days (vs 24h for regular login)
    - Refresh token: 365 days (vs 30 days for regular login)

    The token includes all standard claims (user_id, email, username,
    is_staff, enabled_services, jti) so it works with ALL platform services.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Only superusers can create service tokens for other users
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only administrators can create service tokens'},
                status=status.HTTP_403_FORBIDDEN
            )

        target_email = request.data.get('email', '').strip()
        agent_id = request.data.get('agent_id', '').strip()
        correlation_id = (
            request.headers.get('X-Correlation-ID')
            or request.data.get('correlation_id', '')
            or request.META.get('HTTP_X_REQUEST_ID', '')
        )

        if target_email and agent_id:
            return Response(
                {'error': 'email and agent_id are mutually exclusive'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # PLAT-49: agent token mints must be independently attested against
        # Kubernetes ground truth, not trusted solely from the dashboard/admin
        # caller. Legacy email-only admin mints remain unchanged.
        if agent_id:
            service_account_token = (
                request.data.get('service_account_token', '')
                or request.headers.get('X-Kubernetes-ServiceAccount-Token', '')
            )
            try:
                verify_agent_service_account_token(
                    agent_id=agent_id,
                    service_account_token=service_account_token,
                )
            except MintAttestationError as exc:
                # PLAT-1278: a rejected agent mint is a real service-token
                # failure — count it so IdTokenFailureSpike can fire.
                record_token_event('service_token', 'failure')
                emit_mint_attestation_rejection(
                    reason=exc.code,
                    presented_agent_id=agent_id,
                    resolved_namespace=exc.resolved_namespace or '',
                    pod_name=exc.pod_name or '',
                    correlation_id=correlation_id or '',
                )
                return Response(
                    {
                        'error': exc.code,
                        'error_description': exc.message,
                        'correlation_id': correlation_id,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

        if not target_email and not agent_id:
            return Response(
                {'error': 'email or agent_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Find the target user. agent_id addresses agent accounts by username;
        # email remains the backwards-compatible admin path.
        lookup_value = target_email or agent_id
        try:
            if target_email:
                target_user = User.objects.get(email__iexact=target_email)
            else:
                target_user = User.objects.get(username__iexact=agent_id)
        except User.DoesNotExist:
            # Try by username for email-like inputs and by shizuha.com email for
            # bare agent IDs to preserve the service-token endpoint ergonomics.
            try:
                if target_email:
                    target_user = User.objects.get(username__iexact=target_email.split('@')[0])
                else:
                    target_user = User.objects.get(email__iexact=f'{agent_id}@{MAIL_DOMAIN}')
            except User.DoesNotExist:
                return Response(
                    {'error': f'User {lookup_value} not found'},
                    status=status.HTTP_404_NOT_FOUND
                )

        if not target_user.is_active:
            return Response(
                {'error': f'User {lookup_value} is disabled'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if agent_id and not _is_agent_user(target_user):
            return Response(
                {'error': 'agent_id mints require an agent account'},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Generate long-lived RS256 tokens. Agent accounts keep the broker
        # audience; human/browser accounts use the first-party wildcard audience.
        # PLAT-1278: count the service-token mint outcome on the write path.
        # Fail-open — the counter must never break minting; a mint that throws
        # is a real failure, so record it and re-raise.
        try:
            membership_projection = _fetch_membership_projection(target_user)
            if _is_agent_user(target_user):
                from .agent_tokens import AgentRefreshToken
                refresh = AgentRefreshToken.for_user(target_user)
            else:
                from .agent_tokens import PlatformRefreshToken
                refresh = PlatformRefreshToken.for_user(target_user)

            # ID-70 P1 #2: service tokens are sid-scoped session families, so a
            # logout of one never falls into the account-wide legacy fallback.
            refresh['sid'] = str(uuid.uuid4())
            record_active_session(target_user.id, refresh['sid'])

            # Override lifetime for service tokens
            refresh.set_exp(lifetime=timedelta(days=365))
            refresh.access_token.set_exp(lifetime=timedelta(days=30))

            # Add custom claims (same as regular login)
            _populate_standard_claims(
                refresh,
                target_user,
                membership_projection=membership_projection,
            )

            # INV-5: canonical effective-service computation (ID-11)
            refresh['enabled_services'] = get_effective_services(target_user)

            # Add organization_id if available (from admin service)
            org_id = request.data.get('organization_id', 1)
            refresh['organization_id'] = org_id

            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
        except Exception:
            record_token_event('service_token', 'failure')
            raise
        record_token_event('service_token', 'success')

        logger.info(
            f"Service token created for {target_user.email} "
            f"by {request.user.email} "
            f"(access: 30d, refresh: 365d)"
        )

        return Response({
            'access': access_token,
            'refresh': refresh_token,
            'user': {
                'id': target_user.id,
                'email': target_user.email,
                'username': target_user.username,
                'is_staff': target_user.is_staff,
                'organization_id': org_id,
            },
            'expires_in_days': 30,
            'refresh_expires_in_days': 365,
        })


@extend_schema(tags=['Authentication'])
class ApiTokenView(APIView):
    """
    Mint a long-lived API token for the authenticated user.

    Like GitHub Personal Access Tokens — any user (human or agent) can create
    a long-lived token for themselves. No admin required.

    POST /api/auth/api-token/
    Body (optional):
      {
        "ttl_days": 365,                  # default 365
        "label": "my-automation-token",
        "never_expires": true             # overrides ttl_days; sets exp to year 2200
      }

    Defaults: TTL 365 days. Max TTL 3650 days (10 years). Set
    `never_expires=true` to mint a truly permanent token (GitHub-PAT style) —
    revoke via /api/oauth/revoke or the Authorized Apps UI when no longer
    needed.

    The token carries the same claims as a regular login token (email, org_id,
    enabled_services, is_staff, etc.) — it works with ALL platform services.
    """
    # Accept BOTH HS256 (human) and RS256 (agent) bearer tokens so agents can
    # mint their own long-lived API token. The default HS256-only auth rejected
    # agent RS256 tokens with 401, forcing every agent onto 24h login tokens.
    authentication_classes = [RS256OAuthBearerAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        never_expires = bool(request.data.get('never_expires', False))
        ttl_days = min(int(request.data.get('ttl_days', 365)), 3650)
        label = request.data.get('label', 'api-token')

        # "Never expires" = set exp to Jan 1 2200 UTC, far past any realistic
        # deployment horizon but still a finite int so simplejwt doesn't gag.
        if never_expires:
            ttl_days = 365 * 175  # ~175 years

        membership_projection = _fetch_membership_projection(user)

        # All users get RS256 tokens. Agent accounts keep aud=broker-relay;
        # human/browser accounts use aud='*'. Mirrors get_tokens_for_user().
        if _is_agent_user(user):
            from .agent_tokens import AgentRefreshToken
            refresh = AgentRefreshToken.for_user(user)
        else:
            from .agent_tokens import PlatformRefreshToken
            refresh = PlatformRefreshToken.for_user(user)

        # ID-70 P1 #2: API tokens are sid-scoped session families, so a logout
        # of one never falls into the account-wide legacy fallback.
        refresh['sid'] = str(uuid.uuid4())
        record_active_session(user.id, refresh['sid'])

        # Standard claims (add BEFORE set_exp so the access token includes them)
        _populate_standard_claims(
            refresh,
            user,
            membership_projection=membership_projection,
        )

        # Enabled services
        # INV-5: canonical effective-service computation (ID-11)
        refresh['enabled_services'] = get_effective_services(user)

        # Organization ID
        org_id = request.data.get('organization_id', 1)
        refresh['organization_id'] = org_id

        # Set refresh lifetime
        refresh.set_exp(lifetime=timedelta(days=ttl_days))

        # For access token: simplejwt's refresh.access_token property creates
        # a new token each time with the default lifetime. We mint a custom
        # access token with explicit exp to get the requested TTL.
        if _is_agent_user(user):
            from .agent_tokens import AgentAccessToken
            access = AgentAccessToken()
        else:
            from .agent_tokens import PlatformAccessToken
            access = PlatformAccessToken()
        access.set_exp(lifetime=timedelta(days=ttl_days))
        # Copy all claims from refresh to access (sid included so the access
        # token is session-revocation checked, ID-70 P1 #1).
        for key in ['user_id', 'email', 'username', 'first_name', 'last_name',
                     'is_staff', 'is_superuser', 'is_agent', 'groups',
                     'enabled_services', 'organization_id', 'sid',
                     'organization_memberships']:
            if key in refresh:
                access[key] = refresh[key]
        access['token_type'] = 'access'
        access['jti'] = f'api-{label}-{user.id}'

        access_token = str(access)
        refresh_token = str(refresh)

        logger.info(
            f"API token minted for {user.email} "
            f"(label: {label}, ttl: {ttl_days}d)"
        )

        return Response({
            'access': access_token,
            'refresh': refresh_token,
            'label': label,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': getattr(user, 'username', ''),
            },
            'expires_in_days': ttl_days,
        })


@extend_schema(tags=['Authentication'])
class LogoutView(APIView):
    """
    Logout by blacklisting the refresh token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # ID-65: accept the canonical `refresh_token` field (the provider/QA
        # contract) AND the deprecated `refresh` alias, and blacklist the
        # SUBMITTED token fail-closed BEFORE the user-wide sweep — so a
        # logged-out refresh token can never mint a new access token (the
        # reported auth-bypass regression: logout returned 200 but the token
        # stayed usable because the submitted field was silently ignored).
        import jwt as _pyjwt
        refresh_str = request.data.get('refresh_token') or request.data.get('refresh')
        if not refresh_str:
            return Response(
                {'refresh_token': ['This field is required.']},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Select the correct token class. RS256 tokens are platform/agent tokens
        # (PLAT-1179) and cannot be verified/blacklisted by the generic HS256
        # RefreshToken; peek the alg exactly as the refresh path does.
        try:
            alg = _pyjwt.get_unverified_header(refresh_str).get('alg', 'HS256')
        except Exception:
            alg = 'HS256'
        try:
            if alg == 'RS256':
                from .agent_tokens import (
                    AgentRefreshToken, PlatformRefreshToken, BROKER_RELAY_AUD,
                )
                try:
                    unverified = _pyjwt.decode(refresh_str, options={'verify_signature': False})
                except Exception:
                    unverified = {}
                RefreshClass = (
                    AgentRefreshToken if unverified.get('aud') == BROKER_RELAY_AUD
                    else PlatformRefreshToken
                )
                token = RefreshClass(refresh_str)
            else:
                token = RefreshToken(refresh_str)
        except TokenError as e:
            logger.warning(f"Logout: rejected invalid refresh token: {e}")
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        # The submitted token must belong to the authenticated user — never let
        # one user's logout act on (or blacklist) another user's token.
        token_user_id = token.get('user_id')
        if token_user_id is not None and str(token_user_id) != str(request.user.id):
            logger.warning(
                f"Logout: refresh subject {token_user_id} != authenticated user {request.user.id}"
            )
            return Response(
                {'error': 'Token does not belong to the authenticated user'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        sid = str(token.get('sid') or '').strip()
        try:
            if sid:
                # ID-70: the exact blacklist, authoritative sid revocation, and
                # same-session push cleanup commit together. A partial write can
                # never produce a false-success logout.
                from .models import RevokedSession, ActiveSession
                from .authentication import prime_session_revocation_cache
                with transaction.atomic():
                    token.blacklist()
                    revoked_session, created = RevokedSession.objects.get_or_create(
                        sid=sid,
                        defaults={
                            'user': request.user,
                            'reason': 'logout',
                        },
                    )
                    if revoked_session.user_id != request.user.id:
                        raise ValueError('session subject mismatch')
                    PushToken.objects.filter(
                        user=request.user,
                        session_sid=sid,
                        is_active=True,
                    ).update(is_active=False)
                    # ID-70 P1 #1 hygiene: drop the allow-list row so the session
                    # family is fully gone (the RevokedSession deny-list remains
                    # authoritative for the fail-closed gate).
                    ActiveSession.objects.filter(user=request.user, sid=sid).delete()
                prime_session_revocation_cache(request.user.id, sid)
            else:
                # Bounded legacy fallback: a pre-ID-70 token has no stable family
                # key, so retain the security-preserving account-wide revoke until
                # those tokens age out. The submitted token is still blacklisted
                # fail-closed first (ID-65). Every post-ID-70 mint (login,
                # service-token, api-token) carries a sid, so this branch only
                # ever sees genuinely pre-deployment legacy tokens (ID-70 P1 #2).
                with transaction.atomic():
                    token.blacklist()
                    revoke_all_user_tokens(request.user)
        except Exception as e:
            logger.error(f"Logout: session revocation failed for user {request.user.id}: {e}")
            return Response(
                {'error': 'Logout could not revoke the session; please retry'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        logger.info(
            "User %s logged out (%s)",
            request.user.username,
            'session family revoked' if sid else 'legacy account-wide fallback',
        )
        return Response({'message': 'Successfully logged out'})


@extend_schema(tags=['Authentication'])
class SignupConfigView(APIView):
    """Public captcha/sitekey + whether admin approval is still required."""

    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response(signup_abuse.signup_config())


@extend_schema(tags=['Authentication'])
class RegisterView(APIView):
    """
    Register a new user account.
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(request=RegisterSerializer, responses={201: AuthResponseSerializer})
    def post(self, request):
        _rej = _reject_or_log_unknown_input(request, RegisterSerializer, 'RegisterView')
        if _rej is not None:
            return _rej
        username = normalize_username(request.data.get('username', ''))
        email = normalize_email(request.data.get('email', ''))
        password = request.data.get('password', '')
        password2 = request.data.get('password2', '')
        first_name = request.data.get('first_name', '').strip()
        last_name = request.data.get('last_name', '').strip()

        # Validate required fields
        if not username:
            return Response({'error': 'Username is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)
        if password != password2:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        denied = signup_abuse.reject_signup(
            request,
            email=email,
            captcha_token=str(request.data.get('captcha_token') or ''),
        )
        if denied is not None:
            return Response(denied, status=status.HTTP_400_BAD_REQUEST)
        try:
            validate_username_policy(username)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        # Check if username/email exists
        if User.objects.filter(username__iexact=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email__iexact=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Check for email prefix conflict (for mail account)
        # e.g., if test-owner@example.com exists, reject test-owner@shizuha.com
        has_conflict, conflicting_email = check_email_prefix_conflict(email)
        if has_conflict:
            prefix = get_email_prefix(email)
            return Response({
                'error': f'An account with the email prefix "{prefix}" already exists. '
                         f'Each user must have a unique email prefix for their Shizuha mail account.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate password
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({'error': list(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

        # Drive self-registration: auto-approve + least-privilege {id, drive} grant.
        # Enabled only when ALLOW_DRIVE_SELFREGISTRATION=true (env, default off).
        # DRV-21: external users join free Drive validation track without manual
        # fleet onboarding; they get Drive + ID only (no hive/fleet/admin surfaces).
        drive_intent = request.data.get('intent', '').lower() == 'drive'
        allow_drive_self_reg = getattr(settings, 'ALLOW_DRIVE_SELFREGISTRATION', False)
        open_reg = signup_abuse.open_registration_enabled()
        # HIVE-1987: QA fixture emails are auto-approved/active so non-staff QA
        # seats can mint a fresh blank-slate test user each cycle (captcha is
        # already bypassed in signup_abuse.reject_signup for this domain).
        qa_fixture = signup_abuse.is_qa_fixture_email(email)
        try:
            if drive_intent and allow_drive_self_reg:
                with transaction.atomic():
                    user = User.objects.create_user(
                        username=username,
                        email=email,
                        password=password,
                        first_name=first_name,
                        last_name=last_name,
                        is_active=True,  # auto-approved; no manual gate for Drive external users
                    )
                    profile, _ = UserProfile.objects.get_or_create(user=user)
                    # Every identity gets a valid avatar (operator 2026-08): a
                    # deterministic stock pick unless the user later chooses/edits.
                    assign_default_avatar(profile, user.username)
                    profile.approval_status = 'approved'
                    profile.lifecycle_state = 'active'
                    profile.subscription_tier = 'free'
                    profile.save(update_fields=['approval_status', 'lifecycle_state', 'subscription_tier'])
                    # Least-privilege: id + drive only (not hive/pulse/connect/wiki/admin)
                    drive_tools = Tool.objects.filter(slug__in=['id', 'drive'], is_active=True)
                    profile.enabled_tools.set(drive_tools)
                    granted = list(drive_tools.values_list('slug', flat=True))
                    account, grant = ensure_free_v1_for_user(user)
                    signup_abuse.record_signup(request, email)
                    logger.info(f"Drive external user auto-registered, services={granted}: {username}")
                    tokens = get_tokens_for_user(user, amr=['pwd'])
                    return Response({
                        'user': UserSerializer(user).data,
                        # Match the normal login/register auth response contract.  Keep
                        # the legacy top-level fields for old clients during rollout.
                        'tokens': tokens,
                        **tokens,
                        'drive_signup': True,
                        'billing_account': account_payload(account, grant),
                    }, status=status.HTTP_201_CREATED)

            # Standard path: inactive until admin approves, unless open
            # registration is explicitly enabled after captcha/rate-limits land,
            # or the email is a QA fixture (HIVE-1987) which is auto-approved.
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name,
                    is_active=(open_reg or qa_fixture),
                )
                # Set profile to pending approval
                profile, _ = UserProfile.objects.get_or_create(user=user)
                # Every identity gets a valid avatar (operator 2026-08): a
                # deterministic stock pick unless the user later chooses/edits.
                assign_default_avatar(profile, user.username)
                if open_reg or qa_fixture:
                    profile.approval_status = 'approved'
                    profile.lifecycle_state = 'active'
                    profile.save(update_fields=['approval_status', 'lifecycle_state'])
                else:
                    profile.approval_status = 'pending'
                    profile.save(update_fields=['approval_status'])
                account, grant = ensure_free_v1_for_user(user)
                signup_abuse.record_signup(request, email)

                logger.info(
                    'New user registered (%s): %s',
                    'open' if (open_reg or qa_fixture) else 'pending approval',
                    username,
                )

                # Re-fetch to get updated profile with correct approval_status
                user = User.objects.select_related('profile').get(pk=user.pk)

                if open_reg or qa_fixture:
                    tokens = get_tokens_for_user(user, amr=['pwd'])
                    return Response({
                        'user': UserSerializer(user).data,
                        'tokens': tokens,
                        **tokens,
                        'pending_approval': False,
                        'billing_account': account_payload(account, grant),
                    }, status=status.HTTP_201_CREATED)
                return Response({
                    'user': UserSerializer(user).data,
                    'pending_approval': True,
                    'billing_account': account_payload(account, grant),
                    'message': 'Your account has been created and is pending admin approval. You will receive an email once approved.',
                }, status=status.HTTP_201_CREATED)
        except IntegrityError:
            logger.info('Registration lost a concurrent uniqueness race: %s', username)
            return Response(
                {'error': 'Username or email already exists'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return Response({'error': 'Registration failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(tags=['User'])
class UserView(APIView):
    """
    Get or update the current authenticated user.
    """
    # CTX-492/CTX-497 v3: accept the Cortex SSO RS256 token on GET/HEAD only
    # (read bridge), while PATCH stays HS256/default-only so a broad/delegated
    # RS256 token can never mutate an account. Single method-aware composite.
    authentication_classes = [UserViewScopedCompositeAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: UserSerializer})
    def get(self, request):
        user = User.objects.select_related('profile').get(pk=request.user.pk)
        return Response(UserSerializer(user).data)

    @extend_schema(request=UserUpdateSerializer, responses={200: UserSerializer})
    def patch(self, request):
        # Use serializer for canonicalization, immutable-field rejection, and
        # friendly uniqueness validation. The DB functional unique indexes added
        # by ID-44 remain the race-proof backstop below.
        serializer = UserUpdateSerializer(data=request.data, context={'request': request}, partial=True)
        if not serializer.is_valid():
            first_field = next(iter(serializer.errors))
            error = serializer.errors[first_field]
            if isinstance(error, (list, tuple)):
                error = error[0]
            return Response({'error': str(error)}, status=status.HTTP_400_BAD_REQUEST)
        data = serializer.validated_data

        try:
            with transaction.atomic():
                user = User.objects.select_for_update().get(pk=request.user.pk)
                before = {
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                }

                for field in ('username', 'email', 'first_name', 'last_name'):
                    if field in data:
                        setattr(user, field, data[field])

                changed_fields = [field for field in before if getattr(user, field) != before[field]]
                if changed_fields:
                    user.save(update_fields=changed_fields)
                    after = {field: getattr(user, field) for field in changed_fields}
                    emit_profile_update_event(
                        actor=request.user,
                        target_user=user,
                        surface='auth.user',
                        changed_fields=changed_fields,
                        before={field: before[field] for field in changed_fields},
                        after=after,
                    )
        except IntegrityError:
            return Response(
                {'error': 'Profile update conflicted with another identifier update; please retry with a unique username/email'},
                status=status.HTTP_409_CONFLICT,
            )

        user = User.objects.select_related('profile').get(pk=request.user.pk)
        return Response(UserSerializer(user).data)


@extend_schema(tags=['User'])
class ProfileView(APIView):
    """
    Get or update user profile (extended profile data).
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: UserProfileSerializer})
    def get(self, request):
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        return Response(UserProfileSerializer(profile).data)

    @extend_schema(request=ProfileUpdateSerializer, responses={200: UserProfileSerializer})
    def patch(self, request):
        serializer = ProfileUpdateSerializer(data=request.data, partial=True)
        if not serializer.is_valid():
            first_field = next(iter(serializer.errors))
            error = serializer.errors[first_field]
            if isinstance(error, (list, tuple)):
                error = error[0]
            return Response({'error': str(error)}, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        with transaction.atomic():
            profile, _ = UserProfile.objects.select_for_update().get_or_create(user=request.user)
            before = {field: getattr(profile, field) for field in data}
            for field, value in data.items():
                setattr(profile, field, value)
            changed_fields = [field for field in data if getattr(profile, field) != before[field]]
            if changed_fields:
                profile.save(update_fields=[*changed_fields, 'updated_at'])
                emit_profile_update_event(
                    actor=request.user,
                    target_user=request.user,
                    surface='identity.profile',
                    changed_fields=changed_fields,
                    before={field: before[field] for field in changed_fields},
                    after={field: getattr(profile, field) for field in changed_fields},
                )

        profile.refresh_from_db()
        return Response(UserProfileSerializer(profile).data)


@extend_schema(tags=['Authentication'])
class PasswordChangeView(APIView):
    """
    Change password for the current user.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=PasswordChangeSerializer, responses={200: TokenSerializer})
    def post(self, request):
        _rej = _reject_or_log_unknown_input(request, PasswordChangeSerializer, 'PasswordChangeView')
        if _rej is not None:
            return _rej
        old_password = request.data.get('old_password', '')
        new_password = request.data.get('new_password', '')
        new_password2 = request.data.get('new_password2', '')

        if not old_password or not new_password:
            return Response({'error': 'Old password and new password are required'}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != new_password2:
            return Response({'error': 'New passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        if not user.check_password(old_password):
            return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return Response({'error': list(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        # ID-7: a password change must kill all prior sessions. Revoke FIRST,
        # then mint the caller's fresh tokens (issued after the revoke sweep).
        revoke_all_user_tokens(user)
        logger.info(f"User {user.username} changed password (prior tokens revoked)")

        tokens = get_tokens_for_user(user)
        # PLAT-1278: a password change mints ordinary login tokens, NOT a
        # long-lived service token — record it under the `password` stage so the
        # `service_token` failure-rate signal is not polluted by password changes.
        record_token_event('password', 'success')
        return Response({'message': 'Password changed successfully', 'tokens': tokens})


@extend_schema(tags=['Tools'])
class ToolListView(APIView):
    """
    List all available tools for the current user.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: ToolSerializer(many=True)})
    def get(self, request):
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        tools = profile.get_available_tools()
        return Response(ToolSerializer(tools, many=True).data)


@extend_schema(tags=['Tools'])
class ToolToggleView(APIView):
    """
    Enable or disable a tool for the current user.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # ID-42: accept the product-facing "service"/"service_slug" body key (what
        # the id_toggle_service MCP tool and the Services UI send) in addition to
        # the legacy "tool"/"tool_slug". The model is Tool; the user-facing surface
        # is "service", so both must resolve to the same slug.
        tool_slug = (
            request.data.get('tool')
            or request.data.get('service')
            or request.data.get('service_slug')
            or request.data.get('tool_slug')
        )
        enable = request.data.get('enable', True)

        if not tool_slug:
            return Response(
                {'error': 'A service slug is required (send "service").'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            tool = Tool.objects.get(slug=tool_slug, is_active=True)
        except Tool.DoesNotExist:
            return Response({'error': 'Tool not found'}, status=status.HTTP_404_NOT_FOUND)

        profile, _ = UserProfile.objects.get_or_create(user=request.user)

        if enable:
            # ID-8: server-side authz — a non-admin must not be able to self-grant
            # a service they were not approved for. Default-deny; never trust the
            # client. (Disabling a tool is always allowed — turning access OFF is
            # not an escalation.)
            _TIER_ORDER = ['free', 'basic', 'premium', 'enterprise']
            is_admin = request.user.is_staff or request.user.is_superuser

            if tool.requires_approval and not is_admin:
                return Response(
                    {'error': 'This service requires approval. Use the request endpoint instead.'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            if tool.requires_superuser and not request.user.is_superuser:
                return Response(
                    {'error': 'This service requires superuser status.'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            if not is_admin:
                user_tier = getattr(profile, 'subscription_tier', 'free')
                try:
                    insufficient = _TIER_ORDER.index(tool.minimum_tier) > _TIER_ORDER.index(user_tier)
                except ValueError:
                    insufficient = True  # unknown tier on either side → default-deny
                if insufficient:
                    return Response(
                        {'error': f'This service requires the {tool.minimum_tier} tier or higher.'},
                        status=status.HTTP_403_FORBIDDEN,
                    )

            profile.enable_tool(tool)
            return Response({'message': f'Tool {tool.display_name} enabled'})
        else:
            profile.disable_tool(tool)
            return Response({'message': f'Tool {tool.display_name} disabled'})


@extend_schema(tags=['OAuth'])
class GoogleLoginView(APIView):
    """
    Initiate or complete Google OAuth login.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        """Return the Google OAuth authorize URL (with CSRF state)."""
        client_id = _google_client_id()
        if not client_id:
            return Response({'error': 'Google OAuth is not configured'}, status=status.HTTP_501_NOT_IMPLEMENTED)

        # CSRF state -> stash the caller's post-login continue target server-side
        # (never trust it back from the URL). Single-use, short TTL.
        state = secrets.token_urlsafe(24)
        continue_url = request.query_params.get('continue', '') or ''
        _oauth_cache().set(f'{_GOOGLE_STATE_PREFIX}{state}', {'continue': continue_url},
                  timeout=_GOOGLE_STATE_TTL)

        params = urlencode({
            'client_id': client_id,
            'redirect_uri': _google_redirect_uri(request),
            'response_type': 'code',
            'scope': 'openid email profile',
            'access_type': 'online',
            'state': state,
            'prompt': 'select_account',
        })
        return Response({'url': f'https://accounts.google.com/o/oauth2/v2/auth?{params}'})


# ── Google Sign-In (server-side OAuth; find-or-create a Shizuha ID user) ──────
# Cross-replica cache for OAuth state/handoff (per-pod LocMemCache would
# 500/expire the state when authorize + callback land on different pods).
def _oauth_cache():
    return caches['oauth_shared']

_GOOGLE_STATE_PREFIX = 'google_oauth_state:'
_GOOGLE_STATE_TTL = 600           # 10 min to complete the round-trip
_GOOGLE_HANDOFF_PREFIX = 'google_oauth_handoff:'
_GOOGLE_HANDOFF_TTL = 120         # SPA must claim tokens within 2 min


def _google_client_id():
    try:
        return SocialApp.objects.get(provider='google').client_id
    except SocialApp.DoesNotExist:
        return settings.SOCIALACCOUNT_PROVIDERS.get('google', {}).get('APP', {}).get('client_id', '')


def _google_client_secret():
    try:
        return SocialApp.objects.get(provider='google').secret
    except SocialApp.DoesNotExist:
        return settings.SOCIALACCOUNT_PROVIDERS.get('google', {}).get('APP', {}).get('secret', '')


def _google_redirect_uri(request):
    """The one redirect URI Google must whitelist. Env-pinned so it stays stable
    behind the /id proxy (request-derived host would drift across tailnet/edge)."""
    configured = os.environ.get('GOOGLE_REDIRECT_URI', '')
    if configured:
        return configured
    return request.build_absolute_uri('/shizuha-id/api/auth/social/callback/')


def _google_spa_callback():
    """Frontend page that finishes sign-in (claims the one-time handoff)."""
    return os.environ.get('GOOGLE_SPA_CALLBACK_URL', 'https://shizuha.com/id/auth/google')


def _unique_username(seed):
    base = normalize_username(seed) or 'user'
    base = base[:24].strip('-_.') or 'user'
    candidate = base
    i = 0
    # PLAT-5731: uniqueness must be enforced on the DERIVED mailbox local part,
    # not the raw username — 'alice' and 'alice@gmail.com' are distinct raw
    # values that both derive 'alice@shizuha.com'. A raw username__iexact check
    # alone lets a colliding pair both hold one signed mail identity.
    from .lifecycle import mailbox_localpart_taken
    while (User.objects.filter(username__iexact=candidate).exists()
           or mailbox_localpart_taken(candidate)):
        i += 1
        candidate = f'{base}{i}'
    return candidate


def _find_or_create_google_user(info):
    """Find-or-create a Shizuha ID user from verified Google userinfo.

    Links to an existing account when the verified email matches (Google has
    proven ownership). New accounts are auto-approved when GOOGLE_SIGNUP_AUTO_APPROVE
    is on (default) — a Google-verified email is stronger proof than an unverified
    self-serve email/password signup, so gating it behind manual approval would only
    add friction without adding assurance. Flip the env to fall back to pending.
    """
    email = normalize_email(info['email'])
    created = False
    user = User.objects.filter(email__iexact=email).first()
    if user is None:
        with transaction.atomic():
            user = User.objects.create(
                username=_unique_username(email.split('@')[0]),
                email=email,
                first_name=(info.get('given_name') or '')[:150],
                last_name=(info.get('family_name') or '')[:150],
                is_active=False,   # transition_user flips this per policy below
            )
            user.set_unusable_password()
            user.save(update_fields=['password'])
            profile, _ = UserProfile.objects.get_or_create(user=user)
            # Every identity gets a valid avatar (operator 2026-08): a
            # deterministic stock pick unless the user later chooses/edits.
            assign_default_avatar(profile, user.username)
        created = True

    auto_approve = os.environ.get('GOOGLE_SIGNUP_AUTO_APPROVE', '1').lower() in ('1', 'true', 'yes')
    if created and auto_approve:
        from .lifecycle import transition_user, LifecycleState
        try:
            transition_user(user, LifecycleState.ACTIVE, actor=None,
                            reason='google-oauth verified-email signup')
        except Exception:
            logger.exception('google signup: lifecycle activation failed for %s', user.username)
    return user, created


@extend_schema(tags=['OAuth'])
class GoogleCallbackView(APIView):
    """GET — Google redirects here with ?code&state. Exchange -> user -> handoff."""
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        err = request.query_params.get('error')
        if err:
            return _google_fail(request, err)
        code = request.query_params.get('code')
        state = request.query_params.get('state')
        if not code or not state:
            return _google_fail(request, 'missing code/state')

        stashed = _oauth_cache().get(f'{_GOOGLE_STATE_PREFIX}{state}')
        if stashed is None:
            return _google_fail(request, 'invalid or expired state')
        _oauth_cache().delete(f'{_GOOGLE_STATE_PREFIX}{state}')
        continue_url = stashed.get('continue', '') or ''

        client_id, client_secret = _google_client_id(), _google_client_secret()
        if not client_id or not client_secret:
            return _google_fail(request, 'Google OAuth is not configured')

        try:
            tok = _admin_req.post('https://oauth2.googleapis.com/token', data={
                'code': code,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': _google_redirect_uri(request),
                'grant_type': 'authorization_code',
            }, timeout=10)
            if tok.status_code >= 400:
                logger.warning('google token exchange failed: %s', tok.text[:300])
                return _google_fail(request, 'google token exchange failed')
            access = tok.json().get('access_token')
            info = _admin_req.get('https://openidconnect.googleapis.com/v1/userinfo',
                                  headers={'Authorization': f'Bearer {access}'}, timeout=10).json()
        except Exception:
            logger.exception('google oauth callback error')
            return _google_fail(request, 'google sign-in failed')

        if not info.get('email') or not info.get('email_verified', False):
            return _google_fail(request, 'google account has no verified email')

        email = normalize_email(info['email'])
        existing = User.objects.filter(email__iexact=email).first()
        if existing is None:
            denied = signup_abuse.reject_signup(
                request, email=email, captcha_token='', require_captcha=False,
            )
            if denied is not None:
                return _google_fail(request, 'signup_denied')

        user, created = _find_or_create_google_user(info)
        if created:
            signup_abuse.record_signup(request, email)

        if not user.is_active:
            # Created pending (auto-approve off) or previously deactivated/denied.
            sep = '&' if '?' in _google_spa_callback() else '?'
            return redirect(f'{_google_spa_callback()}{sep}pending=1')

        tokens = get_tokens_for_user(user, amr=['google'])
        record_token_event('google', 'success')

        handoff = secrets.token_urlsafe(32)
        _oauth_cache().set(f'{_GOOGLE_HANDOFF_PREFIX}{handoff}',
                  {'tokens': tokens, 'user_id': user.id}, timeout=_GOOGLE_HANDOFF_TTL)
        q = urlencode({'handoff': handoff, 'continue': continue_url})
        return redirect(f'{_google_spa_callback()}?{q}')


@extend_schema(tags=['OAuth'])
class SocialHandoffView(APIView):
    """POST {handoff} — one-time claim of the tokens minted by the OAuth callback.

    Keeps tokens out of the redirect URL: the callback stashes them server-side
    and the SPA exchanges an opaque single-use code for them here."""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        handoff = request.data.get('handoff', '')
        if not handoff:
            return Response({'error': 'handoff required'}, status=status.HTTP_400_BAD_REQUEST)
        key = f'{_GOOGLE_HANDOFF_PREFIX}{handoff}'
        payload = _oauth_cache().get(key)
        if payload is None:
            return Response({'error': 'invalid or expired handoff'}, status=status.HTTP_400_BAD_REQUEST)
        _oauth_cache().delete(key)  # single-use
        try:
            user = User.objects.get(id=payload['user_id'])
        except User.DoesNotExist:
            return Response({'error': 'user not found'}, status=status.HTTP_400_BAD_REQUEST)
        tokens = payload['tokens']
        return _set_jwt_auth_cookies(
            Response({'user': UserSerializer(user).data, 'tokens': tokens}), tokens)


def _google_fail(request, reason):
    logger.info('google sign-in failed: %s', reason)
    sep = '&' if '?' in _google_spa_callback() else '?'
    return redirect(f'{_google_spa_callback()}{sep}{urlencode({"error": reason})}')


@extend_schema(tags=['OAuth'])
class GitHubLoginView(APIView):
    """
    Initiate GitHub OAuth login.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        """Return the GitHub OAuth URL."""
        try:
            app = SocialApp.objects.get(provider='github')
            client_id = app.client_id
        except SocialApp.DoesNotExist:
            client_id = settings.SOCIALACCOUNT_PROVIDERS.get('github', {}).get('APP', {}).get('client_id', '')

        if not client_id:
            return Response({'error': 'GitHub OAuth is not configured'}, status=status.HTTP_501_NOT_IMPLEMENTED)

        callback_url = request.build_absolute_uri('/api/auth/social/callback/')
        auth_url = (
            f"https://github.com/login/oauth/authorize?"
            f"client_id={client_id}&"
            f"redirect_uri={callback_url}&"
            f"scope=user:email"
        )
        return Response({'url': auth_url})


@extend_schema(tags=['OAuth'])
class OAuthStatusView(APIView):
    """
    Check which OAuth providers are configured.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        providers = {}

        # Check Google
        try:
            SocialApp.objects.get(provider='google')
            providers['google'] = True
        except SocialApp.DoesNotExist:
            client_id = settings.SOCIALACCOUNT_PROVIDERS.get('google', {}).get('APP', {}).get('client_id', '')
            providers['google'] = bool(client_id)

        # Check GitHub
        try:
            SocialApp.objects.get(provider='github')
            providers['github'] = True
        except SocialApp.DoesNotExist:
            client_id = settings.SOCIALACCOUNT_PROVIDERS.get('github', {}).get('APP', {}).get('client_id', '')
            providers['github'] = bool(client_id)

        return Response({
            'providers': providers,
            'username_password': True,
        })


@extend_schema_view(
    list=extend_schema(tags=['Tool Calls']),
    retrieve=extend_schema(tags=['Tool Calls']),
    create=extend_schema(tags=['Tool Calls']),
)
class ToolCallViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing tool calls.
    """
    serializer_class = ToolCallSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ToolCall.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


@extend_schema_view(
    list=extend_schema(tags=['Tool Responses']),
    retrieve=extend_schema(tags=['Tool Responses']),
    create=extend_schema(tags=['Tool Responses']),
)
class ToolResponseViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing tool responses.
    """
    serializer_class = ToolResponseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ToolResponse.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


@extend_schema(tags=['Admin'])
class AllUsersView(APIView):
    """
    List all users in the system (staff only).
    Used by admin dashboard for superuser view.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: UserSerializer(many=True)})
    def get(self, request):
        if not request.user.is_staff:
            return Response(
                {'error': 'Staff access required'},
                status=status.HTTP_403_FORBIDDEN
            )

        # ID-53: per-caller rate-limit + enforced pagination so the full-population
        # list is neither a cheap scraping surface nor an unbounded response.
        rl = list_rate_limit.enforce(request)
        if rl is not None:
            return rl

        qs = User.objects.filter(is_active=True).order_by('-date_joined')
        total = qs.count()
        try:
            limit = min(max(int(request.query_params.get('limit', 50)), 1), 100)
            offset = max(int(request.query_params.get('offset', 0)), 0)
        except (TypeError, ValueError):
            return Response(
                {'error': 'limit and offset must be integers'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        users = qs[offset:offset + limit]
        return Response({
            'count': total,
            'limit': limit,
            'offset': offset,
            'users': UserSerializer(users, many=True).data
        })


@extend_schema(tags=['Authentication'])
class PasswordResetRequestView(APIView):
    """
    Request a password reset email.

    Always returns 200 to prevent email enumeration.
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={200: {'description': 'Reset email sent if account exists'}}
    )
    def post(self, request):
        started_at = time.monotonic()
        email = request.data.get('email', '').strip().lower()
        generic_body = {'message': password_reset_security.GENERIC_RESET_MESSAGE}

        try:
            if not email:
                return Response(generic_body, status=status.HTTP_200_OK)

            if password_reset_security.is_locked(request, email):
                return Response(
                    {**generic_body, 'retry_after': password_reset_security.lockout_remaining(request, email)},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            _failures, lockout_s = password_reset_security.record_request(request, email)
            if lockout_s:
                return Response(
                    {**generic_body, 'retry_after': lockout_s},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            # Get client IP for audit only; spoofable IPs never form the only
            # security key because reset throttling also keys by account/email hash.
            ip_address = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
            if not ip_address:
                ip_address = request.META.get('REMOTE_ADDR')

            try:
                user = User.objects.get(email__iexact=email, is_active=True)

                # Invalidate any existing unused tokens
                PasswordResetToken.objects.filter(
                    user=user,
                    used_at__isnull=True
                ).update(expires_at=timezone.now())

                # Create new token
                token = PasswordResetToken.create_for_user(user, ip_address=ip_address)

                # Build reset URL
                frontend_url = getattr(settings, 'FRONTEND_URL', 'https://erp.shizuha.com/id')
                reset_url = f"{frontend_url}/reset-password?token={token.token}"

                # Send email off the response path; synchronous mail service
                # latency must not become an account-existence timing oracle.
                password_reset_security.send_password_reset_email_async(user, reset_url)
                logger.info("Password reset requested for active account")

            except User.DoesNotExist:
                # Do not send account-creation email from forgot-password. That
                # branch performed visibly different work and created an abuse /
                # timing-enumeration wrinkle. Keep the outward reset response
                # identical and pad the branch below.
                password_reset_security.dummy_reset_work()

            # Always return success to prevent email enumeration
            return Response(generic_body, status=status.HTTP_200_OK)
        finally:
            password_reset_security.pad_response(started_at)


@extend_schema(tags=['Authentication'])
class PasswordResetValidateView(APIView):
    """
    Validate a password reset token.
    Used by frontend to check if token is valid before showing reset form.
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=PasswordResetValidateSerializer,
        responses={
            200: {'description': 'Token is valid'},
            400: {'description': 'Token is invalid or expired'}
        }
    )
    def post(self, request):
        token_str = request.data.get('token', '')

        if not token_str:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = PasswordResetToken.objects.get(token=token_str)

            if not token.is_valid:
                return Response(
                    {'error': 'This reset link has expired or already been used.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            return Response({
                'valid': True,
                'email': token.user.email  # Show which account will be reset
            })

        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Invalid reset link.'},
                status=status.HTTP_400_BAD_REQUEST
            )


@extend_schema(tags=['Authentication'])
class PasswordResetConfirmView(APIView):
    """
    Confirm password reset with new password.
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses={
            200: {'description': 'Password reset successful'},
            400: {'description': 'Invalid token or password'}
        }
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token_str = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        try:
            token = PasswordResetToken.objects.select_related('user').get(token=token_str)

            if not token.is_valid:
                return Response(
                    {'error': 'This reset link has expired or already been used.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = token.user

            # PLAT-556: agent service accounts have no forgot-password flow; a
            # reset here would desync the container credential and break the agent.
            agent_block = _reject_agent_password_reset(user)
            if agent_block is not None:
                return agent_block

            # Validate password strength
            try:
                validate_password(new_password, user)
            except ValidationError as e:
                return Response(
                    {'error': list(e.messages)},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update password
            user.set_password(new_password)
            user.save()
            # ID-7: password reset revokes all prior sessions/tokens.
            revoke_all_user_tokens(user)
            logger.info("Password reset completed with prior tokens revoked")

            # Mark token as used
            token.mark_used()

            # Invalidate all other unused tokens for this user
            PasswordResetToken.objects.filter(
                user=user,
                used_at__isnull=True
            ).exclude(id=token.id).update(expires_at=timezone.now())

            logger.info("Password reset completed")

            return Response({
                'message': 'Your password has been reset successfully. You can now log in.'
            })

        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Invalid reset link.'},
                status=status.HTTP_400_BAD_REQUEST
            )


# --- Service Access Control views ---

@extend_schema(tags=['Services'])
class ServiceListView(APIView):
    """
    List all services with user's enabled/request status.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        tools = Tool.objects.filter(is_active=True)
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        enabled_ids = set(profile.enabled_tools.values_list('id', flat=True))
        pending_tool_ids = set(
            ServiceAccessRequest.objects.filter(
                user=request.user, status='pending'
            ).values_list('tool_id', flat=True)
        )

        result = []
        for tool in tools:
            result.append({
                **ToolSerializer(tool).data,
                'requires_approval': tool.requires_approval,
                'is_enabled': tool.id in enabled_ids,
                'pending_request': tool.id in pending_tool_ids,
                'can_toggle': not tool.requires_approval or request.user.is_staff,
            })
        return Response(result)


@extend_schema(tags=['Services'])
class ServiceAccessRequestCreateView(APIView):
    """
    Request access to a restricted service.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ServiceAccessRequestCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tool_slug = serializer.validated_data['tool_slug']
        reason = serializer.validated_data.get('reason', '')
        organization_id = serializer.validated_data.get('organization_id')

        try:
            tool = Tool.objects.get(slug=tool_slug, is_active=True)
        except Tool.DoesNotExist:
            return Response({'error': 'Service not found'}, status=status.HTTP_404_NOT_FOUND)

        if not tool.requires_approval:
            return Response(
                {'error': 'This service does not require approval. Use the toggle endpoint.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if already enabled
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        if profile.enabled_tools.filter(id=tool.id).exists():
            return Response(
                {'error': 'You already have access to this service.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check for existing pending request
        if ServiceAccessRequest.objects.filter(
            user=request.user, tool=tool, status='pending'
        ).exists():
            return Response(
                {'error': 'You already have a pending request for this service.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        req = ServiceAccessRequest.objects.create(
            user=request.user,
            tool=tool,
            reason=reason,
            organization_id=organization_id,
        )
        return Response(
            ServiceAccessRequestListSerializer(req).data,
            status=status.HTTP_201_CREATED
        )


@extend_schema(tags=['Services'])
class ServiceAccessRequestListView(APIView):
    """
    List user's own access requests.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        requests_qs = ServiceAccessRequest.objects.filter(
            user=request.user
        ).select_related('tool')
        status_filter = request.query_params.get('status')
        if status_filter:
            requests_qs = requests_qs.filter(status=status_filter)
        return Response(ServiceAccessRequestListSerializer(requests_qs, many=True).data)


# --- Admin endpoints (staff-only) ---

@extend_schema(tags=['Admin Services'])
class AdminServiceListView(APIView):
    """
    List all services with global stats (staff only).
    """
    permission_classes = [IsStaffAdmin]
    boundary_denial_event = {
        'operation': 'id.admin_list_services',
        'reason': 'staff_endpoint',
    }

    def get(self, request):
        tools = Tool.objects.all().order_by('display_name')
        result = []
        for tool in tools:
            enabled_count = tool.enabled_by.count()
            pending_count = tool.access_requests.filter(status='pending').count()
            result.append({
                **ToolSerializer(tool).data,
                'requires_approval': tool.requires_approval,
                'requires_superuser': tool.requires_superuser,
                'enabled_user_count': enabled_count,
                'pending_request_count': pending_count,
            })
        return Response(result)


@extend_schema(tags=['Admin Services'])
class AdminServiceUpdateView(APIView):
    """
    Update service config (staff only).
    """
    permission_classes = [IsStaffAdmin]

    def patch(self, request, slug):
        try:
            tool = Tool.objects.get(slug=slug)
        except Tool.DoesNotExist:
            return Response({'error': 'Service not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = AdminServiceUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        changes = {
            field: serializer.validated_data[field]
            for field in ['is_default_enabled', 'requires_approval', 'is_active']
            if field in serializer.validated_data
        }
        # ID-34: privileged catalog mutation must land in the audit ledger.
        tool = audited_service_catalog_update(
            actor=request.user, tool=tool, changes=changes, request=request,
        )

        return Response(ToolSerializer(tool).data)


@extend_schema(tags=['Admin Services'])
class AdminUserServicesView(APIView):
    """
    Get or modify a user's enabled services (staff only).
    """
    permission_classes = [IsStaffAdmin]

    def get(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # INV-5: report the same effective set that tokens carry (ID-11).
        # Ensures staff users see all services, not just their M2M row.
        enabled_slugs = get_effective_services(user)
        return Response({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'is_staff': user.is_staff,
            'enabled_services': enabled_slugs,
        })

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = AdminUserServiceGrantSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        slugs = serializer.validated_data['service_slugs']
        action = serializer.validated_data['action']
        tools = list(Tool.objects.filter(slug__in=slugs, is_active=True))

        break_glass_reason = ''
        if user.id == request.user.id and any(_privileged_service(tool) for tool in tools):
            break_glass_reason = _break_glass_allowed(request, action=f'self-service-{action}')
            if not break_glass_reason:
                return _deny_admin_attempt(
                    request=request, target=user,
                    reason_code='self_privileged_service_change_denied',
                    attempted_action=f'user_services.{action}',
                    attempted={'service_slugs': sorted(slugs), 'action': action},
                )

        # ID-34: grant/revoke must land in the audit ledger.
        enabled_slugs = audited_user_services_change(
            actor=request.user, user=user, tools=tools, action=action,
            request=request, break_glass_reason=break_glass_reason,
        )
        return Response({
            'user_id': user.id,
            'enabled_services': enabled_slugs,
        })


@extend_schema(tags=['Admin Services'])
class AdminAccessRequestListView(APIView):
    """
    List all pending access requests (staff only).
    """
    permission_classes = [IsStaffAdmin]

    def get(self, request):
        requests_qs = ServiceAccessRequest.objects.select_related(
            'tool', 'user'
        )
        status_filter = request.query_params.get('status', 'pending')
        if status_filter != 'all':
            requests_qs = requests_qs.filter(status=status_filter)
        return Response(ServiceAccessRequestListSerializer(requests_qs, many=True).data)


@extend_schema(tags=['Admin Services'])
class AdminAccessRequestReviewView(APIView):
    """
    Approve or deny an access request (staff only).
    """
    permission_classes = [IsStaffAdmin]

    def patch(self, request, pk):
        try:
            access_request = ServiceAccessRequest.objects.select_related(
                'tool', 'user'
            ).get(id=pk)
        except ServiceAccessRequest.DoesNotExist:
            return Response({'error': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)

        if access_request.status != 'pending':
            return Response(
                {'error': 'This request has already been reviewed.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ServiceAccessRequestReviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        break_glass_reason = ''
        if access_request.user_id == request.user.id:
            break_glass_reason = _break_glass_allowed(request, action='self-access-request-review')
            if not break_glass_reason:
                audited_admin_policy_denied(
                    actor=request.user, target_type='service_access_request',
                    target_id=access_request.id,
                    target_repr=f'{access_request.user.username}:{access_request.tool.slug}',
                    reason_code='self_access_request_review_denied',
                    attempted_action='access_request.review',
                    attempted={'status': serializer.validated_data['status'], 'tool': access_request.tool.slug},
                    request=request,
                )
                return Response({'error': 'self_access_request_review_denied'}, status=status.HTTP_403_FORBIDDEN)

        # ID-34: review (and the auto-grant on approval) must land in the
        # audit ledger atomically with the mutation.
        access_request = audited_access_request_review(
            actor=request.user,
            access_request=access_request,
            new_status=serializer.validated_data['status'],
            review_note=serializer.validated_data.get('review_note', ''),
            request=request, break_glass_reason=break_glass_reason,
        )
        if access_request.status == 'approved':
            logger.info(
                f"Service {access_request.tool.slug} approved for user "
                f"{access_request.user.username} by {request.user.username}"
            )

        return Response(ServiceAccessRequestListSerializer(access_request).data)


# --- Push Token Management ---

@extend_schema(tags=['Push Notifications'])
class RegisterPushTokenView(APIView):
    """
    Register or unregister a push notification token.
    POST: Upsert push token (register/update).
    DELETE: Deactivate push token (on logout).
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        token = request.data.get('token')
        device_id = request.data.get('device_id')
        platform = request.data.get('platform')

        if not token or not device_id or not platform:
            return Response(
                {'error': 'token, device_id, and platform are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if platform not in ('android', 'ios', 'web', 'wearos'):
            return Response(
                {'error': 'platform must be android, ios, web, or wearos'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ID-70: ``sid`` is the stable family key across access/refresh rotation;
        # retain jti only as legacy/debug metadata.
        session_sid = ''
        session_jti = ''
        try:
            if request.auth is not None:
                session_sid = str(request.auth.get('sid') or '')
                session_jti = str(request.auth.get('jti') or '')
        except Exception:
            session_sid = ''
            session_jti = ''

        # Upsert: update if same user+device_id, otherwise create
        push_token, created = PushToken.objects.update_or_create(
            user=request.user,
            device_id=device_id,
            defaults={
                'token': token,
                'platform': platform,
                'is_active': True,
                'session_jti': session_jti,
                'session_sid': session_sid,
            },
        )

        logger.info(
            f"Push token {'created' if created else 'updated'} for user "
            f"{request.user.username} device {device_id}"
        )

        # Hygiene: an app install on Android whose data is cleared regenerates
        # its SSAID → a new device_id row is inserted here, but the PREVIOUS
        # row for the same physical install stays is_active=True forever
        # unless FCM later returns UnregisteredError on send. That orphaning
        # is what causes push fan-out to the same physical device. When we
        # see a fresh registration, sweep older (user, platform) rows of the
        # same token family (Expo vs native FCM) that haven't been refreshed
        # in the last 14 days and deactivate them. We deliberately DON'T
        # touch rows on other platforms (web/wearos) or the opposite token
        # family — a user can legitimately run the Kotlin app (native FCM)
        # and ori-expo (Expo) on the same Android device.
        is_expo = token.startswith('ExponentPushToken')
        stale_cutoff = timezone.now() - timedelta(days=14)
        stale_qs = PushToken.objects.filter(
            user=request.user,
            platform=platform,
            is_active=True,
            updated_at__lt=stale_cutoff,
        ).exclude(pk=push_token.pk)
        # Narrow to same token family so we don't kill the complementary app
        if is_expo:
            stale_qs = stale_qs.filter(token__startswith='ExponentPushToken')
        else:
            stale_qs = stale_qs.exclude(token__startswith='ExponentPushToken')
        deactivated = stale_qs.update(is_active=False)
        if deactivated:
            logger.info(
                f"Deactivated {deactivated} stale {platform}/"
                f"{'expo' if is_expo else 'native'} push token(s) for user "
                f"{request.user.username} (not refreshed in 14+ days)"
            )

        return Response({
            'status': 'registered',
            'device_id': push_token.device_id,
            'platform': push_token.platform,
            'created': created,
        }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

    def delete(self, request):
        device_id = request.data.get('device_id')

        if not device_id:
            return Response(
                {'error': 'device_id is required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        updated = PushToken.objects.filter(
            user=request.user,
            device_id=device_id,
        ).update(is_active=False)

        if updated:
            logger.info(f"Push token deactivated for user {request.user.username} device {device_id}")

        return Response({'status': 'unregistered', 'device_id': device_id})


# --- Account Approval views (staff-only) ---

@extend_schema(tags=['Admin Approval'])
class PendingUsersView(APIView):
    """
    List users pending account approval (staff only).
    """
    permission_classes = [IsStaffAdmin]

    def get(self, request):
        pending_profiles = UserProfile.objects.filter(
            approval_status='pending'
        ).select_related('user').order_by('-created_at')

        results = []
        for profile in pending_profiles:
            user = profile.user
            results.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'date_joined': user.date_joined,
                'approval_status': profile.approval_status,
            })

        return Response(results)


@extend_schema(tags=['Admin Approval'])
class PendingUsersCountView(APIView):
    """
    Count of users pending account approval (staff only).
    """
    permission_classes = [IsStaffAdmin]

    def get(self, request):
        count = UserProfile.objects.filter(approval_status='pending').count()
        return Response({'count': count})


@extend_schema(tags=['Admin Approval'])
class UserApprovalView(APIView):
    """
    Approve or deny a pending user's account (admin review).

    ID-24 P1 (HLD ID-3 §4.2, L-1): staff-only. Approving sets ``is_active=True``
    and grants the least-privilege default tools, so the mutation must be gated to
    administrators — matching the ``is_staff`` read gate on the pending list/count
    (``PendingUsersView``/``PendingUsersCountView``). The previous
    ``IsAuthenticated``-only rule let ANY authenticated user approve a pending
    account (privilege escalation past admin review) or deny/deactivate another
    pending user (griefing).

    This does NOT affect Hive agent provisioning: agents are created through the
    internal service API (``internal_urls.py`` "create agent user"), which sets
    ``is_active=True`` and ``approval_status='approved'`` explicitly — it never
    routes through this admin approval endpoint.
    """
    permission_classes = [IsStaffAdmin]

    def patch(self, request, user_id):

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserApprovalReviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_status = serializer.validated_data['status']
        review_note = serializer.validated_data.get('review_note', '')

        profile, _ = UserProfile.objects.get_or_create(user=user)

        if profile.approval_status != 'pending':
            return Response(
                {'error': 'This user has already been reviewed.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # ID-32 + ID-34: the review routes through the lifecycle FSM (which
        # syncs approval_status/is_active and writes UserLifecycleAudit) and
        # commits atomically with the privileged AdminAuditEvent. Notification
        # emails stay out here, after commit.
        from .lifecycle import IllegalLifecycleTransition
        try:
            profile = audited_user_approval(
                actor=request.user, user=user, profile=profile,
                new_status=new_status, review_note=review_note, request=request,
            )
        except IllegalLifecycleTransition as exc:
            return Response(
                {'error': f'Cannot review this user: {exc}'},
                status=status.HTTP_409_CONFLICT,
            )

        if new_status == 'approved':
            logger.info(f"User {user.username} approved by {request.user.username}")
            try:
                send_account_approved_email(user)
            except EmailServiceError as e:
                logger.error(f"Failed to send approval email to {user.email}: {e}")
        elif new_status == 'denied':
            logger.info(f"User {user.username} denied by {request.user.username}")
            try:
                send_account_denied_email(user, review_note)
            except EmailServiceError as e:
                logger.error(f"Failed to send denial email to {user.email}: {e}")

        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'approval_status': profile.approval_status,
        })


class UserReactivateView(APIView):
    """Reactivate a denied or deactivated user (ID-32, HLD ID-3 §4.6).

    Staff-only (INV-4 — matches the UserApprovalView mutation gate). Routes
    through the lifecycle FSM: legal only from ``denied`` or ``deactivated``;
    soft-deleted users canNOT be reactivated (deleted is terminal until the
    hard-purge/cross-service-cleanup slice defines otherwise). The transition
    is audited (actor, from→to, reason).
    """
    permission_classes = [permissions.IsAdminUser]

    def patch(self, request, user_id):
        from .lifecycle import IllegalLifecycleTransition, LifecycleState, transition_user

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        reason = str(request.data.get('reason', '') or '')
        try:
            profile = transition_user(user, LifecycleState.ACTIVE, actor=request.user, reason=reason)
        except IllegalLifecycleTransition as exc:
            return Response(
                {'error': f'Cannot reactivate: {exc}'},
                status=status.HTTP_409_CONFLICT,
            )
        user.refresh_from_db(fields=['is_active'])
        logger.info(f"User {user.username} reactivated by {request.user.username}")

        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'approval_status': profile.approval_status,
            'lifecycle_state': profile.lifecycle_state,
        })


class AdminSetPasswordView(APIView):
    """
    Set a user's password (superuser only).
    Used by the daemon to provision agent accounts.
    """
    permission_classes = [IsSuperUserAdmin]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # PLAT-556: block a HUMAN security sweep from resetting an agent service
        # account's password (it desyncs the container credential and breaks the
        # agent). The DELIBERATE single-write provisioning / drift self-heal path
        # opts in via `agent_provisioning: true` — it sets BOTH the broker-scoped
        # credential AND this account together (PLAT-558), so it cannot drift.
        is_provisioning = bool(request.data.get('agent_provisioning'))
        agent_block = _reject_agent_password_reset(user, is_provisioning=is_provisioning)
        if agent_block is not None:
            logger.warning(
                f"Blocked admin password reset for agent account {user.username} "
                f"by {request.user.username} (PLAT-556 — human sweep; use the "
                f"provisioning single-write path)")
            return agent_block

        break_glass_reason = ''
        if user.id == request.user.id:
            break_glass_reason = _break_glass_allowed(request, action='self-admin-password-set')
            if not break_glass_reason:
                return _deny_admin_attempt(
                    request=request, target=user,
                    reason_code='self_admin_password_set_denied',
                    attempted_action='user_password.admin_set',
                    attempted={'password_changed': True},
                )

        new_password = request.data.get('password', '')
        if not new_password or len(new_password) < 8:
            return Response({'error': 'Password must be at least 8 characters'}, status=status.HTTP_400_BAD_REQUEST)

        # ID-34: the password write commits atomically with its audit event.
        audited_admin_set_password(
            actor=request.user, user=user, new_password=new_password,
            request=request, break_glass_reason=break_glass_reason,
        )
        # ID-7: admin password reset revokes all of the target user's sessions.
        revoke_all_user_tokens(user)
        logger.info(f"Password reset for {user.username} by admin {request.user.username} (prior tokens revoked)")

        return Response({
            'id': user.id,
            'username': user.username,
            'message': 'Password updated successfully',
        })


def id_metrics(request):
    """Prometheus text exposition for Shizuha ID self-check metrics (PLAT-1278)."""
    from django.http import HttpResponse

    from .invariants import collect_id_invariant_metrics, render_prometheus_metrics
    from .security_events import render_boundary_event_metrics

    body = (
        render_prometheus_metrics(collect_id_invariant_metrics())
        + render_boundary_event_metrics()
    )
    return HttpResponse(body, content_type='text/plain; version=0.0.4; charset=utf-8')
