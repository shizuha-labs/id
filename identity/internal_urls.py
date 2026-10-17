"""
Internal API URLs for service-to-service communication.

Includes both unauthenticated internal endpoints (secured by network)
and authenticated admin endpoints for superuser operations.
"""
import logging
import os
import requests

from django.urls import path
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from . import list_rate_limit
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.crypto import constant_time_compare
from django.utils import timezone
from .serializers import UserSerializer, PublicUserSerializer
from .user_resolution import (
    UserResolutionError, resolve_user_by_email, resolve_user_by_id,
    resolve_user_by_username,
)
from .models import PushToken, UserProfile
from .permissions import IsSuperUserAdmin
from .views import revoke_all_user_tokens, _fetch_org_memberships
from .admin_audit import (
    audited_admin_user_create,
    audited_admin_user_delete,
    audited_admin_user_update,
    audited_admin_policy_denied,
)

logger = logging.getLogger(__name__)

EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send'

# Initialize Firebase Admin SDK for FCM push notifications
_firebase_app = None
if os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'):
    try:
        import firebase_admin
        from firebase_admin import credentials
        cred = credentials.Certificate(os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
        _firebase_app = firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialized for FCM push notifications")
    except Exception as e:
        logger.warning(f"Failed to initialize Firebase Admin SDK: {e}")

User = get_user_model()


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
    return str(request.data.get('break_glass_reason') or request.data.get('reason') or '').strip()


def _break_glass_allowed(request):
    reason = _break_glass_reason(request)
    if not reason or not getattr(request.user, 'is_superuser', False):
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


_INTERNAL_SERVICE_TOKEN_HEADER = 'X-Internal-Service-Token'


def _check_service_token(request):
    """ID-58 Phase A: verify the caller's X-Internal-Service-Token header.

    Returns True if the header is present and constant-time-matches the
    configured INTERNAL_SERVICE_TOKEN setting. If the setting is empty
    (not yet configured), always returns False so Phase A is a pure no-op
    until the operator provisions the token.

    Phase A (current): accept-and-log — the return value is used for logging
    and for granting UserSerializer to token-bearing callers, but non-token
    in-cluster callers still work (network-trust fallback).
    Phase C (future): when 100% token adoption is observed in logs, the caller
    can flip to reject non-token in-cluster calls with a uniform 404.
    """
    expected = getattr(settings, 'INTERNAL_SERVICE_TOKEN', '') or ''
    if not expected:
        return False
    supplied = request.headers.get(_INTERNAL_SERVICE_TOKEN_HEADER, '')
    return bool(supplied and constant_time_compare(supplied, expected))


def _scoped_user_serializer(request, target_user=None):
    """Return the appropriate serializer class based on caller trust.

    Revised ID-58 Phase A: token-bearing callers are treated as authorized
    service principals and always get the full UserSerializer (including email
    so Pulse /assign/ keeps working). Per-call token-present vs network-trust
    is logged to the 'identity.internal' logger for adoption monitoring.

    Full UserSerializer for:
    - service-token-bearing callers (ID-58 Phase A — authorized service
      principal via constant_time_compare on X-Internal-Service-Token),
    - direct in-cluster service-to-service calls (no ingress forwarding
      headers — InternalApiIngressGuardMiddleware already 404s any
      ingress-borne request to /api/internal/, so a request reaching a view
      here without X-Forwarded-For/X-Real-IP is a trusted platform service;
      Pulse/Connect/Hive key identity by EMAIL and break without it),
    - authenticated staff/superuser,
    - self-read.
    PublicUserSerializer (minimal PII) for everything else — defense in depth
    should the middleware ever be removed or the ingress detection change.
    """
    from .internal_api_guard import request_via_ingress

    token_authenticated = _check_service_token(request)
    via_ingress = request_via_ingress(request)

    # ID-58 Phase A adoption metric: log every internal lookup so callers'
    # migration to token-bearing auth is observable before Phase C flips.
    logger.info(
        "internal-lookup authz=%s via_ingress=%s ua=%.60s",
        "service-token" if token_authenticated else "network-trust",
        via_ingress,
        request.META.get('HTTP_USER_AGENT', '') or 'unknown',
    )

    if token_authenticated:
        return UserSerializer
    if not via_ingress:
        return UserSerializer
    if request.user and request.user.is_authenticated:
        if request.user.is_staff or request.user.is_superuser:
            return UserSerializer
        if target_user is not None and request.user.pk == target_user.pk:
            return UserSerializer
    return PublicUserSerializer



class InternalUserView(APIView):
    """
    Get user by ID for internal service-to-service calls.
    """
    permission_classes = [permissions.AllowAny]  # Internal calls, secured by network

    def get(self, request, user_id):
        try:
            user = resolve_user_by_id(user_id)
        except UserResolutionError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        if not user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_scoped_user_serializer(request, user)(user).data)


class InternalUserByEmailView(APIView):
    """
    Get user by email for internal service-to-service calls.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            user = resolve_user_by_email(request.query_params.get('email'))
        except UserResolutionError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        if not user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_scoped_user_serializer(request, target_user=user)(user).data)


class InternalUserByUsernameView(APIView):
    """
    Get user by username for internal service-to-service calls.

    Used by shizuha-connect's MessageUserView when a caller wants to send
    a DM addressed by username (the ergonomic default — agents see inbound
    messages prefixed with `[username]` and want to reply by that handle
    without an extra lookup hop). Mirrors `InternalUserByEmailView`.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            user = resolve_user_by_username(request.query_params.get('username'))
        except UserResolutionError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        if not user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_scoped_user_serializer(request, target_user=user)(user).data)


def _parse_int_list(raw):
    values = []
    for part in str(raw or '').split(','):
        part = part.strip()
        if not part:
            continue
        try:
            values.append(int(part))
        except (TypeError, ValueError):
            raise ValueError('ids must be a comma-separated list of integers')
    return values


def _approved_active_directory_queryset():
    """Canonical directory base: active, approved, non-deleted users only."""
    return (
        User.objects.select_related('profile')
        .filter(is_active=True)
        .filter(models.Q(profile__approval_status='approved') | models.Q(profile__isnull=True))
        .filter(models.Q(profile__lifecycle_state='active') | models.Q(profile__isnull=True))
    )


def _shared_org_visible_user_ids(caller, candidates):
    """Return candidate ids visible to caller under same-org directory policy."""
    candidate_list = list(candidates)
    if not getattr(caller, 'is_authenticated', False):
        return []
    if getattr(caller, 'is_staff', False) or getattr(caller, 'is_superuser', False):
        return [u.id for u in candidate_list]

    visible = {caller.id}
    caller_orgs = set((_fetch_org_memberships(caller) or {}).keys())
    if not caller_orgs:
        return [u.id for u in candidate_list if u.id in visible]

    for user in candidate_list:
        if user.id == caller.id:
            continue
        target_orgs = set((_fetch_org_memberships(user) or {}).keys())
        if caller_orgs & target_orgs:
            visible.add(user.id)
    return [u.id for u in candidate_list if u.id in visible]


class InternalUserListView(APIView):
    """
    Directory list/search for internal service-to-service calls.

    Results are scoped before count/pagination: staff/superusers can see the
    full active directory; ordinary humans and agent service accounts see self
    plus active users sharing at least one organization membership. Anonymous
    callers cannot list/search the directory. This keeps id_list_users from
    becoming a cross-org enumeration channel while preserving deterministic
    pagination for authorized results.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            ids = _parse_int_list(request.query_params.get('ids'))
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        caller = request.user
        if not getattr(caller, 'is_authenticated', False):
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        # ID-53: per-caller rate-limit on the directory list/search enumeration surface.
        rl = list_rate_limit.enforce(request)
        if rl is not None:
            return rl

        users = _approved_active_directory_queryset()
        if ids:
            users = users.filter(id__in=ids)

        search = (request.query_params.get('search') or '').strip()
        if search:
            users = users.filter(
                models.Q(username__icontains=search) |
                models.Q(email__icontains=search) |
                models.Q(first_name__icontains=search) |
                models.Q(last_name__icontains=search)
            )

        order_by = request.query_params.get('order_by', 'id')
        allowed_ordering = {'id', '-id', 'username', '-username', 'email', '-email', 'date_joined', '-date_joined'}
        if order_by not in allowed_ordering:
            return Response({'error': 'Unsupported order_by'}, status=status.HTTP_400_BAD_REQUEST)

        users = users.order_by(order_by, 'id' if order_by != 'id' else 'username')
        candidate_users = list(users[:500])
        visible_ids = _shared_org_visible_user_ids(caller, candidate_users)
        scoped_users = [u for u in candidate_users if u.id in set(visible_ids)]

        try:
            limit = min(max(int(request.query_params.get('limit', 20)), 1), 100)
            offset = max(int(request.query_params.get('offset', 0)), 0)
        except (TypeError, ValueError):
            return Response({'error': 'limit and offset must be integers'}, status=status.HTTP_400_BAD_REQUEST)

        page = scoped_users[offset:offset + limit]
        return Response({
            'count': len(scoped_users),
            'limit': limit,
            'offset': offset,
            'results': _scoped_user_serializer(request)(page, many=True).data,
        })


class InternalUserCreateView(APIView):
    """
    Create a user for internal service-to-service calls.
    Used by shizuha-agent to create users for AI agents.
    Secured by network (not exposed externally).
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        is_active = request.data.get('is_active', True)

        if not username or not email or not password:
            return Response(
                {'error': 'username, email, and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if user already exists
        if User.objects.filter(username=username).exists():
            return Response(
                {'error': f'Username "{username}" already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if User.objects.filter(email__iexact=email).exists():
            return Response(
                {'error': f'Email "{email}" already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate password
        try:
            validate_password(password)
        except ValidationError as e:
            return Response(
                {'error': 'Password validation failed', 'details': list(e.messages)},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create user (non-staff, non-superuser)
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        user.is_active = is_active
        user.save()

        # Internal service-created accounts are trusted — mark approved explicitly
        # so they don't accidentally enter the pending-approval gate (ID-31).
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.approval_status = 'approved'
        profile.lifecycle_state = 'active'
        profile.save(update_fields=['approval_status', 'lifecycle_state'])

        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


class AdminUserCreateView(APIView):
    """
    Create a new user (superuser only).
    """
    permission_classes = [IsSuperUserAdmin]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        is_staff = request.data.get('is_staff', False)
        is_superuser = request.data.get('is_superuser', False)
        is_active = request.data.get('is_active', True)

        if not username or not email or not password:
            return Response(
                {'error': 'username, email, and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if user already exists
        if User.objects.filter(username=username).exists():
            return Response(
                {'error': f'Username "{username}" already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if User.objects.filter(email__iexact=email).exists():
            return Response(
                {'error': f'Email "{email}" already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate password
        try:
            validate_password(password)
        except ValidationError as e:
            return Response(
                {'error': 'Password validation failed', 'details': list(e.messages)},
                status=status.HTTP_400_BAD_REQUEST
            )

        # ID-34: privileged account creation (incl. staff/superuser grants and
        # the trusted 'approved' status) commits atomically with its audit event.
        user = audited_admin_user_create(
            actor=request.user,
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            is_staff=is_staff,
            is_superuser=is_superuser,
            is_active=is_active,
            request=request,
        )

        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


class AdminUserUpdateView(APIView):
    """
    Update a user (superuser only).
    """
    permission_classes = [IsSuperUserAdmin]

    def patch(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Validate + collect allowed field changes, then apply them through the
        # audited wrapper (ID-34) so the mutation cannot commit without its
        # ledger event.
        changes = {}
        if 'username' in request.data:
            new_username = request.data['username']
            if User.objects.filter(username=new_username).exclude(id=user_id).exists():
                return Response(
                    {'error': f'Username "{new_username}" already exists'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            changes['username'] = new_username

        if 'email' in request.data:
            new_email = request.data['email']
            if User.objects.filter(email__iexact=new_email).exclude(id=user_id).exists():
                return Response(
                    {'error': f'Email "{new_email}" already exists'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            changes['email'] = new_email

        for field in ('first_name', 'last_name', 'is_staff', 'is_superuser', 'is_active'):
            if field in request.data:
                changes[field] = request.data[field]

        new_password = None
        if 'password' in request.data:
            try:
                validate_password(request.data['password'])
                new_password = request.data['password']
            except ValidationError as e:
                return Response(
                    {'error': 'Password validation failed', 'details': list(e.messages)},
                    status=status.HTTP_400_BAD_REQUEST
                )

        break_glass_reason = ''
        if user.id == request.user.id and (changes or new_password is not None):
            sensitive = sorted(set(changes) & {'is_staff', 'is_superuser', 'is_active'})
            if new_password is not None:
                sensitive.append('password')
            # Any self-targeted internal admin mutation is denied unless the
            # superuser explicitly enters break-glass with a reason.
            break_glass_reason = _break_glass_allowed(request)
            if not break_glass_reason:
                return _deny_admin_attempt(
                    request=request, target=user,
                    reason_code='self_admin_user_update_denied',
                    attempted_action='user_account.admin_update',
                    attempted={'fields': sorted(changes), 'sensitive_fields': sensitive},
                )

        user = audited_admin_user_update(
            actor=request.user, user=user, changes=changes,
            new_password=new_password, request=request,
            break_glass_reason=break_glass_reason,
        )
        return Response(UserSerializer(user).data)


class InternalUserDeleteView(APIView):
    """
    Delete (or deactivate) a user for internal service-to-service calls.
    Used by shizuha-agent when an AI agent is deleted.
    Secured by network (not exposed externally).
    """
    permission_classes = [permissions.AllowAny]

    def delete(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        username = user.username
        # Deactivate rather than hard-delete to preserve audit trails.
        # ID-32: route through the lifecycle FSM (active→deactivated, audited).
        from .lifecycle import IllegalLifecycleTransition, LifecycleState, transition_user
        try:
            transition_user(user, LifecycleState.DEACTIVATED, actor=None,
                            reason='internal service deactivation')
        except IllegalLifecycleTransition as exc:
            return Response(
                {'error': f'Cannot deactivate: {exc}'},
                status=status.HTTP_409_CONFLICT,
            )
        return Response({
            'message': f'User "{username}" deactivated successfully',
            'id': user_id,
        })


class AdminUserDeleteView(APIView):
    """
    Delete a user (superuser only).
    """
    permission_classes = [IsSuperUserAdmin]

    def delete(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        break_glass_reason = ''
        if user.id == request.user.id:
            break_glass_reason = _break_glass_allowed(request)
            if not break_glass_reason:
                return _deny_admin_attempt(
                    request=request, target=user,
                    reason_code='self_admin_user_delete_denied',
                    attempted_action='user_account.admin_delete',
                    attempted={'delete': True},
                )

        # ID-32/ID-34: soft delete commits atomically with its admin audit
        # event; the user row and lifecycle audit trail are preserved.
        username = user.username
        # ID-32 + ID-34: soft-delete through the audited admin wrapper. It
        # applies the lifecycle tombstone and appends the admin audit event in
        # one transaction; invalid lifecycle transitions are rejected.
        from .lifecycle import IllegalLifecycleTransition
        try:
            audited_admin_user_delete(actor=request.user, user=user, request=request, break_glass_reason=break_glass_reason)
        except IllegalLifecycleTransition as exc:
            return Response(
                {'error': f'Cannot delete: {exc}. Pending users must be denied first; '
                          f'already-deleted users cannot be deleted again.'},
                status=status.HTTP_409_CONFLICT,
            )
        return Response({'message': f'User "{username}" soft-deleted (audit trail preserved)'})


class AdminUserListView(APIView):
    """
    List all users with filters (superuser only).
    """
    permission_classes = [IsSuperUserAdmin]

    def get(self, request):
        rl = list_rate_limit.enforce(request)
        if rl is not None:
            return rl
        users = User.objects.all()

        # Filters
        if request.query_params.get('is_staff'):
            users = users.filter(is_staff=request.query_params.get('is_staff').lower() == 'true')
        if request.query_params.get('is_superuser'):
            users = users.filter(is_superuser=request.query_params.get('is_superuser').lower() == 'true')
        if request.query_params.get('is_active'):
            users = users.filter(is_active=request.query_params.get('is_active').lower() == 'true')
        if request.query_params.get('search'):
            search = request.query_params.get('search')
            users = users.filter(
                models.Q(username__icontains=search) |
                models.Q(email__icontains=search) |
                models.Q(first_name__icontains=search) |
                models.Q(last_name__icontains=search)
            )

        # Ordering
        order_by = request.query_params.get('order_by', '-date_joined')
        users = users.order_by(order_by)

        # Pagination
        limit = min(int(request.query_params.get('limit', 50)), 100)
        offset = int(request.query_params.get('offset', 0))
        total = users.count()
        users = users[offset:offset + limit]

        return Response({
            'count': total,
            'results': UserSerializer(users, many=True).data
        })


class InternalPushSendView(APIView):
    """
    Send push notification to a user's active devices via Expo Push API.
    Internal endpoint, secured by network (not exposed externally).

    POST /api/internal/push/send/
    Body: {
        "user_id": 1,
        "title": "Task Overdue!",
        "body": "Deploy hotfix is now overdue",
        "data": {"type": "pulse_overdue", "screen": "PulseTab"},
        "priority": "high",
        "channel_id": "pulse_alerts"
    }
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        user_id = request.data.get('user_id')
        title = request.data.get('title')
        body = request.data.get('body')
        data = request.data.get('data', {})
        priority = request.data.get('priority', 'high')
        channel_id = request.data.get('channel_id', 'default')

        if not user_id or not title or not body:
            return Response(
                {'error': 'user_id, title, and body are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Dedupe tokens before sending so a user with multiple historical
        # installs on the same physical device doesn't receive N copies.
        # Strategy (matches WhatsApp / Slack-style hygiene):
        #   1. Drop rows updated > 30 days ago — FCM tokens naturally rotate,
        #      anything unrefreshed for a month is effectively dead.
        #   2. Dedupe identical token strings (FCM can re-issue the same token
        #      across reinstalls, creating duplicate rows with different
        #      device_ids pointing to the same device).
        #   3. Keep only the most recently updated row per (platform,
        #      token_family) — where token_family is "expo" for Expo tokens
        #      and "native" for raw FCM. This collapses orphan rows from
        #      prior app installs on the same device while preserving the
        #      distinction between the Kotlin app (native FCM) and ori-expo
        #      (Expo Push) both running on the same Android device, and
        #      across multiple platforms (web, wearos).
        from django.utils import timezone as _tz
        from datetime import timedelta as _td
        freshness_cutoff = _tz.now() - _td(days=30)
        qs = (
            PushToken.objects
            .filter(user_id=user_id, is_active=True, updated_at__gte=freshness_cutoff)
            .order_by('-updated_at')
        )
        seen_tokens = set()
        seen_family_keys = set()
        deduped = []
        for pt in qs:
            tok = pt.token or ''
            if tok in seen_tokens:
                continue
            seen_tokens.add(tok)
            family = 'expo' if tok.startswith('ExponentPushToken') else 'native'
            family_key = (pt.platform, family)
            if family_key in seen_family_keys:
                # Older orphan row for same (platform, token_family) —
                # a newer registration already superseded it on this device.
                continue
            seen_family_keys.add(family_key)
            deduped.append(pt)

        tokens = deduped
        if not tokens:
            return Response({'sent': 0, 'failed': 0, 'details': [], 'message': 'No active devices'})

        # Split tokens by format: Expo tokens start with "ExponentPushToken[",
        # everything else (raw FCM tokens from native Android) goes via FCM
        expo_tokens = [pt for pt in tokens if pt.token.startswith('ExponentPushToken')]
        fcm_tokens = [pt for pt in tokens if not pt.token.startswith('ExponentPushToken')]

        sent = 0
        failed = 0
        details = []

        # Send via Expo Push API (ExponentPushToken[...] format)
        if expo_tokens:
            expo_sent, expo_failed, expo_details = self._send_expo(
                expo_tokens, title, body, data, priority, channel_id
            )
            sent += expo_sent
            failed += expo_failed
            details.extend(expo_details)

        # Send via FCM (native FCM tokens from Android/Wear OS)
        if fcm_tokens:
            fcm_sent, fcm_failed, fcm_details = self._send_fcm(
                fcm_tokens, title, body, data, priority, channel_id
            )
            sent += fcm_sent
            failed += fcm_failed
            details.extend(fcm_details)

        return Response({'sent': sent, 'failed': failed, 'details': details})

    def _send_expo(self, tokens, title, body, data, priority, channel_id):
        """Send push notifications via Expo Push API."""
        messages = []
        token_map = {}
        for i, pt in enumerate(tokens):
            messages.append({
                'to': pt.token,
                'sound': 'default',
                'title': title,
                'body': body,
                'data': data,
                'badge': 1,
                'priority': priority,
                'channelId': channel_id,
            })
            token_map[i] = pt

        sent = 0
        failed = 0
        details = []

        try:
            resp = requests.post(
                EXPO_PUSH_URL,
                json=messages,
                headers={
                    'Accept': 'application/json',
                    'Accept-Encoding': 'gzip, deflate',
                    'Content-Type': 'application/json',
                },
                timeout=15,
            )

            if resp.status_code == 200:
                result = resp.json()
                tickets = result.get('data', [])
                for i, ticket in enumerate(tickets):
                    ticket_status = ticket.get('status')
                    if ticket_status == 'ok':
                        sent += 1
                        details.append({'device': token_map[i].device_id, 'status': 'ok'})
                    else:
                        failed += 1
                        error_msg = ticket.get('message', '')
                        error_type = ticket.get('details', {}).get('error', '')
                        details.append({
                            'device': token_map[i].device_id,
                            'status': 'error',
                            'error': error_msg,
                        })
                        if error_type == 'DeviceNotRegistered':
                            token_map[i].is_active = False
                            token_map[i].save(update_fields=['is_active'])
                            logger.info(f"Deactivated stale token for device {token_map[i].device_id}")
            else:
                logger.warning(f"Expo Push API returned {resp.status_code}: {resp.text}")
                failed = len(messages)
                details = [{'status': 'error', 'error': f'Expo API {resp.status_code}'}]
        except Exception as e:
            logger.error(f"Error calling Expo Push API: {e}")
            failed = len(messages)
            details = [{'status': 'error', 'error': str(e)}]

        return sent, failed, details

    def _send_fcm(self, tokens, title, body, data, priority, channel_id):
        """Send push notifications via Firebase Cloud Messaging."""
        if not _firebase_app:
            logger.warning("Firebase Admin SDK not initialized, skipping FCM push")
            return 0, len(tokens), [
                {'device': pt.device_id, 'status': 'error', 'error': 'FCM not configured'}
                for pt in tokens
            ]

        from firebase_admin import messaging

        sent = 0
        failed = 0
        details = []

        fcm_data = {k: str(v) for k, v in data.items()} if data else {}
        fcm_data['channel_id'] = channel_id
        fcm_data['channelId'] = channel_id  # Kotlin reads camelCase

        # Include title/body in data so onMessageReceived always fires
        # (data-only messages are always delivered to the app, not auto-displayed)
        fcm_data['title'] = title
        fcm_data['body'] = body

        for pt in tokens:
            try:
                message = messaging.Message(
                    data=fcm_data,
                    token=pt.token,
                    android=messaging.AndroidConfig(
                        priority='high' if priority == 'high' else 'normal',
                    ),
                )
                messaging.send(message)
                sent += 1
                details.append({'device': pt.device_id, 'status': 'ok'})
            except messaging.UnregisteredError:
                pt.is_active = False
                pt.save(update_fields=['is_active'])
                logger.info(f"Deactivated stale FCM token for device {pt.device_id}")
                failed += 1
                details.append({'device': pt.device_id, 'status': 'error', 'error': 'UnregisteredError'})
            except Exception as e:
                logger.error(f"FCM send error for device {pt.device_id}: {e}")
                failed += 1
                details.append({'device': pt.device_id, 'status': 'error', 'error': str(e)})

        return sent, failed, details


class InternalAgentIdentityView(APIView):
    """
    Internal API for managing agent user accounts (shizuha-id identity).
    Called by shizuha-agent during runtime sync — not exposed to end users.

    GET:  Look up an agent by username.
    POST: Create or reconnect an agent user account.
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        """Look up a single agent by ``username`` — OR, when no username is
        given (HIVE-179), return the agent INVENTORY: all ``account_type=agent``
        accounts with their owner, optionally filtered by ``owner_id``.

        Auth note (HIVE-179 / aoi architecture review): the inventory maps
        agents -> owning humans, which is more sensitive than a single lookup.
        Per the review it is gated identically to the other internal endpoints
        (AllowAny + network-secured) for v1; a service-token gate is a noted
        follow-on hardening. The ``alive`` filter is joined from the Pulse
        heartbeat by the CALLER (liveness is not stored in id).
        """
        username = request.query_params.get('username', '')
        if username:
            try:
                user = User.objects.select_related('profile').get(username=username)
            except User.DoesNotExist:
                return Response({'exists': False})

            profile = getattr(user, 'profile', None)
            return Response({
                'exists': True,
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'account_type': getattr(profile, 'account_type', 'human') if profile else 'human',
                'created_by_id': getattr(profile, 'created_by_id', None) if profile else None,
                'agent_runtime_id': getattr(profile, 'agent_runtime_id', None) if profile else None,
                'is_active': user.is_active,
            })

        # HIVE-179: runtime agent inventory — system-owned canary subjects are
        # non-human but are never fleet runtimes and must not be provisioned.
        profiles = (
            UserProfile.objects
            .filter(account_type='agent')
            .exclude(ownership_class='system_canary')
            .select_related('user', 'created_by')
            .order_by('user__username')
        )
        owner_id = request.query_params.get('owner_id')
        if owner_id:
            profiles = profiles.filter(created_by_id=owner_id)

        agents = [{
            'user_id': p.user_id,
            'username': p.user.username,
            'email': p.user.email,
            'display_name': (p.user.get_full_name() or p.user.username),
            'account_type': p.account_type,
            'created_by_id': p.created_by_id,
            'created_by_username': p.created_by.username if p.created_by_id else None,
            'agent_runtime_id': p.agent_runtime_id,
            'created_at': p.user.date_joined.isoformat() if p.user.date_joined else None,
            'is_active': p.user.is_active,
            # Runtime identity prefetch needs the same privilege bits used by
            # the canonical UserSerializer.  Keep them on the internal,
            # network-scoped inventory so the fleet controller never has to
            # borrow a human/staff JWT merely to hydrate agent identities.
            'is_staff': p.user.is_staff,
            'is_superuser': p.user.is_superuser,
        } for p in profiles]
        return Response({'agents': agents, 'count': len(agents)})

    def patch(self, request):
        """Claim or reassign an existing agent account owner.

        Internal-only endpoint used by Hive: ownership is derived from the
        authenticated Hive caller and passed as actor_user_id, never from an agent
        runtime token/body-controlled owner field. Non-staff callers may only claim
        orphan agents (created_by is null); staff callers may reassign/unclaim.
        """
        agent_user_id = request.data.get('agent_user_id')
        username = (request.data.get('username') or '').strip()
        actor_user_id = request.data.get('actor_user_id')
        actor_email = request.data.get('actor_email') or ''
        action = request.data.get('action') or 'claim'

        # HIVE-599: SSOT reconcile is a service action (no ownership actor needed).
        # Handled up-front so it doesn't require actor_user_id like claim/reassign.
        # Trust: same as the rest of /api/internal/ — the ingress guard 404s any
        # externally-forwarded request, so a call reaching this view without
        # ingress markers is a trusted in-cluster service (Hive). Staff actor or
        # service token also authorize. It ONLY sets account_type='agent' — never
        # touches ownership, credentials, or any privilege surface.
        if action == 'reconcile_account_type':
            from .internal_api_guard import request_via_ingress
            actor = User.objects.filter(id=actor_user_id).first() if actor_user_id else None
            is_staff_actor = bool(actor and (getattr(actor, 'is_staff', False) or getattr(actor, 'is_superuser', False)))
            trusted_internal = not request_via_ingress(request)
            if not (is_staff_actor or _check_service_token(request) or trusted_internal):
                return Response({'error': 'reconcile requires trusted internal caller, staff actor, or service token'}, status=403)
            rec_qs = User.objects.select_related('profile')
            try:
                if agent_user_id:
                    target = rec_qs.get(id=agent_user_id)
                elif username:
                    target = rec_qs.get(username=username)
                else:
                    return Response({'error': 'agent_user_id or username is required'}, status=400)
            except User.DoesNotExist:
                return Response({'error': 'Agent user not found'}, status=404)
            from .models import UserProfile
            prof = getattr(target, 'profile', None)
            if not prof:
                UserProfile.objects.create(user=target, account_type='agent')
                changed = True
            else:
                changed = getattr(prof, 'account_type', 'human') != 'agent'
                if changed:
                    prof.account_type = 'agent'
                    prof.save(update_fields=['account_type', 'updated_at'])
            logger.info('internal-agents: reconciled account_type=agent for %s (uid=%s, changed=%s)',
                        target.username, target.id, changed)
            return Response({'action': 'reconcile_account_type', 'user_id': target.id,
                             'username': target.username, 'account_type': 'agent', 'changed': changed})

        if not actor_user_id:
            return Response({'error': 'actor_user_id is required'}, status=400)
        try:
            actor = User.objects.get(id=actor_user_id)
        except User.DoesNotExist:
            return Response({'error': f'Actor user {actor_user_id} not found'}, status=404)
        # Security boundary: Hive tells ID which authenticated human is acting,
        # but ID must derive staff/operator authority from its own user record.
        # Never trust request-body `is_staff` (including truthy strings like
        # "false") for reassign/unclaim authorization.
        is_staff = bool(getattr(actor, 'is_staff', False) or getattr(actor, 'is_superuser', False))
        if not actor_email:
            actor_email = getattr(actor, 'email', '') or ''

        qs = User.objects.select_related('profile')
        try:
            if agent_user_id:
                agent = qs.get(id=agent_user_id)
            elif username:
                agent = qs.get(username=username)
            else:
                return Response({'error': 'agent_user_id or username is required'}, status=400)
        except User.DoesNotExist:
            return Response({'error': 'Agent user not found'}, status=404)

        profile = getattr(agent, 'profile', None)
        if not profile or getattr(profile, 'account_type', 'human') != 'agent':
            return Response({'error': 'Target user is not an agent account'}, status=400)

        if getattr(profile, 'ownership_class', '') == 'personal_default_member':
            return Response({
                'action': 'denied',
                'reason': 'system_locked_personal_default',
                'owner_id': profile.created_by_id,
            }, status=409)

        previous_owner_id = getattr(profile, 'created_by_id', None)
        from .audit import emit_agent_claim_event

        if action in ('unclaim', 'clear'):
            if not is_staff:
                emit_agent_claim_event(
                    agent_user_id=agent.id, agent_username=agent.username,
                    actor_user_id=actor.id, actor_email=actor_email,
                    outcome='denied_unclaim_nonstaff', previous_owner_id=previous_owner_id,
                )
                return Response({'error': 'Only staff can unclaim/reassign agents'}, status=403)
            profile.created_by = None
            profile.save(update_fields=['created_by', 'updated_at'])
            emit_agent_claim_event(
                agent_user_id=agent.id, agent_username=agent.username,
                actor_user_id=actor.id, actor_email=actor_email,
                outcome='unclaimed', previous_owner_id=previous_owner_id,
            )
            return Response({'action': 'unclaimed', 'user_id': agent.id, 'owner_id': None})

        if previous_owner_id and previous_owner_id != actor.id and not is_staff:
            emit_agent_claim_event(
                agent_user_id=agent.id, agent_username=agent.username,
                actor_user_id=actor.id, actor_email=actor_email,
                outcome='denied_owned_by_another', previous_owner_id=previous_owner_id,
            )
            return Response({
                'action': 'denied',
                'reason': 'owned_by_another_user',
                'owner_id': previous_owner_id,
            }, status=409)

        if previous_owner_id == actor.id:
            outcome = 'already_owned'
        else:
            profile.created_by = actor
            profile.save(update_fields=['created_by', 'updated_at'])
            outcome = 'reassigned' if previous_owner_id else 'claimed'

        emit_agent_claim_event(
            agent_user_id=agent.id, agent_username=agent.username,
            actor_user_id=actor.id, actor_email=actor_email,
            outcome=outcome, previous_owner_id=previous_owner_id,
        )
        return Response({
            'action': outcome,
            'user_id': agent.id,
            'username': agent.username,
            'email': agent.email,
            'owner_id': actor.id,
            'previous_owner_id': previous_owner_id,
        })

    def post(self, request):
        """
        Create or reconnect an agent user account.

        Required fields:
          - username: agent username (e.g. "kai")
          - email: agent email (e.g. "kai@shizuha.com")
          - created_by_id: user ID of the human who owns this agent
          - runtime_id: runtime that hosts this agent

        Returns:
          - action: "created" | "reconnected" | "denied"
          - user_id: the agent's shizuha-id user ID
        """
        username = request.data.get('username', '')
        email = request.data.get('email', '')
        created_by_id = request.data.get('created_by_id')
        runtime_id = request.data.get('runtime_id', '')
        display_name = request.data.get('display_name', '')

        if not username or not email or not created_by_id:
            return Response(
                {'error': 'username, email, and created_by_id are required'},
                status=400
            )

        # Verify the creating user exists
        try:
            creator = User.objects.get(id=created_by_id)
        except User.DoesNotExist:
            return Response({'error': f'Creator user {created_by_id} not found'}, status=404)

        # Check if username already exists
        existing_user = User.objects.select_related('profile').filter(
            username=username
        ).first()

        if existing_user:
            profile = getattr(existing_user, 'profile', None)
            account_type = getattr(profile, 'account_type', 'human') if profile else 'human'

            if account_type == 'human':
                return Response({
                    'action': 'denied',
                    'reason': 'username_taken_by_human',
                    'message': f'Username "{username}" belongs to a human account',
                    'user_id': existing_user.id,
                }, status=409)

            # Personal-default identities may reconnect only through the
            # dedicated owner-scoped fleet provision endpoint, which enforces
            # their canonical username/email/owner binding. This legacy
            # generic endpoint must not rewrite runtime or mutable identity
            # fields even when the caller supplies the current owner.
            if getattr(profile, 'ownership_class', '') == 'personal_default_member':
                return Response({
                    'action': 'denied',
                    'reason': 'system_locked_personal_default',
                    'user_id': existing_user.id,
                    'owner_id': profile.created_by_id,
                }, status=409)

            # It's an agent account — check ownership
            owner_id = getattr(profile, 'created_by_id', None) if profile else None
            if owner_id and owner_id != created_by_id:
                return Response({
                    'action': 'denied',
                    'reason': 'owned_by_another_user',
                    'message': f'Agent "{username}" is owned by user {owner_id}, not {created_by_id}',
                    'user_id': existing_user.id,
                    'owner_id': owner_id,
                }, status=409)

            # Same owner — reconnect
            if profile:
                profile.agent_runtime_id = runtime_id
                profile.save(update_fields=['agent_runtime_id', 'updated_at'])

            # Update email if changed
            if email and existing_user.email != email:
                if not User.objects.filter(email=email).exclude(id=existing_user.id).exists():
                    existing_user.email = email
                    existing_user.save(update_fields=['email'])

            return Response({
                'action': 'reconnected',
                'user_id': existing_user.id,
                'username': existing_user.username,
                'email': existing_user.email,
            })

        # Check if email already exists (different username)
        existing_email = User.objects.filter(email=email).first()
        if existing_email:
            return Response({
                'action': 'denied',
                'reason': 'email_taken',
                'message': f'Email "{email}" is already in use by user "{existing_email.username}"',
                'user_id': existing_email.id,
            }, status=409)

        # Create new agent user
        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=display_name or username,
            is_active=True,
        )
        user.set_unusable_password()
        user.save(update_fields=['password'])

        # Profile is auto-created by signal — update it for agent identity
        profile = user.profile
        profile.account_type = 'agent'
        profile.created_by = creator
        profile.agent_runtime_id = runtime_id
        profile.approval_status = 'approved'
        profile.lifecycle_state = 'active'
        profile.save(update_fields=[
            'account_type', 'created_by', 'agent_runtime_id',
            'approval_status', 'lifecycle_state', 'updated_at'
        ])

        return Response({
            'action': 'created',
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
        }, status=201)


class InternalAgentClaimView(APIView):
    """
    Internal API (HIVE-177 Phase 3): claim an agent account — set its owner
    (created_by) to a human user. Used by Hive's claim action so a real user
    can take ownership of an orphan/BYO agent and have it surface under them.
    Network-secured (internal only).

    POST { "username" | "email", "owner_id", "force"?:bool }
      - sets UserProfile.created_by = owner_id on the (account_type=agent) target.
      - by default only claims an UNOWNED agent (created_by is null); pass
        force=true to reassign an already-owned agent (staff/operator action).
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = (request.data.get('username') or '').strip()
        email = (request.data.get('email') or '').strip()
        owner_id = request.data.get('owner_id')
        force = bool(request.data.get('force'))
        if not owner_id or not (username or email):
            return Response({'error': 'owner_id and (username or email) are required'}, status=400)
        try:
            owner = User.objects.get(id=owner_id)
        except User.DoesNotExist:
            return Response({'error': f'owner {owner_id} not found'}, status=404)
        q = User.objects.select_related('profile')
        try:
            target = q.get(username=username) if username else q.get(email__iexact=email)
        except User.DoesNotExist:
            return Response({'error': 'agent not found'}, status=404)
        profile = getattr(target, 'profile', None)
        if not profile or getattr(profile, 'account_type', 'human') != 'agent':
            return Response({'error': 'target is not an agent account'}, status=409)
        # Personal-default identities are bound to their owner by the fleet
        # provisioner.  This legacy claim endpoint must not provide a second
        # mutation path around that system lock, even when ``force`` is set.
        if getattr(profile, 'ownership_class', '') == 'personal_default_member':
            return Response({
                'action': 'denied',
                'reason': 'system_locked_personal_default',
                'owner_id': profile.created_by_id,
            }, status=409)
        if profile.created_by_id and profile.created_by_id != int(owner_id) and not force:
            return Response({
                'error': 'already_owned',
                'message': f'agent owned by user {profile.created_by_id}; pass force=true to reassign',
                'owner_id': profile.created_by_id,
            }, status=409)
        profile.created_by = owner
        profile.save(update_fields=['created_by'])
        return Response({
            'claimed': True, 'agent': target.username, 'owner_id': owner.id, 'owner_username': owner.username,
        })


class InternalAgentListView(APIView):
    """
    Internal API: list agent user accounts (account_type=agent).

    Used by Hive to surface external/BYO agents grouped by their owner
    (created_by). Returns identity + ownership only; liveness is joined
    downstream from the Pulse heartbeat. Network-secured (internal only).

    GET params:
      - owner_id (optional): only agents whose created_by == this user id.
      - active (optional, "true"/"false"): filter by user.is_active.
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        qs = UserProfile.objects.select_related('user', 'created_by').filter(
            account_type='agent'
        )
        owner_id = request.query_params.get('owner_id')
        if owner_id:
            qs = qs.filter(created_by_id=owner_id)
        active = request.query_params.get('active')
        if active in ('true', 'false'):
            qs = qs.filter(user__is_active=(active == 'true'))

        agents = []
        for p in qs:
            u = p.user
            display_name = (
                getattr(p, 'display_name', '') or getattr(u, 'display_name', '')
                or (u.get_full_name() if hasattr(u, 'get_full_name') else '')
                or u.username
            )
            agents.append({
                'user_id': u.id,
                'username': u.username,
                'email': u.email,
                'display_name': display_name,
                'account_type': p.account_type,
                'created_by_id': p.created_by_id,
                'created_by_username': p.created_by.username if p.created_by_id else None,
                'agent_runtime_id': getattr(p, 'agent_runtime_id', None),
                'is_active': u.is_active,
                'created_at': u.date_joined.isoformat() if u.date_joined else None,
                'last_login': u.last_login.isoformat() if u.last_login else None,
            })
        return Response({'count': len(agents), 'agents': agents})


class InternalFleetProvisionAgentView(APIView):
    """
    Least-privilege HIVE fleet provisioner endpoint.

    This replaces HIVE's use of a broad shizuha-id admin credential for agent
    account provisioning. The caller must present the shared in-cluster fleet
    provisioner token and the endpoint only creates/reconnects accounts in the
    agents.shizuha.io namespace with account_type=agent.
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def _authorized(self, request):
        expected = getattr(settings, 'FLEET_PROVISIONER_TOKEN', '') or ''
        if not expected:
            return False, Response(
                {'error': 'Fleet provisioner token is not configured'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        supplied = request.headers.get('X-Fleet-Provisioner-Token', '')
        if not supplied or not constant_time_compare(supplied, expected):
            return False, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        return True, None

    def post(self, request):
        ok, response = self._authorized(request)
        if not ok:
            return response

        username = (request.data.get('username') or '').strip()
        email = (request.data.get('email') or '').strip().lower()
        password = request.data.get('password') or ''
        runtime_id = (request.data.get('runtime_id') or '').strip()
        display_name = (request.data.get('display_name') or username).strip()
        owner_user_id = request.data.get('owner_user_id')

        owner = None
        if owner_user_id not in (None, ''):
            try:
                owner_user_id = int(owner_user_id)
            except (TypeError, ValueError):
                return Response({'error': 'owner_user_id must be a positive integer subject'}, status=400)
            if owner_user_id <= 0:
                return Response({'error': 'owner_user_id must be a positive integer subject'}, status=400)
            owner = User.objects.select_related('profile').filter(id=owner_user_id).first()
            if not owner or getattr(getattr(owner, 'profile', None), 'account_type', 'human') != 'human':
                return Response({'error': f'Human owner {owner_user_id} not found'}, status=404)
            if username != f'shizuha-{owner_user_id}' or email != f'shizuha-{owner_user_id}@agents.shizuha.io':
                return Response({'error': 'Personal-default identity must use its canonical owner-derived username/email'}, status=400)

        if not username or not email or not password:
            return Response(
                {'error': 'username, email, and password are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(password) < 8:
            return Response({'error': 'Password must be at least 8 characters'}, status=status.HTTP_400_BAD_REQUEST)

        existing_user = User.objects.select_related('profile').filter(username__iexact=username).first()
        _existing_is_agent = bool(
            existing_user
            and getattr(getattr(existing_user, 'profile', None), 'account_type', 'human') == 'agent'
        )
        # Domain gate (SCLI-205 → PLAT-4220, operator 2026-07-11). The CANONICAL
        # agent email is @shizuha.com — we do NOT own shizuha.io, so new agents
        # must be creatable on @shizuha.com, not only reconnected.
        # The human-safety boundary (ren guardrail #5) is NOT the domain — it is
        # three domain-INDEPENDENT invariants, all still enforced below:
        #   1) `account_type='agent'` is force-set on every account this endpoint
        #      touches (create AND reconnect) — it never yields a human account;
        #   2) an existing HUMAN username is rejected (username_taken_by_human);
        #   3) an email already owned by anyone else is rejected (email_taken).
        # So a @shizuha.com email can never let the scoped provisioner create or
        # hijack a human account. We keep an agent-eligible domain allowlist only
        # as a sanity bound (@shizuha.com canonical, @agents.shizuha.io legacy).
        if not (email.endswith('@shizuha.com') or email.endswith('@agents.shizuha.io')):
            return Response(
                {'error': 'Fleet provisioner may only manage agent accounts on '
                          '@shizuha.com (canonical) or @agents.shizuha.io (legacy)'},
                status=status.HTTP_403_FORBIDDEN,
            )
        action = 'created'
        if existing_user:
            profile = getattr(existing_user, 'profile', None)
            if getattr(profile, 'account_type', 'human') != 'agent':
                return Response(
                    {
                        'action': 'denied',
                        'reason': 'username_taken_by_human',
                        'message': f'Username "{username}" belongs to a human account',
                        'user_id': existing_user.id,
                    },
                    status=status.HTTP_409_CONFLICT,
                )
            if getattr(profile, 'ownership_class', '') == 'personal_default_member':
                if owner is None or profile.created_by_id != owner.id:
                    return Response({
                        'action': 'denied',
                        'reason': 'system_locked_personal_default',
                        'user_id': existing_user.id,
                        'owner_id': profile.created_by_id,
                    }, status=status.HTTP_409_CONFLICT)
            elif owner is not None and profile.created_by_id not in (None, owner.id):
                return Response({
                    'action': 'denied',
                    'reason': 'owned_by_another_user',
                    'user_id': existing_user.id,
                    'owner_id': profile.created_by_id,
                }, status=status.HTTP_409_CONFLICT)
            user = existing_user
            action = 'reconnected'
            if email and user.email != email:
                if User.objects.filter(email__iexact=email).exclude(id=user.id).exists():
                    return Response(
                        {'action': 'denied', 'reason': 'email_taken', 'user_id': user.id},
                        status=status.HTTP_409_CONFLICT,
                    )
                user.email = email
        else:
            email_owner = User.objects.select_related('profile').filter(email__iexact=email).first()
            if email_owner:
                return Response(
                    {
                        'action': 'denied',
                        'reason': 'email_taken',
                        'message': f'Email "{email}" is already in use by user "{email_owner.username}"',
                        'user_id': email_owner.id,
                    },
                    status=status.HTTP_409_CONFLICT,
                )
            first_name, _, last_name = display_name.partition(' ')
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=first_name or username,
                last_name=last_name,
                is_active=True,
            )

        user.set_password(password)
        user.is_active = True
        user.save()
        revoke_all_user_tokens(user)

        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.account_type = 'agent'
        profile.agent_runtime_id = runtime_id
        if owner is not None:
            profile.created_by = owner
            profile.ownership_class = 'personal_default_member'
        profile.approval_status = 'approved'
        profile.lifecycle_state = 'active'
        profile.approved_at = timezone.now()
        profile.approval_note = 'Approved by scoped HIVE fleet provisioner endpoint'
        profile.save(update_fields=[
            'account_type', 'created_by', 'ownership_class', 'agent_runtime_id', 'approval_status', 'lifecycle_state',
            'approved_at', 'approval_note', 'updated_at',
        ])

        # HIVE-620/624: grant provisioned agents the core services they actually
        # use — above all `connect`, without which the agent's message_user calls
        # fail the service-access gate (the personal-agent "receives but never
        # replies" root cause). Union-only (never downgrades a custom grant);
        # tunable via FLEET_AGENT_DEFAULT_SERVICES.
        try:
            import os as _os
            from .models import Tool as _Tool
            _svc = _os.environ.get('FLEET_AGENT_DEFAULT_SERVICES',
                                   'id,hive,connect,pulse,wiki,mail,notes,drive,home')
            _slugs = [s.strip() for s in _svc.split(',') if s.strip()]
            _tools = list(_Tool.objects.filter(slug__in=_slugs, is_active=True))
            if _tools:
                profile.enabled_tools.add(*_tools)
        except Exception:
            logger.exception('fleet provision: default service grant failed for %s', username)

        logger.info('Fleet provisioner %s agent account %s (user_id=%s)', action, username, user.id)
        return Response({
            'action': action,
            'user_id': user.id,
            # HIVE-620 authority binding: Hive persists both immutable user
            # subjects and their exact ID profile rows.  Mutable usernames,
            # emails, and a later username->profile lookup are never authority.
            'profile_id': profile.id,
            'username': user.username,
            'email': user.email,
            'owner_user_id': profile.created_by_id,
            'owner_profile_id': (
                profile.created_by.profile.id if profile.created_by_id is not None else None
            ),
            'ownership_class': profile.ownership_class,
            'approval_status': profile.approval_status,
        }, status=status.HTTP_201_CREATED if action == 'created' else status.HTTP_200_OK)


class InternalStepUpVerifyView(APIView):
    """
    Server-to-server step-up token validation (HLD §5.3, HIVE-6).

    mTLS-internal only — never owner-facing. Called by a consuming service
    (hive-api, Books, Drive) presenting the token from the ``X-Step-Up-Token``
    header plus the expected scope tuple. On a valid token the jti is
    **atomically consumed** (single-use); subsequent verifies of the same token
    return ``valid:false, reason:"replayed"``.

    For irreversible actions the consumer forwards ``session_binding`` (the
    ``ath`` it computed from the owner's bearer token on the destructive
    request); verify compares it constant-time against the token's ``cnf.ath``
    (A7 (a)). The ``reason`` enum (expired | scope_mismatch | replayed | unknown
    | binding_mismatch) is for the caller's audit log, never surfaced verbatim.
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]  # secured by network (mTLS)

    def post(self, request):
        from .stepup import verify_step_up_token
        from .audit import emit_step_up_event

        token = request.data.get('token')
        expected_scope = request.data.get('expected_scope') or {}
        session_binding = request.data.get('session_binding') or ''

        if not token or not expected_scope:
            return Response(
                {'error': 'token and expected_scope are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = verify_step_up_token(token, expected_scope, session_binding)
        emit_step_up_event(
            'step_up_verify',
            owner_id=expected_scope.get('owner_id'),
            action=expected_scope.get('action', ''),
            resource_id=expected_scope.get('resource_id', ''),
            outcome='valid' if result.valid else result.reason,
        )
        body = {'valid': result.valid}
        if result.valid:
            body['scope'] = result.scope
        else:
            body['reason'] = result.reason
        return Response(body)


class InternalTestTenantDeprovisionView(APIView):
    """HIVE-444: scoped test-tenant deprovision for the QA/validation runtime.

    A NON-superuser deletion path, callable with a dedicated shared-secret
    service credential (X-Validation-Runtime-Token). Safety gate: refuses
    unless the target is PROVABLY a test tenant — email domain
    @shizuha-test.local OR the QA fixture signup domain (HIVE-423 moved the
    golden-path harness to QA_FIXTURE_SIGNUP_DOMAIN, HIVE-2697 ruling 2:
    saga-parked tenants must deprovision cleanly) AND non-staff/non-superuser
    AND a person account.
    Hard-deletes (test fixtures must not accumulate); the deprovision itself
    is recorded in the hash-chained AdminAuditEvent ledger, which survives
    the user-row cascade. Threat model: HIVE-444 task record (STRIDE-lite).
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    TEST_TENANT_DOMAIN = '@shizuha-test.local'

    def _test_tenant_domains(self):
        domains = [self.TEST_TENANT_DOMAIN]
        qa_domain = (getattr(settings, 'QA_FIXTURE_SIGNUP_DOMAIN', '') or '').strip().lower()
        if qa_domain:
            domains.append('@' + qa_domain)
        return tuple(domains)

    def _authorized(self, request):
        expected = getattr(settings, 'VALIDATION_RUNTIME_TOKEN', '') or ''
        if not expected:
            return False, Response(
                {'error': 'Validation runtime token is not configured'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        supplied = request.headers.get('X-Validation-Runtime-Token', '')
        if not supplied or not constant_time_compare(supplied, expected):
            return False, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        return True, None

    def delete(self, request, user_id):
        ok, response = self._authorized(request)
        if not ok:
            return response

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        email = (user.email or '').strip().lower()
        account_type = getattr(getattr(user, 'profile', None), 'account_type', '') or ''
        # The hard test-tenant predicate — refuse-by-default. Every condition
        # must hold; a real user can never satisfy the test domain, and even a
        # mis-created test account with elevated bits is refused.
        if (
            not email.endswith(self._test_tenant_domains())
            or user.is_staff
            or user.is_superuser
            or account_type == 'agent'
        ):
            logger.warning(
                'HIVE-444 deprovision REFUSED for user %s (%s): not a test tenant '
                '(domain=%s staff=%s superuser=%s account_type=%s)',
                user_id, email, email.endswith(self._test_tenant_domains()),
                user.is_staff, user.is_superuser, account_type,
            )
            return Response(
                {'error': 'Target is not a test tenant'},
                status=status.HTTP_403_FORBIDDEN,
            )

        from .models import AdminAuditEvent
        username = user.username
        from django.db import transaction as db_transaction
        with db_transaction.atomic():
            AdminAuditEvent.objects.append(
                action='test_tenant.deprovision',
                actor=None,
                target_type='user',
                target_id=user.id,
                target_repr=f'{username} <{email}>',
                before={'email': email, 'username': username},
                request_metadata={'service': 'validation-runtime', 'endpoint': 'internal-test-tenant-deprovision'},
            )
            revoke_all_user_tokens(user)
            user.delete()

        logger.info('HIVE-444 deprovisioned test tenant %s (%s)', username, email)
        return Response({'message': f'Test tenant "{username}" deprovisioned', 'id': user_id})


class InternalHumanDirectoryView(APIView):
    """Active human directory for Hive's default-agent backfill.

    Network-gated (ingress 404s /api/internal/*). Includes staff humans so
    Hive eligibility can skip them; excludes agents and non-active rows.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            limit = min(max(int(request.query_params.get('limit', 100)), 1), 200)
            offset = max(int(request.query_params.get('offset', 0)), 0)
        except (TypeError, ValueError):
            return Response({'error': 'limit and offset must be integers'},
                            status=status.HTTP_400_BAD_REQUEST)
        users = (
            _approved_active_directory_queryset()
            .exclude(profile__account_type='agent')
            .order_by('id')
        )
        total = users.count()
        page = list(users[offset:offset + limit])
        results = []
        for user in page:
            profile = getattr(user, 'profile', None)
            results.append({
                'id': user.id,
                'username': user.username,
                'email': user.email or '',
                'is_staff': bool(user.is_staff),
                'is_superuser': bool(user.is_superuser),
                'is_active': bool(user.is_active),
                'account_type': getattr(profile, 'account_type', 'human') or 'human',
            })
        return Response({
            'count': total,
            'limit': limit,
            'offset': offset,
            'results': results,
        })


urlpatterns = [
    # Internal endpoints (no auth, secured by network)
    path('humans/', InternalHumanDirectoryView.as_view(), name='internal-humans'),
    path('users/<int:user_id>/', InternalUserView.as_view(), name='internal-user'),
    path('users/', InternalUserListView.as_view(), name='internal-users'),
    path('users/by-email/', InternalUserByEmailView.as_view(), name='internal-user-by-email'),
    path('users/by-username/', InternalUserByUsernameView.as_view(), name='internal-user-by-username'),
    path('users/create/', InternalUserCreateView.as_view(), name='internal-user-create'),
    path('users/<int:user_id>/delete/', InternalUserDeleteView.as_view(), name='internal-user-delete'),
    # HIVE-444: scoped test-tenant teardown for the validation runtime
    path('test-tenants/<int:user_id>/deprovision/', InternalTestTenantDeprovisionView.as_view(), name='internal-test-tenant-deprovision'),

    # Agent identity (runtime sync)
    path('agents/', InternalAgentIdentityView.as_view(), name='internal-agents'),
    path('agents/list/', InternalAgentListView.as_view(), name='internal-agents-list'),
    path('agents/claim/', InternalAgentClaimView.as_view(), name='internal-agents-claim'),
    path('fleet/provision-agent/', InternalFleetProvisionAgentView.as_view(), name='internal-fleet-provision-agent'),

    # Push notifications
    path('push/send/', InternalPushSendView.as_view(), name='internal-push-send'),

    # Step-up token verification (HIVE-6 §5.3, mTLS-internal)
    path('step-up/verify/', InternalStepUpVerifyView.as_view(), name='internal-step-up-verify'),

    # Admin endpoints (require superuser authentication)
    path('admin/users/', AdminUserListView.as_view(), name='admin-user-list'),
    path('admin/users/create/', AdminUserCreateView.as_view(), name='admin-user-create'),
    path('admin/users/<int:user_id>/', AdminUserUpdateView.as_view(), name='admin-user-update'),
    path('admin/users/<int:user_id>/delete/', AdminUserDeleteView.as_view(), name='admin-user-delete'),
]
