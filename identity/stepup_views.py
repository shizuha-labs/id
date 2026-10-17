"""
Owner-facing step-up endpoints (HIVE-6 / HLD page 7197343e, v1.0).

  POST /v1/owner/step-up/begin    -> issue a challenge (never a token)   §5.1
  POST /v1/owner/step-up/answer   -> submit factor, mint one-shot token  §5.2

Plus the §4.1 enrollment trust-bootstrap lifecycle:

  POST /v1/owner/step-up/enroll/begin    -> provision a provisional TOTP secret
  POST /v1/owner/step-up/enroll/confirm   -> consume the email-OOB link, activate
  POST /v1/owner/step-up/enroll/recover   -> lost-factor recovery (gated)

The server-to-server ``/step-up/verify`` lives in ``internal_urls`` (mTLS-internal).
The wire contract is frozen by the HLD; these views are the producer impl.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from . import stepup
from .audit import emit_step_up_event
from .models import TOTPDevice, StepUpChallenge, StepUpEnrollmentToken, UserProfile, RecoveryCode
from .services import (
    EmailServiceError,
    send_step_up_enrollment_email,
    send_step_up_notification_email,
)
from .stepup_throttles import StepUpBeginThrottle, StepUpEnrollConfirmThrottle, StepUpEnrollThrottle

logger = logging.getLogger(__name__)

# Answer window for an issued challenge (short; the action-scoped TTL the *minted
# token* carries is separate, from the §2/§4.2 policy).
CHALLENGE_ANSWER_WINDOW_S = 120
# Lock a challenge after this many wrong answers (§7).
MAX_ANSWER_ATTEMPTS = 5
# Existing-factor proof scope for HLD §4.1b re-enrollment. Owners can mint this
# via the normal begin -> answer step-up flow with action=factor-reenroll and
# resource_id=step-up-enrollment; the enrollment endpoint then consumes it.
REENROLL_ACTION = 'factor-reenroll'
REENROLL_RESOURCE_ID = 'step-up-enrollment'


def _client_ip(request):
    ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
    return ip or request.META.get('REMOTE_ADDR')


def _bearer_access_token(request) -> str:
    """Extract the raw bearer access token for the A7 (a) ath binding."""
    header = request.META.get('HTTP_AUTHORIZATION', '')
    if header.startswith('Bearer '):
        return header[len('Bearer '):].strip()
    return ''


def _confirmed_factor_device(user, factor=None):
    queryset = TOTPDevice.objects.filter(user=user, confirmed=True)
    if factor:
        queryset = queryset.filter(device_type=factor)
    return queryset.order_by('-created_at').first()


def _confirmed_factor_devices(user):
    return list(TOTPDevice.objects.filter(user=user, confirmed=True).order_by('-created_at'))


def _strongest_confirmed_device(user):
    devices = _confirmed_factor_devices(user)
    devices.sort(
        key=lambda device: stepup.FACTOR_STRENGTH.get(device.device_type, 0),
        reverse=True,
    )
    return devices[0] if devices else None


def _confirmed_totp_device(user):
    return _confirmed_factor_device(user, TOTPDevice.DEVICE_TOTP)


def _confirmed_webauthn_devices(user):
    return list(
        TOTPDevice.objects.filter(
            user=user, device_type=TOTPDevice.DEVICE_WEBAUTHN, confirmed=True,
        ).order_by('-created_at')
    )


def _min_factor_for_reenroll(user, action, resource_id):
    if action != REENROLL_ACTION or resource_id != REENROLL_RESOURCE_ID:
        return ''
    device = _strongest_confirmed_device(user)
    return device.device_type if device is not None else ''


def _preferred_confirmed_device_for_action(user, action):
    devices = list(TOTPDevice.objects.filter(user=user, confirmed=True).order_by('-created_at'))
    devices.sort(
        key=lambda device: stepup.FACTOR_STRENGTH.get(device.device_type, 0),
        reverse=True,
    )
    for device in devices:
        if stepup.factor_meets_floor(device.device_type, action):
            return device
    return None


def _verify_existing_factor_for_enrollment(request, existing_device):
    """Validate HLD §4.1b existing-factor proof for any enrolled factor type."""
    if existing_device is None:
        return True

    # Backward-compatible fast path for TOTP owners. This remains fail-closed for
    # WebAuthn-only owners because they cannot present a TOTP code.
    if existing_device.device_type == TOTPDevice.DEVICE_TOTP:
        current_code = request.data.get('current_code') or ''
        if current_code and stepup.get_factor('totp').verify(
            device=existing_device, answer=current_code, challenge=_PseudoChallenge(request.user),
        ):
            return True

    # Factor-invariant path: the owner proves the current strongest factor via
    # the frozen begin -> answer contract, then spends that one-shot token here.
    # The token must carry a satisfied-factor claim at least as strong as the
    # current strongest confirmed device; a mixed WebAuthn+TOTP owner cannot
    # mint the factor-reenroll token with TOTP and then retire WebAuthn.
    token = (
        request.data.get('current_step_up_token')
        or request.data.get('step_up_token')
        or ''
    )
    if not token:
        return False
    expected_scope = {
        'owner_id': request.user.pk,
        'resource_id': REENROLL_RESOURCE_ID,
        'action': REENROLL_ACTION,
    }
    proof = stepup.verify_step_up_token(
        token, expected_scope, min_factor=existing_device.device_type,
    )
    return proof.valid


def _enroll_confirm_attempt_key(token: StepUpEnrollmentToken) -> str:
    return f'stepup:enroll-confirm:failures:{token.pk}:{token.device_id}'


def _enroll_confirm_max_attempts() -> int:
    return int(getattr(settings, 'STEP_UP_ENROLL_CONFIRM_MAX_ATTEMPTS', 5))


def _enroll_confirm_ttl_seconds(token: StepUpEnrollmentToken) -> int:
    return max(1, int((token.expires_at - timezone.now()).total_seconds()))


def _enroll_confirm_locked(token: StepUpEnrollmentToken) -> bool:
    return int(cache.get(_enroll_confirm_attempt_key(token)) or 0) >= _enroll_confirm_max_attempts()


def _record_enroll_confirm_failure(token: StepUpEnrollmentToken) -> int:
    key = _enroll_confirm_attempt_key(token)
    try:
        failures = cache.incr(key)
    except ValueError:
        cache.set(key, 1, _enroll_confirm_ttl_seconds(token))
        failures = 1
    return int(failures)


def _clear_enroll_confirm_failures(token: StepUpEnrollmentToken) -> None:
    cache.delete(_enroll_confirm_attempt_key(token))


def _webauthn_registration_ttl_s():
    return int(getattr(settings, 'WEBAUTHN_REGISTRATION_CHALLENGE_TTL_S', 120))


def _webauthn_registration_max_attempts():
    return int(getattr(settings, 'WEBAUTHN_REGISTRATION_MAX_ATTEMPTS', 5))


def _parse_state_time(value):
    parsed = parse_datetime(value) if value else None
    if parsed is not None and timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _clear_webauthn_registration(device):
    device.webauthn_state = {}
    device.save(update_fields=['webauthn_state', 'updated_at'])


def _webauthn_registration_expired(state):
    expires_at = _parse_state_time(state.get('expires_at'))
    return expires_at is None or timezone.now() > expires_at


class StepUpBeginView(APIView):
    """§5.1 — initiate a challenge. Requires a live authenticated session."""
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [StepUpBeginThrottle]

    def post(self, request):
        action = (request.data.get('action') or '').strip()
        resource_id = (request.data.get('resource_id') or '').strip()
        requested_factor = (request.data.get('factor') or '').strip()

        if not action or not resource_id:
            return Response(
                {'error': 'action and resource_id are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not stepup.is_known_action(action):
            return Response({'error': 'unknown action'}, status=status.HTTP_400_BAD_REQUEST)

        reenroll_min_factor = _min_factor_for_reenroll(request.user, action, resource_id)

        if requested_factor:
            factor = requested_factor
            if factor not in stepup.FACTOR_STRENGTH:
                return Response({'error': 'unknown factor'}, status=status.HTTP_400_BAD_REQUEST)
            # Enforce the §4.2 floor early (also re-checked at mint).
            if not stepup.factor_meets_floor(factor, action):
                return Response({'error': 'factor_below_floor'}, status=status.HTTP_403_FORBIDDEN)
            if reenroll_min_factor and (
                stepup.FACTOR_STRENGTH.get(factor, 0)
                < stepup.FACTOR_STRENGTH.get(reenroll_min_factor, 0)
            ):
                return Response({'error': 'factor_below_floor'}, status=status.HTTP_403_FORBIDDEN)
            device = _confirmed_factor_device(request.user, factor)
        else:
            device = _preferred_confirmed_device_for_action(request.user, action)
            factor = device.device_type if device is not None else stepup.action_min_factor(action)

        # Fail-closed: an owner with no confirmed factor at the required/requested
        # strength cannot begin a destructive step-up.
        if device is None:
            emit_step_up_event(
                'step_up_challenge', owner_id=request.user.pk, action=action,
                resource_id=resource_id, outcome='factor_not_enrolled',
            )
            return Response(
                {'error': 'factor_not_enrolled'},
                status=status.HTTP_409_CONFLICT,
            )

        webauthn_options = None
        webauthn_state = {}
        if factor == TOTPDevice.DEVICE_WEBAUTHN:
            try:
                webauthn_options, webauthn_state = stepup.webauthn_authentication_begin(device)
            except ValueError:
                return Response({'error': 'factor_not_enrolled'}, status=status.HTTP_409_CONFLICT)

        ttl_s = stepup.action_ttl_s(action)
        challenge = StepUpChallenge.objects.create(
            challenge_id=StepUpChallenge.new_id(),
            user=request.user,
            device=device,
            action=action,
            resource_id=resource_id,
            factor=factor,
            session_ath=stepup.access_token_ath(_bearer_access_token(request)),
            webauthn_state=webauthn_state,
            expires_at=timezone.now() + timedelta(seconds=CHALLENGE_ANSWER_WINDOW_S),
        )
        emit_step_up_event(
            'step_up_challenge', owner_id=request.user.pk, action=action,
            resource_id=resource_id, outcome='issued',
        )
        response = {
            'challenge_id': challenge.challenge_id,
            'factor': factor,
            'expires_at': challenge.expires_at.isoformat(),
            'ttl_on_success_s': ttl_s,
        }
        if webauthn_options is not None:
            response['public_key'] = webauthn_options['publicKey']
        return Response(response)


class StepUpAnswerView(APIView):
    """§5.2 — submit the factor answer; on success mint the one-shot token."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        challenge_id = (request.data.get('challenge_id') or '').strip()
        answer = request.data.get('code') or request.data.get('assertion')

        if not challenge_id:
            return Response({'error': 'challenge_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            challenge = StepUpChallenge.objects.select_related('device', 'user').get(
                challenge_id=challenge_id, user=request.user,
            )
        except StepUpChallenge.DoesNotExist:
            return Response({'error': 'unknown challenge'}, status=status.HTTP_400_BAD_REQUEST)

        if challenge.is_expired:
            return Response({'error': 'challenge expired'}, status=status.HTTP_410_GONE)
        if not challenge.is_open:
            return Response({'error': 'challenge locked or already answered'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)

        # §4.2 floor (re-checked at mint time, not just begin).
        if not stepup.factor_meets_floor(challenge.factor, challenge.action):
            return Response({'error': 'factor_below_floor'}, status=status.HTTP_403_FORBIDDEN)
        if not stepup.prod_gate_ok(challenge.factor, challenge.action):
            # password backend on a destructive action in prod -> fail closed.
            return Response({'error': 'factor_below_floor'}, status=status.HTTP_403_FORBIDDEN)

        factor = stepup.get_factor(challenge.factor)
        ok = factor.verify(device=challenge.device, answer=answer, challenge=challenge)
        if not ok:
            challenge.attempts += 1
            if challenge.attempts >= MAX_ANSWER_ATTEMPTS:
                challenge.locked = True
                emit_step_up_event(
                    'step_up_lock', owner_id=request.user.pk, action=challenge.action,
                    resource_id=challenge.resource_id, outcome='locked',
                )
            challenge.save(update_fields=['attempts', 'locked'])
            emit_step_up_event(
                'step_up_answer', owner_id=request.user.pk, action=challenge.action,
                resource_id=challenge.resource_id, outcome='rejected',
            )
            code = status.HTTP_429_TOO_MANY_REQUESTS if challenge.locked else status.HTTP_403_FORBIDDEN
            return Response({'error': 'invalid factor answer'}, status=code)

        # Mint the one-shot step-up token (RS256). Bind to the begin-time session.
        ttl_s = stepup.action_ttl_s(challenge.action)
        scope = stepup.StepUpScope(
            owner_id=request.user.pk,
            resource_id=challenge.resource_id,
            action=challenge.action,
        )
        token, _jti, exp_epoch = stepup.mint_step_up_token(
            scope, ttl_s=ttl_s, session_ath=challenge.session_ath,
            factor=challenge.factor,
        )

        challenge.answered_at = timezone.now()
        if challenge.device:
            challenge.device.last_used_at = timezone.now()
            challenge.device.save(update_fields=['last_used_at', 'updated_at'])
        challenge.save(update_fields=['answered_at'])

        emit_step_up_event(
            'step_up_answer', owner_id=request.user.pk, action=challenge.action,
            resource_id=challenge.resource_id, outcome='minted',
        )
        return Response({
            'step_up_token': token,
            'expires_at': timezone.datetime.fromtimestamp(
                exp_epoch, tz=timezone.get_current_timezone()
            ).isoformat(),
            'scope': scope.as_dict(),
        })


class StepUpEnrollBeginView(APIView):
    """§4.1(a/b) — provision a provisional TOTP secret and send the email-OOB link.

    First-enroll (no existing confirmed factor) AND-gates: live session +
    password re-entry + (the email link, confirmed in the next step). Re-enroll
    (any confirmed factor already exists) is **asymmetric**: it additionally
    requires proof of the existing factor, fail-closed — the email link alone
    must never add/overwrite a factor.
    """
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [StepUpEnrollThrottle]

    def post(self, request):
        password = request.data.get('password') or ''
        if not request.user.check_password(password):
            return Response({'error': 'password re-entry required'},
                            status=status.HTTP_403_FORBIDDEN)

        existing = _strongest_confirmed_device(request.user)
        if existing is None:
            purpose = StepUpEnrollmentToken.PURPOSE_FIRST_ENROLL
        else:
            # Asymmetric re-enroll: require the EXISTING factor (§4.1b). This is
            # factor-type aware so a WebAuthn-only owner is never treated as a
            # first-enroll that can add a weaker TOTP device with email alone.
            if not _verify_existing_factor_for_enrollment(request, existing):
                return Response(
                    {'error': 'existing factor required to re-enroll'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            purpose = StepUpEnrollmentToken.PURPOSE_REENROLL

        import pyotp
        secret = pyotp.random_base32()
        device = TOTPDevice.objects.create(
            user=request.user,
            device_type=TOTPDevice.DEVICE_TOTP,
            name=request.data.get('name', ''),
            secret=secret,
            confirmed=False,  # provisional until the email link is consumed
        )
        token = StepUpEnrollmentToken.create_for_device(
            device, purpose=purpose, ip_address=_client_ip(request),
        )
        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://erp.shizuha.com/id')
        enroll_url = f"{frontend_url}/step-up/enroll/confirm?token={token.token}"
        try:
            send_step_up_enrollment_email(request.user, enroll_url, purpose=purpose)
        except EmailServiceError:
            logger.error("step-up enrollment email failed for %s", request.user.pk)

        emit_step_up_event(
            'step_up_reenroll' if purpose == StepUpEnrollmentToken.PURPOSE_REENROLL
            else 'step_up_enroll',
            owner_id=request.user.pk, outcome='provisional_created', detail=purpose,
        )
        # Provisioning URI lets the client render the QR; secret only returned
        # on this authenticated provisioning call, never logged.
        otpauth = pyotp.TOTP(secret).provisioning_uri(
            name=request.user.email, issuer_name='Shizuha',
        )
        return Response({
            'device_id': device.id,
            'otpauth_uri': otpauth,
            'confirmation_required': True,
        }, status=status.HTTP_201_CREATED)


class StepUpEnrollConfirmView(APIView):
    """§4.1 — consume the single-use email-OOB link and activate the device.

    On re-enroll/recover, any *other* confirmed device is retired so the new one
    is authoritative, and an OOB "your 2FA changed" notification fires.
    """
    permission_classes = [permissions.AllowAny]  # the token is the credential
    throttle_classes = [StepUpEnrollConfirmThrottle]

    def post(self, request):
        token_value = (request.data.get('token') or '').strip()
        if not token_value:
            return Response({'error': 'token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = StepUpEnrollmentToken.objects.select_related('device', 'user').get(
                token=token_value,
            )
        except StepUpEnrollmentToken.DoesNotExist:
            return Response({'error': 'invalid token'}, status=status.HTTP_400_BAD_REQUEST)

        if not token.is_valid:
            return Response({'error': 'token expired or already used'},
                            status=status.HTTP_400_BAD_REQUEST)
        if _enroll_confirm_locked(token):
            return Response({'error': 'enrollment confirmation locked'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        device = token.device
        if device.device_type == TOTPDevice.DEVICE_TOTP:
            code = (request.data.get('code') or request.data.get('answer') or '').strip()
            if not code:
                failures = _record_enroll_confirm_failure(token)
                code_status = status.HTTP_429_TOO_MANY_REQUESTS if failures >= _enroll_confirm_max_attempts() else status.HTTP_400_BAD_REQUEST
                return Response({'error': 'totp code is required'}, status=code_status)
            if not stepup.verify_provisional_totp_device(device=device, answer=code):
                failures = _record_enroll_confirm_failure(token)
                code_status = status.HTTP_429_TOO_MANY_REQUESTS if failures >= _enroll_confirm_max_attempts() else status.HTTP_403_FORBIDDEN
                return Response({'error': 'invalid totp code'}, status=code_status)

        # Retire other confirmed devices on re-enroll/recover (new one wins).
        if token.purpose in (
            StepUpEnrollmentToken.PURPOSE_REENROLL,
            StepUpEnrollmentToken.PURPOSE_RECOVER,
        ):
            TOTPDevice.objects.filter(
                user=token.user, confirmed=True,
            ).exclude(pk=device.pk).update(confirmed=False)

        device.mark_confirmed()
        token.mark_used()
        _clear_enroll_confirm_failures(token)
        profile, _ = UserProfile.objects.get_or_create(user=token.user)
        if profile.twofa_enrolled_at is None:
            profile.twofa_enrolled_at = timezone.now()
            profile.save(update_fields=['twofa_enrolled_at', 'updated_at'])
        recovery_codes = RecoveryCode.regenerate_for_user(
            token.user, count=getattr(settings, 'TWOFA_RECOVERY_CODE_COUNT', 10)
        )

        notify_event = {
            StepUpEnrollmentToken.PURPOSE_FIRST_ENROLL: 'first_enroll',
            StepUpEnrollmentToken.PURPOSE_REENROLL: 'reenroll',
            StepUpEnrollmentToken.PURPOSE_RECOVER: 'reset',
        }.get(token.purpose, 'first_enroll')
        try:
            send_step_up_notification_email(token.user, event=notify_event)
        except EmailServiceError:
            logger.error("step-up notification email failed for %s", token.user.pk)

        emit_step_up_event(
            'step_up_enroll', owner_id=token.user.pk, outcome='confirmed',
            detail=token.purpose,
        )
        return Response({'confirmed': True, 'recovery_codes': recovery_codes})


class StepUpWebAuthnRegisterBeginView(APIView):
    """Begin WebAuthn/passkey registration (HIVE-20).

    This is an enrollment ceremony, not a change to the frozen step-up
    begin/answer/verify contract. It creates a provisional WebAuthn device; the
    complete step verifies attestation and then reuses the existing email-OOB
    confirmation token before the device becomes confirmed.
    """
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [StepUpEnrollThrottle]

    def post(self, request):
        password = request.data.get('password') or ''
        if not request.user.check_password(password):
            return Response({'error': 'password re-entry required'},
                            status=status.HTTP_403_FORBIDDEN)

        existing = _strongest_confirmed_device(request.user)
        existing_webauthn = _confirmed_webauthn_devices(request.user)
        purpose = StepUpEnrollmentToken.PURPOSE_FIRST_ENROLL
        if existing is not None:
            if not _verify_existing_factor_for_enrollment(request, existing):
                return Response(
                    {'error': 'existing factor required to register WebAuthn'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            purpose = StepUpEnrollmentToken.PURPOSE_REENROLL

        options, state = stepup.webauthn_registration_begin(
            request.user, existing_devices=existing_webauthn,
        )
        device = TOTPDevice.objects.create(
            user=request.user,
            device_type=TOTPDevice.DEVICE_WEBAUTHN,
            name=request.data.get('name', 'passkey'),
            secret='',
            confirmed=False,
            webauthn_state={
                **state,
                'purpose': purpose,
                'ip_address': _client_ip(request),
                'expires_at': (timezone.now() + timedelta(seconds=_webauthn_registration_ttl_s())).isoformat(),
                'attempts': 0,
            },
        )
        emit_step_up_event(
            'step_up_webauthn_register', owner_id=request.user.pk,
            outcome='challenge_issued', detail=purpose,
        )
        return Response({
            'device_id': device.id,
            'public_key': options['publicKey'],
            'confirmation_required': True,
        }, status=status.HTTP_201_CREATED)


class StepUpWebAuthnRegisterCompleteView(APIView):
    """Complete WebAuthn registration, then issue the email-OOB confirm leg."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        device_id = request.data.get('device_id')
        response = request.data.get('response') or request.data.get('attestation')
        if not device_id or not response:
            return Response(
                {'error': 'device_id and response are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            device = TOTPDevice.objects.get(
                id=device_id, user=request.user,
                device_type=TOTPDevice.DEVICE_WEBAUTHN, confirmed=False,
            )
        except TOTPDevice.DoesNotExist:
            return Response({'error': 'registration not found'}, status=status.HTTP_404_NOT_FOUND)
        if not device.webauthn_state:
            return Response({'error': 'registration challenge expired'}, status=status.HTTP_410_GONE)

        original_state = dict(device.webauthn_state)
        if _webauthn_registration_expired(original_state):
            _clear_webauthn_registration(device)
            return Response({'error': 'registration challenge expired'}, status=status.HTTP_410_GONE)
        attempts = int(original_state.get('attempts') or 0)
        if attempts >= _webauthn_registration_max_attempts():
            _clear_webauthn_registration(device)
            return Response({'error': 'registration challenge locked'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        state = dict(original_state)
        purpose = state.pop('purpose', StepUpEnrollmentToken.PURPOSE_FIRST_ENROLL)
        ip_address = state.pop('ip_address', _client_ip(request))
        state.pop('expires_at', None)
        state.pop('attempts', None)
        device.webauthn_state = state
        try:
            stepup.webauthn_registration_complete(device, response)
        except Exception as exc:  # noqa: BLE001 — surface a safe ceremony failure
            logger.exception('WebAuthn registration failed for %s', request.user.pk)
            retry_state = dict(original_state)
            retry_state['attempts'] = attempts + 1
            if retry_state['attempts'] >= _webauthn_registration_max_attempts():
                _clear_webauthn_registration(device)
                return Response(
                    {'error': 'webauthn registration failed', 'detail': str(exc)},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            device.webauthn_state = retry_state
            device.save(update_fields=['webauthn_state', 'updated_at'])
            return Response(
                {'error': 'webauthn registration failed', 'detail': str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token = StepUpEnrollmentToken.create_for_device(
            device, purpose=purpose, ip_address=ip_address,
        )
        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://erp.shizuha.com/id')
        enroll_url = f"{frontend_url}/step-up/enroll/confirm?token={token.token}"
        try:
            send_step_up_enrollment_email(request.user, enroll_url, purpose=purpose)
        except EmailServiceError:
            logger.error('step-up WebAuthn enrollment email failed for %s', request.user.pk)

        emit_step_up_event(
            'step_up_webauthn_register', owner_id=request.user.pk,
            outcome='attestation_verified', detail=purpose,
        )
        return Response({'confirmed': False, 'confirmation_required': True})


class RecoveryCodeRegenerateView(APIView):
    """Regenerate single-use recovery codes after password re-entry."""
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [StepUpEnrollThrottle]

    def post(self, request):
        password = request.data.get('password') or ''
        if not request.user.check_password(password):
            return Response({'error': 'password re-entry required'}, status=status.HTTP_403_FORBIDDEN)
        existing = _strongest_confirmed_device(request.user)
        if existing is None:
            return Response({'error': 'confirmed factor required'}, status=status.HTTP_403_FORBIDDEN)
        if not _verify_existing_factor_for_enrollment(request, existing):
            return Response({'error': 'current confirmed factor required'}, status=status.HTTP_403_FORBIDDEN)
        codes = RecoveryCode.regenerate_for_user(
            request.user, count=getattr(settings, 'TWOFA_RECOVERY_CODE_COUNT', 10)
        )
        emit_step_up_event('step_up_recovery_codes', owner_id=request.user.pk, outcome='regenerated')
        return Response({'recovery_codes': codes, 'shown_once': True})


class StepUpRecoverView(APIView):
    """§4.1(c) — lost-factor recovery. NOT a silent email-only reset.

    Requires email-OOB **+ a cooldown** **+** an OOB "2FA was reset" notification,
    and is operator-assisted for high-value owners. The cooldown and the
    high-value-owner threshold are config-driven (§4.2 registry), not hardcoded.
    """
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [StepUpEnrollThrottle]

    def post(self, request):
        user = request.user

        # Operator-assist gate for high-value owners (config-driven threshold).
        high_value_ids = set(getattr(settings, 'STEP_UP_HIGH_VALUE_OWNER_IDS', []))
        if user.pk in high_value_ids:
            emit_step_up_event(
                'step_up_recover', owner_id=user.pk, outcome='operator_assist_required',
            )
            return Response(
                {'error': 'operator_assist_required',
                 'detail': 'High-value account recovery requires operator assistance.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Cooldown: bound how often recovery can be (re)initiated (config-driven).
        cooldown_h = int(getattr(settings, 'STEP_UP_RECOVERY_COOLDOWN_HOURS', 24))
        recent_cutoff = timezone.now() - timedelta(hours=cooldown_h)
        recent = StepUpEnrollmentToken.objects.filter(
            user=user,
            purpose=StepUpEnrollmentToken.PURPOSE_RECOVER,
            created_at__gte=recent_cutoff,
        ).exists()
        if recent:
            emit_step_up_event('step_up_recover', owner_id=user.pk, outcome='cooldown_active')
            return Response({'error': 'recovery_cooldown_active'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)

        import pyotp
        secret = pyotp.random_base32()
        device = TOTPDevice.objects.create(
            user=user, device_type=TOTPDevice.DEVICE_TOTP,
            name=request.data.get('name', 'recovered'), secret=secret, confirmed=False,
        )
        token = StepUpEnrollmentToken.create_for_device(
            device, purpose=StepUpEnrollmentToken.PURPOSE_RECOVER,
            ip_address=_client_ip(request),
        )
        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://erp.shizuha.com/id')
        enroll_url = f"{frontend_url}/step-up/enroll/confirm?token={token.token}"
        try:
            send_step_up_enrollment_email(user, enroll_url, purpose='recover')
        except EmailServiceError:
            logger.error("step-up recovery email failed for %s", user.pk)

        emit_step_up_event('step_up_recover', owner_id=user.pk, outcome='recovery_initiated')
        otpauth = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name='Shizuha')
        return Response({
            'device_id': device.id,
            'otpauth_uri': otpauth,
            'confirmation_required': True,
        }, status=status.HTTP_201_CREATED)


class _PseudoChallenge:
    """Minimal duck-typed challenge for factor.verify() during enrollment, where
    no StepUpChallenge row exists yet (re-enroll current-factor check)."""
    def __init__(self, user):
        self.user = user
