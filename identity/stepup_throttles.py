"""
DRF throttles for the step-up endpoints (HLD §7 rate-limit posture).

No generic per-endpoint throttling exists in shizuha-id today, so these are
purpose-built. ``begin`` is throttled per ``(owner, action)`` to bound challenge
spam; ``answer`` brute-force is bounded by the per-challenge lock-after-N in the
view (not a throttle). ``verify`` is mTLS-internal and not owner-facing.
"""
import hashlib

from rest_framework.throttling import SimpleRateThrottle


class StepUpBeginThrottle(SimpleRateThrottle):
    """Throttle step-up challenge issuance per ``(owner_id, action)`` (§7).

    Default 5 challenges / 5 min; override via DRF ``DEFAULT_THROTTLE_RATES``
    under the ``step_up_begin`` scope.
    """
    scope = 'step_up_begin'

    def get_cache_key(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return None  # unauthenticated begin is rejected upstream anyway
        action = (request.data or {}).get('action', '')
        return self.cache_format % {
            'scope': self.scope,
            'ident': f'{request.user.pk}:{action}',
        }


class StepUpEnrollThrottle(SimpleRateThrottle):
    """Throttle enrollment-confirmation sends per owner (§7 / §4.1)."""
    scope = 'step_up_enroll'

    def get_cache_key(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return None
        return self.cache_format % {
            'scope': self.scope,
            'ident': str(request.user.pk),
        }


class StepUpEnrollConfirmThrottle(SimpleRateThrottle):
    """Defense-in-depth IP+token throttle for public enrollment confirmation."""
    scope = 'step_up_enroll_confirm'

    def get_cache_key(self, request, view):
        token = ((request.data or {}).get('token') or '').strip()
        if not token:
            return None
        digest = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
        return self.cache_format % {
            'scope': self.scope,
            'ident': f'{self.get_ident(request)}:{digest}',
        }


class Login2FAThrottle(SimpleRateThrottle):
    """Throttle login-time second-factor attempts per client IP."""
    scope = 'login_2fa'

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return self.cache_format % {'scope': self.scope, 'ident': ident}
