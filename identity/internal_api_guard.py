"""Internal-API ingress guard (PLAT incident 2026-07-06, follow-up to ID-52).

The `/api/internal/` endpoints are service-to-service APIs meant to be
reachable ONLY on the cluster network (consumers call
`http://shizuha-id.shizuha.svc:8001` directly). They were however also
publicly mounted through the `shizuha-id-backend` ingress
(`/shizuha-id/(api|admin|static)...` matches `api/internal/...`), which is
what ID-52's PII field scoping was (correctly) defending against — but that
scoping also stripped `email` from trusted in-cluster consumers and broke
Pulse task assignment platform-wide (Pulse identity is federated by email).

This middleware closes the actual hole: any request to an internal path that
arrived THROUGH the ingress is rejected with 404. Detection: the nginx
ingress always appends `X-Forwarded-For` / `X-Real-IP` to proxied requests
and an external client cannot make it omit them, while direct in-cluster
Service calls carry neither. An in-cluster caller that spoofs the header
simply locks itself out — fail closed.

With ingress-borne traffic blocked here, `_scoped_user_serializer` can trust
non-forwarded requests with the full serializer again (see internal_urls.py).
"""

from django.http import JsonResponse

# Match both mounts: /api/internal/... and /shizuha-id/api/internal/...
_INTERNAL_MARKER = '/api/internal/'


def request_via_ingress(request) -> bool:
    """True when the request was proxied by the public ingress."""
    meta = request.META
    return bool(meta.get('HTTP_X_FORWARDED_FOR') or meta.get('HTTP_X_REAL_IP'))


class InternalApiIngressGuardMiddleware:
    """404 any ingress-borne request to the internal service-to-service API."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if _INTERNAL_MARKER in request.path and request_via_ingress(request):
            # 404 (not 403) — don't advertise that the path exists publicly.
            return JsonResponse({'error': 'Not found'}, status=404)
        return self.get_response(request)
