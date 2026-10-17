"""
URL configuration for Shizuha ID (Identity Service).
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.db.models import Q
from django.utils import timezone
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)
from identity.oauth_views import AuthorizationServerMetadataView, JWKSView
from identity.oauth_urls import well_known_patterns as oauth_wk, oauth_api_patterns


from identity.views import id_metrics


def health_check(request):
    """Simple health check endpoint for container health checks."""
    return JsonResponse({'status': 'healthy'})


def _user_lifecycle_outbox_stats():
    """Return fail-loud stats for ID-39 lifecycle event delivery."""
    from identity.models import UserLifecycleEvent

    max_lag_seconds = int(getattr(settings, 'USER_LIFECYCLE_OUTBOX_MAX_LAG_SECONDS', 300))
    now = timezone.now()
    retryable = [
        UserLifecycleEvent.STATUS_PENDING,
        UserLifecycleEvent.STATUS_FAILED,
        UserLifecycleEvent.STATUS_PUBLISHING,
    ]
    pending_qs = UserLifecycleEvent.objects.filter(status__in=retryable)
    due_qs = pending_qs.filter(Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now))
    oldest = due_qs.order_by('created_at').values_list('created_at', flat=True).first()
    lag_seconds = int((now - oldest).total_seconds()) if oldest else 0
    failed = pending_qs.filter(status=UserLifecycleEvent.STATUS_FAILED).count()
    stale_publishing = pending_qs.filter(
        status=UserLifecycleEvent.STATUS_PUBLISHING,
        next_attempt_at__lt=now,
    ).count()
    ok = lag_seconds <= max_lag_seconds and stale_publishing == 0
    return {
        'status': 'healthy' if ok else 'degraded',
        'healthy': 1 if ok else 0,
        'invariant': 'no active grants/sessions/assignments reference a deactivated or deleted ID user',
        'owner_route': 'DevOps monitoring alert for user-lifecycle-outbox health',
        'pending_total': pending_qs.count(),
        'due_total': due_qs.count(),
        'failed_total': failed,
        'stale_publishing_total': stale_publishing,
        'oldest_lag_seconds': lag_seconds,
        'max_lag_seconds': max_lag_seconds,
    }


def user_lifecycle_outbox_health(request):
    """Fail-loud JSON health surface for ID-39 lifecycle event delivery."""
    stats = _user_lifecycle_outbox_stats()
    return JsonResponse(stats, status=200 if stats['healthy'] else 503)


def user_lifecycle_outbox_metrics(request):
    """Prometheus metrics for ID-39 lifecycle event delivery alerts."""
    stats = _user_lifecycle_outbox_stats()
    lines = [
        '# HELP shizuha_id_user_lifecycle_outbox_healthy ID-39 user lifecycle outbox health; 1 means within lag/staleness SLO.',
        '# TYPE shizuha_id_user_lifecycle_outbox_healthy gauge',
        f"shizuha_id_user_lifecycle_outbox_healthy {stats['healthy']}",
        '# HELP shizuha_id_user_lifecycle_outbox_pending_total Pending/failed/publishing lifecycle events awaiting successful delivery.',
        '# TYPE shizuha_id_user_lifecycle_outbox_pending_total gauge',
        f"shizuha_id_user_lifecycle_outbox_pending_total {stats['pending_total']}",
        '# HELP shizuha_id_user_lifecycle_outbox_due_total Lifecycle events due for dispatch now.',
        '# TYPE shizuha_id_user_lifecycle_outbox_due_total gauge',
        f"shizuha_id_user_lifecycle_outbox_due_total {stats['due_total']}",
        '# HELP shizuha_id_user_lifecycle_outbox_failed_total Lifecycle events currently in failed retry state.',
        '# TYPE shizuha_id_user_lifecycle_outbox_failed_total gauge',
        f"shizuha_id_user_lifecycle_outbox_failed_total {stats['failed_total']}",
        '# HELP shizuha_id_user_lifecycle_outbox_stale_publishing_total Events stuck in publishing after their retry deadline.',
        '# TYPE shizuha_id_user_lifecycle_outbox_stale_publishing_total gauge',
        f"shizuha_id_user_lifecycle_outbox_stale_publishing_total {stats['stale_publishing_total']}",
        '# HELP shizuha_id_user_lifecycle_outbox_oldest_lag_seconds Age in seconds of the oldest due lifecycle event.',
        '# TYPE shizuha_id_user_lifecycle_outbox_oldest_lag_seconds gauge',
        f"shizuha_id_user_lifecycle_outbox_oldest_lag_seconds {stats['oldest_lag_seconds']}",
        '# HELP shizuha_id_user_lifecycle_outbox_max_lag_seconds Configured max lifecycle outbox lag seconds before alerting.',
        '# TYPE shizuha_id_user_lifecycle_outbox_max_lag_seconds gauge',
        f"shizuha_id_user_lifecycle_outbox_max_lag_seconds {stats['max_lag_seconds']}",
        '',
    ]
    from django.http import HttpResponse

    return HttpResponse('\n'.join(lines), content_type='text/plain; version=0.0.4')

urlpatterns = [
    # Prefixed URLs for nginx proxy
    path('shizuha-id/admin/', admin.site.urls),
    path('shizuha-id/api/auth/', include('identity.urls')),
    path('shizuha-id/api/internal/', include('identity.internal_urls')),
    # OAuth 2.0 authorization server (prefixed)
    path('shizuha-id/.well-known/oauth-authorization-server',
         AuthorizationServerMetadataView.as_view(),
         name='oauth-metadata-prefixed'),
    path('shizuha-id/.well-known/openid-configuration',
         AuthorizationServerMetadataView.as_view(),
         name='openid-configuration-prefixed'),
    path('shizuha-id/.well-known/jwks.json', JWKSView.as_view(), name='oauth-jwks-prefixed'),
    path('shizuha-id/api/oauth/', include((oauth_api_patterns, 'oauth'))),

    # OpenAPI documentation (prefixed)
    path('shizuha-id/api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('shizuha-id/api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('shizuha-id/api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    path('shizuha-id/api/health/user-lifecycle-outbox/', user_lifecycle_outbox_health, name='user-lifecycle-outbox-health-prefixed'),
    path('shizuha-id/api/metrics/user-lifecycle-outbox/', user_lifecycle_outbox_metrics, name='user-lifecycle-outbox-metrics-prefixed'),

    # Non-prefixed URLs for direct access
    path('admin/', admin.site.urls),
    path('api/auth/', include('identity.urls')),
    path('api/internal/', include('identity.internal_urls')),
    path('api/health/', health_check, name='health-check'),
    path('api/health/user-lifecycle-outbox/', user_lifecycle_outbox_health, name='user-lifecycle-outbox-health'),
    path('api/metrics/user-lifecycle-outbox/', user_lifecycle_outbox_metrics, name='user-lifecycle-outbox-metrics'),
    path('api/metrics/', id_metrics, name='id-metrics'),
    # OAuth 2.0 authorization server (non-prefixed)
    *oauth_wk,
    path('api/oauth/', include((oauth_api_patterns, 'oauth-direct'))),

    # OpenAPI documentation (non-prefixed)
    path('api/schema/', SpectacularAPIView.as_view(), name='schema-direct'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema-direct'), name='swagger-ui-direct'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema-direct'), name='redoc-direct'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
