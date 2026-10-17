"""
URL configuration for Shizuha ID identity app.
"""
from django.urls import path
from rest_framework.routers import DefaultRouter

from .storm_views import StormAwareTokenRefreshView
from .views import (
    TokenRefreshView,
    MultiClassTokenVerifyView,
    LoginView, Login2FAView, LogoutView, RegisterView, SignupConfigView, ServiceTokenView, ApiTokenView,
    UserView, ProfileView, PasswordChangeView,
    GoogleLoginView, GitHubLoginView, OAuthStatusView,
    GoogleCallbackView, SocialHandoffView,
    ToolListView, ToolToggleView,
    ToolCallViewSet, ToolResponseViewSet,
    PasswordResetRequestView, PasswordResetValidateView, PasswordResetConfirmView,
    AllUsersView,
    # Service access control
    ServiceListView, ServiceAccessRequestCreateView, ServiceAccessRequestListView,
    AdminServiceListView, AdminServiceUpdateView,
    AdminUserServicesView, AdminAccessRequestListView, AdminAccessRequestReviewView,
    # Push notifications
    RegisterPushTokenView,
    # Account approval
    PendingUsersView, PendingUsersCountView, UserApprovalView, UserReactivateView,
    # Admin password management
    AdminSetPasswordView,
)
from .admin_audit_views import (
    AdminAuditEventListView, AdminAuditEventDetailView, AdminAuditVerifyView,
)
from .billing_views import BillingAccountView, UpgradeInterestView
from .stepup_views import (
    StepUpBeginView, StepUpAnswerView,
    StepUpEnrollBeginView, StepUpEnrollConfirmView, StepUpRecoverView,
    StepUpWebAuthnRegisterBeginView, StepUpWebAuthnRegisterCompleteView,
    RecoveryCodeRegenerateView,
)

router = DefaultRouter()
router.register('tool-calls', ToolCallViewSet, basename='tool-calls')
router.register('tool-responses', ToolResponseViewSet, basename='tool-responses')

urlpatterns = [
    # Authentication
    path('login/', LoginView.as_view(), name='login'),
    path('login/2fa/', Login2FAView.as_view(), name='login-2fa'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
    path('signup-config/', SignupConfigView.as_view(), name='signup-config'),
    path('refresh/', StormAwareTokenRefreshView.as_view(), name='token-refresh'),
    # PLAT-166 / ADR-PLAT-002 §5.2 contract (signature+expiry verify, 200 =
    # valid / 401 = invalid), migrated to the service's token classes per
    # PLAT-7641: the stock view decoded every token with the global HS256
    # backend and false-rejected the RS256 tokens (PLAT-255/PLAT-1179) that
    # the authentication path accepts. Verify-ONLY (no issuance change).
    path('verify/', MultiClassTokenVerifyView.as_view(), name='token-verify'),
    path('service-token/', ServiceTokenView.as_view(), name='service-token'),
    path('api-token/', ApiTokenView.as_view(), name='api-token'),

    # User management
    path('user/', UserView.as_view(), name='user'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('billing/account/', BillingAccountView.as_view(), name='billing-account'),
    path('billing/upgrade-interest/', UpgradeInterestView.as_view(), name='billing-upgrade-interest'),
    path('password/change/', PasswordChangeView.as_view(), name='password-change'),

    # Password reset
    path('password/reset/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password/reset/validate/', PasswordResetValidateView.as_view(), name='password-reset-validate'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    # OAuth
    path('social/google/', GoogleLoginView.as_view(), name='google-login'),
    path('social/callback/', GoogleCallbackView.as_view(), name='social-google-callback'),
    path('social/handoff/', SocialHandoffView.as_view(), name='social-handoff'),
    path('social/github/', GitHubLoginView.as_view(), name='github-login'),
    path('oauth/status/', OAuthStatusView.as_view(), name='oauth-status'),

    # Tools (legacy)
    path('tools/', ToolListView.as_view(), name='tools'),
    path('tools/toggle/', ToolToggleView.as_view(), name='tool-toggle'),

    # Services — user-facing
    path('services/', ServiceListView.as_view(), name='service-list'),
    path('services/toggle/', ToolToggleView.as_view(), name='service-toggle'),
    path('services/request/', ServiceAccessRequestCreateView.as_view(), name='service-request'),
    path('services/requests/', ServiceAccessRequestListView.as_view(), name='service-requests'),

    # Services — admin (staff-only)
    path('admin/services/', AdminServiceListView.as_view(), name='admin-service-list'),
    path('admin/services/<slug:slug>/', AdminServiceUpdateView.as_view(), name='admin-service-update'),
    path('admin/users/<int:user_id>/services/', AdminUserServicesView.as_view(), name='admin-user-services'),
    path('admin/requests/', AdminAccessRequestListView.as_view(), name='admin-request-list'),
    path('admin/requests/<int:pk>/', AdminAccessRequestReviewView.as_view(), name='admin-request-review'),

    # Admin password management (superuser-only)
    path('admin/users/<int:user_id>/set-password/', AdminSetPasswordView.as_view(), name='admin-set-password'),

    # Admin audit ledger — read/verify (staff or superuser) — ID-37 / HLD ID-5 §4.5
    path('admin/audit/events/', AdminAuditEventListView.as_view(), name='admin-audit-events'),
    path('admin/audit/events/<int:seq>/', AdminAuditEventDetailView.as_view(), name='admin-audit-event-detail'),
    path('admin/audit/verify/', AdminAuditVerifyView.as_view(), name='admin-audit-verify'),

    # Account approval (staff-only)
    path('admin/users/pending/', PendingUsersView.as_view(), name='admin-pending-users'),
    path('admin/users/pending/count/', PendingUsersCountView.as_view(), name='admin-pending-users-count'),
    path('admin/users/<int:user_id>/approve/', UserApprovalView.as_view(), name='admin-user-approve'),
    path('admin/users/<int:user_id>/reactivate/', UserReactivateView.as_view(), name='admin-user-reactivate'),

    # Step-up re-authentication (HIVE-6 — owner-facing; verify is internal)
    path('step-up/begin/', StepUpBeginView.as_view(), name='step-up-begin'),
    path('step-up/answer/', StepUpAnswerView.as_view(), name='step-up-answer'),
    path('step-up/enroll/begin/', StepUpEnrollBeginView.as_view(), name='step-up-enroll-begin'),
    path('step-up/enroll/confirm/', StepUpEnrollConfirmView.as_view(), name='step-up-enroll-confirm'),
    path('step-up/webauthn/register/begin/', StepUpWebAuthnRegisterBeginView.as_view(), name='step-up-webauthn-register-begin'),
    path('step-up/webauthn/register/complete/', StepUpWebAuthnRegisterCompleteView.as_view(), name='step-up-webauthn-register-complete'),
    path('step-up/recovery-codes/regenerate/', RecoveryCodeRegenerateView.as_view(), name='step-up-recovery-codes-regenerate'),
    path('step-up/recover/', StepUpRecoverView.as_view(), name='step-up-recover'),

    # Push notifications
    path('push-token/', RegisterPushTokenView.as_view(), name='push-token'),

    # Admin (staff only)
    path('users/all/', AllUsersView.as_view(), name='all-users'),
] + router.urls
