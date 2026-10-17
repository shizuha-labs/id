"""URL configuration for OAuth 2.0 authorization server endpoints."""
from django.urls import path

from .oauth_views import (
    AuthorizationServerMetadataView,
    AuthorizedAppsView,
    AuthorizeApproveView,
    AuthorizeInfoView,
    ClientRegistrationView,
    DeviceRegistryView,
    JWKSView,
    OAuthRevocationStatusView,
    RevokeView,
    TokenView,
    UserinfoView,
)


# Mounted at the service root so /.well-known is reachable without a prefix.
well_known_patterns = [
    path('.well-known/oauth-authorization-server',
         AuthorizationServerMetadataView.as_view(),
         name='oauth-metadata'),
    path('.well-known/openid-configuration',
         AuthorizationServerMetadataView.as_view(),
         name='openid-configuration'),
    path('.well-known/jwks.json', JWKSView.as_view(), name='oauth-jwks'),
]

oauth_api_patterns = [
    path('register', ClientRegistrationView.as_view(), name='oauth-register'),
    path('authorize/info', AuthorizeInfoView.as_view(), name='oauth-authorize-info'),
    path('authorize/approve', AuthorizeApproveView.as_view(), name='oauth-authorize-approve'),
    path('token', TokenView.as_view(), name='oauth-token'),
    path('revocation-status', OAuthRevocationStatusView.as_view(), name='oauth-revocation-status'),
    path('revoke', RevokeView.as_view(), name='oauth-revoke'),
    path('userinfo', UserinfoView.as_view(), name='oauth-userinfo'),
    path('authorized-apps', AuthorizedAppsView.as_view(), name='oauth-authorized-apps'),
    path('authorized-apps/<str:client_id>', AuthorizedAppsView.as_view(), name='oauth-authorized-apps-detail'),
    path('devices', DeviceRegistryView.as_view(), name='oauth-devices'),
]
