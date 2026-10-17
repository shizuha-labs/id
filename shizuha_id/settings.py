"""
Django settings for Shizuha ID (Identity Service).

This service handles authentication, user profiles, and OAuth across
all Shizuha platform applications.
"""

import os
from pathlib import Path
from datetime import timedelta
from urllib.parse import urlparse

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
# This key is shared across all Shizuha services for JWT validation
def _required_env(name):
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise RuntimeError(f'{name} must be configured with a nonblank value')
    return value


SECRET_KEY = (_required_env('JWT_SECRET_KEY') if 'JWT_SECRET_KEY' in os.environ
              else _required_env('SECRET_KEY'))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1,0.0.0.0,shizuha-id,shizuha-pulse,shizuha-admin,*').split(',')

APPEND_SLASH = False
FORCE_SCRIPT_NAME = os.environ.get('FORCE_SCRIPT_NAME', '/shizuha-id')

USE_X_FORWARDED_HOST = True
USE_X_FORWARDED_PORT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',

    # Third-party
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'drf_spectacular',
    'django_celery_beat',

    # Allauth for OAuth
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.github',

    # dj-rest-auth
    'dj_rest_auth',
    'dj_rest_auth.registration',

    # Local apps
    'identity.apps.IdentityConfig',
]

SITE_ID = 1

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    # PLAT-1331 Part B: per-tenant request quota (availability isolation).
    # Inert unless TENANT_RATE_LIMIT_ENABLED; fail-open on Redis error.
    'identity.tenant_rate_limit.TenantRateLimitMiddleware',
    # 2026-07-06 incident: /api/internal/ is service-to-service ONLY — 404 any
    # request that arrived through the public ingress (see internal_api_guard).
    'identity.internal_api_guard.InternalApiIngressGuardMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

ROOT_URLCONF = 'shizuha_id.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'shizuha_id.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB', 'shizuha_id'),
        'USER': os.environ.get('POSTGRES_USER', 'postgres'),
        'PASSWORD': _required_env('POSTGRES_PASSWORD'),
        'HOST': os.environ.get('POSTGRES_HOST', 'localhost'),
        'PORT': os.environ.get('POSTGRES_PORT', '5432'),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = 'shizuha-id/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Celery Configuration
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/2')
CONNECT_SECURITY_EVENT_METRICS_REDIS_URL = os.environ.get(
    'CONNECT_SECURITY_EVENT_METRICS_REDIS_URL', CELERY_BROKER_URL,
)
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')

# Shared cache for cross-replica short-lived state (Django's implicit default is
# per-process LocMemCache, so with >1 replica an OAuth `state` set on the pod
# that built the authorize URL was invisible to the pod handling the callback →
# "invalid or expired state"). Keep the default LocMemCache behaviour for
# everything else; add ONE Redis-backed alias for the OAuth state/handoff.
# Django 4+ ships a native RedisCache (uses the `redis` package; no django-redis).
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    },
    'oauth_shared': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.environ.get('OAUTH_STATE_REDIS_URL', CELERY_BROKER_URL),
        'KEY_PREFIX': 'idoauth',
    },
}

# Canonical OAuth/OIDC issuer. Without this, _issuer_url() derives the issuer
# from the REQUEST host, so in-cluster fetches, hairpinned server-side token
# exchanges, and browser flows can each see a different issuer — Forgejo's
# shizuha-id login source failed exactly there ("issuer in token does not
# match issuer in OpenIDConfig discovery", ORIG-18 2026-07-15). The env is
# already set on the deployment; the canonical default prevents local/test or
# newly provisioned instances from silently minting issuer-less platform JWTs.
OAUTH_ISSUER_URL = (
    os.environ.get('OAUTH_ISSUER_URL') or 'https://shizuha.com/id'
).rstrip('/')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Asia/Kolkata'
CELERY_ENABLE_UTC = True
CELERY_TASK_DEFAULT_QUEUE = 'shizuha_id'
CELERY_TASK_DEFAULT_EXCHANGE = 'shizuha_id'
CELERY_TASK_DEFAULT_ROUTING_KEY = 'shizuha_id'

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_AUTHENTICATION_CLASSES': [
        # PLAT-672 / ren security review: RS256OAuthBearerAuthentication is NOT the
        # global default. It accepts THIRD-PARTY OAuth access tokens (aud=client_id,
        # scope='openid profile', aud/iss verification disabled) and is intentionally
        # scoped to OAuth-scope-aware endpoints (UserinfoView). Making it the platform
        # default would let an OAuth token minted for one client/scope be replayed
        # against unrelated shizuha-id APIs as the user (audience confusion). Verifying
        # FIRST-PARTY platform tokens via RS256 platform-wide requires an audience/scope
        # binding layer first — tracked in PLAT-675/the Phase-1 cutover design.
        'identity.authentication.OAuthClientRevocationJWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    # Step-up rate-limit posture (HIVE-6 §7). Scopes are consumed by the
    # purpose-built throttles in identity/stepup_throttles.py.
    'DEFAULT_THROTTLE_RATES': {
        'step_up_begin': '5/min',
        'step_up_enroll': '5/hour',
        'step_up_enroll_confirm': '20/hour',
        'login_2fa': '10/min',
        'login_password': '20/min',
    },
}

FRONTEND_URL = os.environ.get('SHIZUHA_ID_FRONTEND_URL', 'https://erp.shizuha.com/id')

# Step-up re-authentication (HIVE-6 / HLD page 7197343e). All operator data is
# config-driven (§4.2): action TTL + min-factor floor, the dev/CI-only password
# backend gate, and the §4.1c recovery cooldown / high-value-owner threshold.
STEP_UP_ACTION_POLICY = {
    'hard-delete': {'ttl_s': 60, 'min_factor': 'totp'},   # irreversible -> cnf-bound
    'export': {'ttl_s': 300, 'min_factor': 'totp'},
    'rename': {'ttl_s': 60, 'min_factor': 'totp'},
    'dashboard': {'ttl_s': 300, 'min_factor': 'totp'},
    # Existing-factor proof for adding/replacing factors (§4.1b). Kept as a
    # normal step-up action so WebAuthn-only owners can prove their current
    # phishing-resistant factor before enrolling another factor.
    'factor-reenroll': {'ttl_s': 120, 'min_factor': 'totp'},
}
# Fail-closed: the password second factor may satisfy a destructive action only
# in DEBUG/CI, never in a prod deployment (unless explicitly force-enabled).
STEP_UP_ALLOW_PASSWORD_BACKEND = os.environ.get(
    'STEP_UP_ALLOW_PASSWORD_BACKEND', 'False'
).lower() == 'true'
# §4.1c lost-factor recovery tunables (config, not hardcoded).
STEP_UP_RECOVERY_COOLDOWN_HOURS = int(os.environ.get('STEP_UP_RECOVERY_COOLDOWN_HOURS', '24'))
STEP_UP_HIGH_VALUE_OWNER_IDS = [
    int(x) for x in os.environ.get('STEP_UP_HIGH_VALUE_OWNER_IDS', '').split(',') if x.strip()
]


# Login-time MFA rollout (PLAT-493 / SEC-2). Default off for staged rollout.
TWOFA_LOGIN_ENFORCEMENT = os.environ.get('TWOFA_LOGIN_ENFORCEMENT', 'off').lower()
TWOFA_LOGIN_PENDING_TTL_SECONDS = int(os.environ.get('TWOFA_LOGIN_PENDING_TTL_SECONDS', '300'))
TWOFA_LOGIN_MAX_ATTEMPTS = int(os.environ.get('TWOFA_LOGIN_MAX_ATTEMPTS', '5'))
STEP_UP_ENROLL_CONFIRM_MAX_ATTEMPTS = int(os.environ.get('STEP_UP_ENROLL_CONFIRM_MAX_ATTEMPTS', '5'))
TWOFA_RECOVERY_CODE_COUNT = int(os.environ.get('TWOFA_RECOVERY_CODE_COUNT', '10'))
TWOFA_RECOVERY_CODE_LOW_WATERMARK = int(os.environ.get('TWOFA_RECOVERY_CODE_LOW_WATERMARK', '2'))
LOGIN_PASSWORD_MAX_ATTEMPTS = int(os.environ.get('LOGIN_PASSWORD_MAX_ATTEMPTS', '5'))
LOGIN_PASSWORD_WINDOW_SECONDS = int(os.environ.get('LOGIN_PASSWORD_WINDOW_SECONDS', '900'))
LOGIN_PASSWORD_BASE_LOCKOUT_SECONDS = int(os.environ.get('LOGIN_PASSWORD_BASE_LOCKOUT_SECONDS', '60'))
LOGIN_PASSWORD_MAX_LOCKOUT_SECONDS = int(os.environ.get('LOGIN_PASSWORD_MAX_LOCKOUT_SECONDS', '900'))
LOGIN_PASSWORD_IP_EXEMPT_CIDRS = os.environ.get('LOGIN_PASSWORD_IP_EXEMPT_CIDRS', '')
LOGIN_PASSWORD_TRUSTED_PROXY_CIDRS = os.environ.get('LOGIN_PASSWORD_TRUSTED_PROXY_CIDRS', '')

PASSWORD_RESET_MAX_ATTEMPTS = int(os.environ.get('PASSWORD_RESET_MAX_ATTEMPTS', '5'))
PASSWORD_RESET_WINDOW_SECONDS = int(os.environ.get('PASSWORD_RESET_WINDOW_SECONDS', '900'))
PASSWORD_RESET_BASE_LOCKOUT_SECONDS = int(os.environ.get('PASSWORD_RESET_BASE_LOCKOUT_SECONDS', '60'))
PASSWORD_RESET_MAX_LOCKOUT_SECONDS = int(os.environ.get('PASSWORD_RESET_MAX_LOCKOUT_SECONDS', '900'))
PASSWORD_RESET_MIN_RESPONSE_SECONDS = float(os.environ.get('PASSWORD_RESET_MIN_RESPONSE_SECONDS', '0.25'))

# WebAuthn/passkey RP settings (HIVE-20). Allowed origins and RP ID default to
# the browser origin / host derived from FRONTEND_URL. Explicit env overrides
# remain available for multi-origin dev/test deployments.
_frontend_parts = urlparse(FRONTEND_URL)
_frontend_origin = (
    f'{_frontend_parts.scheme}://{_frontend_parts.netloc}'
    if _frontend_parts.scheme and _frontend_parts.netloc else ''
)
_frontend_host = _frontend_parts.hostname or 'localhost'
WEBAUTHN_RP_ID = os.environ.get('WEBAUTHN_RP_ID', _frontend_host)
WEBAUTHN_RP_NAME = os.environ.get('WEBAUTHN_RP_NAME', 'Shizuha ID')
WEBAUTHN_ALLOWED_ORIGINS = [
    x.strip() for x in os.environ.get('WEBAUTHN_ALLOWED_ORIGINS', _frontend_origin).split(',')
    if x.strip()
]
WEBAUTHN_REGISTRATION_CHALLENGE_TTL_S = int(os.environ.get('WEBAUTHN_REGISTRATION_CHALLENGE_TTL_S', '120'))

# DRV-21: allow external users to self-register for Drive without manual approval.
# Off by default; enable by setting ALLOW_DRIVE_SELFREGISTRATION=true in env.
# When enabled, POST /api/auth/register/ with intent=drive auto-approves the user
# and grants {id, drive} services only (least-privilege, no fleet/admin surfaces).
ALLOW_DRIVE_SELFREGISTRATION = os.environ.get('ALLOW_DRIVE_SELFREGISTRATION', 'False').lower() == 'true'

# Public signup without the admin-approval queue. Leave OFF until Turnstile +
# signup rate limits have been live-verified. Password register stays pending
# until this is true.
ALLOW_OPEN_REGISTRATION = os.environ.get('ALLOW_OPEN_REGISTRATION', 'False').lower() == 'true'

# Cloudflare Turnstile. Secret empty => captcha not required (tests/dev).
# Production must set TURNSTILE_SECRET so siteverify is fail-closed.
TURNSTILE_SITE_KEY = os.environ.get('TURNSTILE_SITE_KEY', '').strip()
TURNSTILE_SECRET = os.environ.get('TURNSTILE_SECRET', '').strip()
_turnstile_required = os.environ.get('TURNSTILE_REQUIRED', '').strip().lower()
TURNSTILE_REQUIRED = (
    None if _turnstile_required == ''
    else _turnstile_required in ('1', 'true', 'yes', 'on')
)

# Signup flood budgets (per rolling window). Apply even while approval is on.
# Default off so DEBUG/CI suites that mint many 127.0.0.1 users stay green.
# Production chart sets SIGNUP_RATE_LIMITS_ENABLED=true.
SIGNUP_RATE_LIMITS_ENABLED = os.environ.get('SIGNUP_RATE_LIMITS_ENABLED', 'False').lower() in (
    '1', 'true', 'yes', 'on',
)
SIGNUP_WINDOW_SECONDS = int(os.environ.get('SIGNUP_WINDOW_SECONDS', '3600'))
SIGNUP_IP_MAX_PER_WINDOW = int(os.environ.get('SIGNUP_IP_MAX_PER_WINDOW', '5'))
SIGNUP_SUBNET_MAX_PER_WINDOW = int(os.environ.get('SIGNUP_SUBNET_MAX_PER_WINDOW', '20'))
SIGNUP_DOMAIN_MAX_PER_WINDOW = int(os.environ.get('SIGNUP_DOMAIN_MAX_PER_WINDOW', '8'))

# Dedicated QA e2e principal-class allowlist (ID-85/ID-86; ren's PLAT-1247
# sign-off, condition C1). The ONLY principals for which the class-scoped
# ``qa_e2e_session_mint`` audit signal is emitted on interactive login. The
# principal itself is provisioned out-of-band by DevOps (ID-87) with
# standard-user entitlements only; its credential material lives exclusively
# in the QA credential broker. Comma-separated env override for future QA
# principals; empty disables the signal entirely (never gates the login).
QA_E2E_PRINCIPALS = tuple(
    p.strip().lower()
    for p in os.environ.get('ID_QA_E2E_PRINCIPALS', 'qa-e2e').split(',')
    if p.strip()
)

# QA fixture signup bypass (HIVE-1987): emails whose domain matches this value
# skip the Turnstile captcha (honeypot + rate limits still apply) and are
# auto-approved/active on registration. This gives non-staff QA seats a
# fresh blank-slate test user each cycle without operator/staff approval.
# Empty (default) => disabled; public signups keep full captcha gating.
QA_FIXTURE_SIGNUP_DOMAIN = os.environ.get('QA_FIXTURE_SIGNUP_DOMAIN', '').strip().lower()

WEBAUTHN_REGISTRATION_MAX_ATTEMPTS = int(os.environ.get('WEBAUTHN_REGISTRATION_MAX_ATTEMPTS', '5'))

# CTX-492/CTX-497 v3: bounded allowlist of OAuth public-client ids whose RS256
# SSO access tokens may authenticate the UserView (/id/api/auth/user/) read
# bridge (GET/HEAD only). Comma-separated env; empty => the RS256 read bridge is
# effectively off (fail-closed). Populate with the Cortex SSO public client id at
# rollout. Migration: once issuance stamps aud='shizuha-userinfo' (or scope
# 'profile:read'), swap the allowlist for that aud/scope check and clear this.
RS256_USERINFO_ALLOWED_CLIENT_IDS = tuple(
    c.strip() for c in os.environ.get('RS256_USERINFO_ALLOWED_CLIENT_IDS', '').split(',') if c.strip()
)

# PLAT-5343 slice 1 — v2 membership-projection cutover (HLD v12 §4.1, §4.4 step 3).
# The acyclic Admin v2 composition path activates only when the flag is set AND
# the dedicated assertion material is provisioned (deploy secrets, never code):
#   SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION   'true' once Admin v2 is live (selection point)
#   SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY     ID's DEDICATED internal-signing key (EdDSA PEM);
#                                         never the user-token SIGNING_KEY above
#   SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL   ID's credential bound to principal 'shizuha-id'
#                                         on Admin's v2 route
# A selected v2 without its material fails the mint closed (v2_emission_unavailable);
# there is no runtime fallback from a selected v2 to the circular v1 path.
SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION = os.environ.get('SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION', '')
SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY = os.environ.get('SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY', '')
SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL = os.environ.get('SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL', '')

# JWT Settings - Shared across all Shizuha services
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=24),  # Extended from 1hr for better UX across federated apps
    'REFRESH_TOKEN_LIFETIME': timedelta(days=30),  # Extended from 7 days
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    # PLAT-8714 failure mode B: tokens minted on a manage-Job pod's node clock
    # were rejected (401) by ID pods on other nodes when inter-node drift put
    # `iat` a few seconds in the future (SimpleJWT default leeway is 0).
    # 30s absorbs normal multi-node drift without meaningfully delaying
    # expiry-based rejection; revocation remains blacklist/lifecycle-driven.
    'LEEWAY': timedelta(seconds=30),
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    # Accept legacy HS256 access tokens plus first-party RS256 platform tokens.
    # AgentAccessToken validates the broker-relay audience; PlatformAccessToken
    # validates the first-party wildcard audience. Do NOT swap the global
    # authenticator to RS256OAuthBearerAuthentication, which is intentionally
    # broader for OAuth userinfo only.
    'AUTH_TOKEN_CLASSES': (
        'rest_framework_simplejwt.tokens.AccessToken',
        'identity.agent_tokens.AgentAccessToken',
        'identity.agent_tokens.PlatformAccessToken',
    ),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# Resource servers in this set must resolve the mailbox identity through the
# authenticated userinfo endpoint instead of trusting an offline email claim.
# Stalwart otherwise validates a self-contained JWT with clock leeway, which
# delays lifecycle revocation and can recreate a just-deprovisioned principal.
OAUTH_ONLINE_USERINFO_CLIENT_NAMES = frozenset(
    value.strip()
    for value in os.environ.get(
        'OAUTH_ONLINE_USERINFO_CLIENT_NAMES', 'shizuha-mail',
    ).split(',')
    if value.strip()
)

# Refresh-storm detection (ADR-PLAT-002 §5-INV-2, population-wide signal)
REFRESH_STORM_ENABLED = os.environ.get('REFRESH_STORM_ENABLED', 'true').lower() != 'false'
REFRESH_STORM_THRESHOLD = int(os.environ.get('REFRESH_STORM_THRESHOLD', '20'))
REFRESH_STORM_WINDOW_S = int(os.environ.get('REFRESH_STORM_WINDOW_S', '10'))
# Safety TTL (s) for the storm-active latch — only guards a stuck latch if the
# process dies mid-storm; must be >> the window so it never expires under
# sustained load. Normal disarm is the below-threshold DEL in the Lua window.
REFRESH_STORM_ACTIVE_TTL_S = int(os.environ.get('REFRESH_STORM_ACTIVE_TTL_S', '3600'))
# M-C config-switch hook (AC5): select the WindowStrategy by name. Swapping to a
# per-upstream-partition strategy at M-C is a setting change, not a code change.
REFRESH_STORM_WINDOW_STRATEGY = os.environ.get('REFRESH_STORM_WINDOW_STRATEGY', 'population-wide')
# Defaults to the Celery/Redis instance; override to isolate the window store.
REFRESH_STORM_REDIS_URL = os.environ.get('REFRESH_STORM_REDIS_URL', CELERY_BROKER_URL)

# PLAT-1331 Part B — per-tenant rate-limit (availability isolation). Default OFF
# until the pilot enables it per-environment; fail-open on Redis error.
TENANT_RATE_LIMIT_ENABLED = os.environ.get('TENANT_RATE_LIMIT_ENABLED', 'false').lower() == 'true'
TENANT_RATE_LIMIT_RPM = int(os.environ.get('TENANT_RATE_LIMIT_RPM', '600'))
TENANT_RATE_LIMIT_WINDOW_S = int(os.environ.get('TENANT_RATE_LIMIT_WINDOW_S', '60'))
TENANT_RATE_LIMIT_REDIS_URL = os.environ.get('TENANT_RATE_LIMIT_REDIS_URL', REFRESH_STORM_REDIS_URL)

# dj-rest-auth settings
REST_AUTH = {
    'USE_JWT': True,
    'JWT_AUTH_COOKIE': 'shizuha-access-token',
    'JWT_AUTH_REFRESH_COOKIE': 'shizuha-refresh-token',
    'JWT_AUTH_HTTPONLY': True,
    'JWT_AUTH_SECURE': not DEBUG,
    'JWT_AUTH_SAMESITE': 'Lax',
    # Share the browser session across first-party *.shizuha.com hosts
    # (origin.shizuha.com deploy-status board etc.). Host-only in DEBUG.
    'JWT_AUTH_COOKIE_DOMAIN': os.environ.get(
        'JWT_AUTH_COOKIE_DOMAIN', '' if DEBUG else '.shizuha.com'
    ),
    'SESSION_LOGIN': False,
    'TOKEN_MODEL': None,
}

# Allauth settings
ACCOUNT_LOGIN_METHODS = {'email', 'username'}
ACCOUNT_SIGNUP_FIELDS = ['email*', 'username*', 'password1*', 'password2*']
ACCOUNT_EMAIL_VERIFICATION = 'optional'
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_ADAPTER = 'allauth.account.adapter.DefaultAccountAdapter'
SOCIALACCOUNT_ADAPTER = 'identity.adapters.ApprovalSocialAccountAdapter'
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True

# OAuth Provider Settings
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'online'},
        'OAUTH_PKCE_ENABLED': True,
        'APP': {
            'client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
            'secret': os.environ.get('GOOGLE_CLIENT_SECRET', ''),
        },
    },
    'github': {
        'SCOPE': ['user:email'],
        'APP': {
            'client_id': os.environ.get('GITHUB_CLIENT_ID', ''),
            'secret': os.environ.get('GITHUB_CLIENT_SECRET', ''),
        },
    },
}

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# DRF Spectacular settings
SPECTACULAR_SETTINGS = {
    'TITLE': 'Shizuha ID API',
    'DESCRIPTION': '''
Identity and Authentication Service for the Shizuha Platform.

## Overview

Shizuha ID provides centralized authentication and user management for all
Shizuha platform applications including Pulse, Notify, Admin, and others.

## Features

- JWT-based authentication
- OAuth providers (Google, GitHub)
- User profile management
- Tool preferences
- Account management (deletion, export)

## Authentication

All authenticated endpoints require a Bearer token in the Authorization header.
    ''',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
}

# CORS settings
CORS_ALLOW_ALL_ORIGINS = os.environ.get('CORS_ALLOW_ALL_ORIGINS', 'true').lower() in ('true', '1', 'yes')
CORS_ALLOWED_ORIGINS = [origin.strip() for origin in os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if origin.strip()]

# Password Reset Settings
SHIZUHA_MAIL_API_URL = os.environ.get('SHIZUHA_MAIL_API_URL', 'http://shizuha-mail:8014')
# MAIL-74: immutable system OAuth client_id for delegated mail tokens (never client_name).
SHIZUHA_MAIL_OAUTH_CLIENT_ID = os.environ.get('SHIZUHA_MAIL_OAUTH_CLIENT_ID', '').strip()

PASSWORD_RESET_TOKEN_EXPIRY_HOURS = int(os.environ.get('PASSWORD_RESET_EXPIRY_HOURS', '1'))

# Scoped in-cluster token for HIVE fleet agent account provisioning.
# Empty means the internal endpoint fails closed.
FLEET_PROVISIONER_TOKEN = os.environ.get('FLEET_PROVISIONER_TOKEN', '')
# HIVE-444: scoped credential for the QA/validation runtime's test-tenant
# deprovision endpoint (NOT superuser; test-domain-gated).
VALIDATION_RUNTIME_TOKEN = os.environ.get('VALIDATION_RUNTIME_TOKEN', '')
# ID-58 Phase A: optional internal-service-token for /api/internal/users/* lookups.
# Empty means Phase A accept-and-log mode is still active but the token check
# always returns False (no token configured = all callers are network-trust).
# Phase C (require mode) is gated on 100% observed adoption; do NOT enable
# require mode until caller logs confirm 100% token adoption.
INTERNAL_SERVICE_TOKEN = os.environ.get('INTERNAL_SERVICE_TOKEN', '')
# Hive in-cluster URL for the default personal-agent ensure on activation.
# Empty (the test/default) skips the notify so ID CI never talks to live Hive.
SHIZUHA_HIVE_INTERNAL_URL = os.environ.get('SHIZUHA_HIVE_INTERNAL_URL', '').rstrip('/')

# PLAT-4133: authenticated, sanitized boundary-denial events to Connect SIEM-lite.
SHIZUHA_CONNECT_SECURITY_EVENT_URL = os.environ.get(
    'SHIZUHA_CONNECT_SECURITY_EVENT_URL',
    'http://shizuha-connect.shizuha.svc.cluster.local:8019/api/internal/security-events/',
)
CONNECT_SECURITY_EVENT_ORIGIN_SECRET = os.environ.get('CONNECT_SECURITY_EVENT_ORIGIN_SECRET', '')
CONNECT_SECURITY_EVENT_TIMEOUT_SECONDS = float(os.environ.get('CONNECT_SECURITY_EVENT_TIMEOUT_SECONDS', '1.0'))
CONNECT_SECURITY_EVENT_EMIT_ENABLED = os.environ.get('CONNECT_SECURITY_EVENT_EMIT_ENABLED', 'true').lower() in ('1', 'true', 'yes')

# CSRF settings
CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in os.environ.get(
    'CSRF_TRUSTED_ORIGINS',
    'http://localhost:8001,http://localhost:8002,https://ai.shizuha.com,https://chat.shizuha.com,https://id.shizuha.com',
).split(',') if origin.strip()]

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'identity': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
