"""Live/CI invariant probe: every OAuth grant minted by ID is RS256-only.

The probe uses the real token endpoint view and signing key, creates an
isolated fixture inside one database transaction, and rolls the transaction
back before returning. It is therefore safe to run both in Django CI and in a
live ID pod after rollout without leaving users, clients, codes, or refresh
records behind.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from datetime import timedelta

import jwt
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from .models import AuthorizationCode, OAuthClient
from .oauth_views import TokenView


class MembershipProjectionTemporarilyUnavailable(RuntimeError):
    """The live dependency contract asked the probe to retry later."""

    def __init__(self, grant: str, retry_after: int = 1):
        self.grant = grant
        self.retry_after = max(1, retry_after)
        super().__init__(
            f'{grant}: membership projection temporarily unavailable '
            f'(retry after {self.retry_after}s)'
        )


def _assert_rs256_response(grant: str, response) -> list[str]:
    if (
        response.status_code == 503
        and response.data.get('error') == 'membership_projection_unavailable'
    ):
        retry_after = response.get('Retry-After', '1')
        try:
            retry_after = int(retry_after)
        except (TypeError, ValueError):
            retry_after = 1
        raise MembershipProjectionTemporarilyUnavailable(grant, retry_after)
    if response.status_code != 200:
        raise AssertionError(f'{grant}: token endpoint returned {response.status_code}: {response.data}')
    checked = []
    for field in ('access_token', 'refresh_token', 'id_token'):
        value = response.data.get(field)
        if not value:
            continue
        header = jwt.get_unverified_header(value)
        if header.get('alg') != 'RS256':
            raise AssertionError(f'{grant}:{field}: expected alg=RS256, got {header.get("alg")!r}')
        if not header.get('kid'):
            raise AssertionError(f'{grant}:{field}: RS256 token is missing kid')
        checked.append(field)
    if 'access_token' not in checked:
        raise AssertionError(f'{grant}: no access token was checked')
    return checked


def _run_oauth_rs256_invariant_probe_once() -> dict[str, list[str]]:
    """Exercise password, authorization_code, refresh, and client_credentials."""
    factory = APIRequestFactory()
    suffix = secrets.token_hex(8)
    username = f'id61-rs256-{suffix}'
    password = secrets.token_urlsafe(24)
    client_secret = secrets.token_urlsafe(32)
    client_id = f'id61-rs256-{suffix}'
    redirect_uri = 'https://id61.invalid/callback'
    verifier = secrets.token_urlsafe(32)

    with transaction.atomic():
        user = get_user_model().objects.create_user(
            username=username,
            email=f'{username}@example.invalid',
            password=password,
        )
        client = OAuthClient.objects.create(
            client_id=client_id,
            client_secret_hash=hashlib.sha256(client_secret.encode()).hexdigest(),
            client_name='ID-61 RS256 invariant probe',
            redirect_uris=[redirect_uri],
            grant_types=['password', 'authorization_code', 'refresh_token', 'client_credentials'],
            response_types=['code'],
            scope='openid profile id:probe.read',
            client_type=OAuthClient.CLIENT_TYPE_CONFIDENTIAL,
            owner=user,
        )

        def post(data):
            request = factory.post('/id/api/oauth/token', data, format='json')
            return TokenView.as_view()(request)

        password_response = post({
            'grant_type': 'password',
            'client_id': client_id,
            'client_secret': client_secret,
            'username': username,
            'password': password,
            'scope': 'openid profile',
        })
        results = {'password': _assert_rs256_response('password', password_response)}

        code = AuthorizationCode.objects.create(
            code=secrets.token_urlsafe(32),
            client=client,
            user=user,
            redirect_uri=redirect_uri,
            scope='openid profile',
            code_challenge=verifier,
            code_challenge_method='plain',
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        code_response = post({
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code.code,
            'redirect_uri': redirect_uri,
            'code_verifier': verifier,
        })
        results['authorization_code'] = _assert_rs256_response('authorization_code', code_response)

        refresh_response = post({
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': password_response.data['refresh_token'],
        })
        results['refresh_token'] = _assert_rs256_response('refresh_token', refresh_response)

        client_response = post({
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'id:probe.read',
        })
        results['client_credentials'] = _assert_rs256_response('client_credentials', client_response)

        # The probe is observational: never persist its user/client/token rows.
        transaction.set_rollback(True)
        return results


def run_oauth_rs256_invariant_probe(
    *,
    max_attempts: int = 5,
) -> dict[str, list[str]]:
    """Run the live probe, honoring Identity's typed transient 503 contract."""
    if max_attempts < 1:
        raise ValueError('max_attempts must be at least 1')

    for attempt in range(1, max_attempts + 1):
        try:
            return _run_oauth_rs256_invariant_probe_once()
        except MembershipProjectionTemporarilyUnavailable as exc:
            if attempt == max_attempts:
                raise
            time.sleep(exc.retry_after)

    raise AssertionError('unreachable')
