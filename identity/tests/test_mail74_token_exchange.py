"""MAIL-74: self-only delegated token exchange for shizuha-mail."""
from unittest import mock

import jwt
from django.contrib.auth import get_user_model
from django.db import OperationalError
from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken

from identity.lifecycle import LifecycleState, mailbox_address_for_user
from identity.models import OAuthClient, Tool, UserProfile
from identity.oauth_views import _mint_tokens


User = get_user_model()
_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = mock.patch(
        'identity.oauth_views._fetch_membership_projection',
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


@override_settings(
    OAUTH_ONLINE_USERINFO_CLIENT_NAMES=frozenset({'shizuha-mail'}),
    SHIZUHA_MAIL_OAUTH_CLIENT_ID='mail74-shizuha-mail-client',
)
class Mail74TokenExchangeTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.user = User.objects.create_user(
            username='mail74-user',
            email='mail74-user@shizuha.com',
            password='pw',
            is_active=True,
        )
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.lifecycle_state = LifecycleState.ACTIVE
        profile.approval_status = 'approved'
        profile.save()
        mail_tool, _ = Tool.objects.get_or_create(
            slug='mail',
            defaults={'display_name': 'Mail', 'is_active': True},
        )
        profile.enabled_tools.add(mail_tool)
        self.mail_client = OAuthClient.objects.create(
            client_id='mail74-shizuha-mail-client',
            client_name='shizuha-mail',
            redirect_uris=['https://mail.example/callback'],
            grant_types=['authorization_code', 'refresh_token'],
            response_types=['code'],
            scope='openid email mail',
            access_token_ttl_minutes=1,
            is_system=True,
        )
        tokens = _mint_tokens(
            self.user,
            OAuthClient.objects.create(
                client_id='mail74-platform',
                client_name='platform-test',
                redirect_uris=[],
                grant_types=['password'],
                response_types=[],
                scope='openid profile email',
            ),
            'openid profile email',
            'https://id.example.invalid',
        )
        self.subject_access = tokens['access_token']

    def _exchange(self, token=None, **extra):
        body = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': token if token is not None else self.subject_access,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            **extra,
        }
        return self.api.post('/api/oauth/token', body, format='json')

    def test_mints_access_only_shizuha_mail_token(self):
        resp = self._exchange()
        self.assertEqual(resp.status_code, 200, resp.content)
        data = resp.json()
        self.assertIn('access_token', data)
        self.assertNotIn('refresh_token', data)
        self.assertEqual(data['expires_in'], 60)
        self.assertEqual(data['scope'], 'openid email')
        claims = jwt.decode(data['access_token'], options={'verify_signature': False})
        self.assertEqual(claims['aud'], self.mail_client.client_id)
        self.assertEqual(claims['client_id'], self.mail_client.client_id)
        self.assertEqual(claims['sub'], str(self.user.pk))
        self.assertEqual(claims['user_id'], self.user.pk)
        self.assertEqual(claims['scope'], 'openid email')
        self.assertEqual(claims['token_type'], 'access')
        self.assertEqual(claims['token_use'], 'mail_delegated')
        # MAIL-122: was `assertNotIn('email', claims)`. A SECOND stale assertion
        # of the reversed behaviour, in a test whose name is about access-only
        # minting rather than about email — so it was not named in the fix
        # contract and only surfaced by running the full module.
        self.assertEqual(claims['email'], 'mail74-user@shizuha.com')
        # HLD v12 claim-minimization: exact allowlist only (no staff/services/org/profile).
        # MAIL-122 adds exactly ONE member — `email`, the managed mailbox Stalwart
        # authenticates offline via claimUsername. The allowlist is the security
        # property here, so it stays exact: this is a deliberate +1, not a relaxation.
        allowed = {
            'iss', 'sub', 'user_id', 'aud', 'iat', 'exp', 'jti',
            'client_id', 'scope', 'token_type', 'token_use',
            'email',
        }
        self.assertEqual(set(claims.keys()), allowed, claims.keys())
        for unrelated in (
            'enabled_services', 'is_staff', 'is_superuser', 'is_service',
            'organization_memberships', 'project_ids', 'project_roles',
            'roles', 'groups', 'username', 'preferred_username', 'name',
            # `email` moved to the allowlist above. `email_verified` stays denied:
            # the mailbox is managed by ID, so a verification claim would assert a
            # property Stalwart must not infer from this token.
            'email_verified', 'given_name', 'family_name',
        ):
            self.assertNotIn(unrelated, claims)
        self.assertLessEqual(claims['exp'] - claims['iat'], 60)
        self.assertEqual(jwt.get_unverified_header(data['access_token'])['alg'], 'RS256')

    def test_rejects_invalid_subject_token(self):
        resp = self._exchange(token='not-a-jwt')
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()['error'], 'invalid_grant')

    def test_rejects_without_mail_entitlement(self):
        with mock.patch(
            'identity.services.get_effective_services',
            return_value=['notes', 'wiki'],
        ):
            resp = self._exchange()
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()['error'], 'access_denied')

    def test_rejects_inactive_lifecycle(self):
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        profile = self.user.profile
        profile.lifecycle_state = LifecycleState.DEACTIVATED
        profile.save(update_fields=['lifecycle_state'])
        resp = self._exchange()
        self.assertIn(resp.status_code, (401, 403))

    def test_accepts_current_hs256_platform_access_token(self):
        # The live platform bearer is a SimpleJWT/HS256 access token.  Keep
        # this caller path gated as well as the OAuth/RS256 subject path.
        resp = self._exchange(token=str(AccessToken.for_user(self.user)))
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertIn('access_token', resp.json())

    def test_missing_lifecycle_profile_fails_closed(self):
        UserProfile.objects.filter(user=self.user).delete()
        resp = self._exchange()
        self.assertEqual(resp.status_code, 403, resp.content)
        self.assertEqual(resp.json()['error'], 'invalid_grant')

    def test_lifecycle_lookup_error_fails_closed(self):
        with mock.patch(
            'identity.oauth_views.UserProfile.objects.get',
            side_effect=OperationalError('database unavailable'),
        ):
            resp = self._exchange()
        self.assertEqual(resp.status_code, 503, resp.content)
        self.assertEqual(resp.json()['error'], 'temporarily_unavailable')

    def test_missing_subject_token_400(self):
        resp = self.api.post(
            '/api/oauth/token',
            {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange'},
            format='json',
        )
        self.assertEqual(resp.status_code, 400)


    def test_spoofed_client_name_does_not_win(self):
        """Duplicate client_name must not steal the configured client_id audience."""
        OAuthClient.objects.create(
            client_id='spoofed-mail-client',
            client_name='shizuha-mail',
            redirect_uris=['https://evil.example/cb'],
            grant_types=['authorization_code'],
            response_types=['code'],
            scope='openid email',
            is_system=False,
        )
        resp = self._exchange()
        self.assertEqual(resp.status_code, 200, resp.content)
        claims = jwt.decode(resp.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(claims['aud'], 'mail74-shizuha-mail-client')
        self.assertEqual(claims['client_id'], 'mail74-shizuha-mail-client')
        self.assertNotEqual(claims['aud'], 'spoofed-mail-client')

    def test_missing_configured_client_id_fails_closed(self):
        OAuthClient.objects.filter(client_id='mail74-shizuha-mail-client').delete()
        resp = self._exchange()
        self.assertEqual(resp.status_code, 500, resp.content)
        self.assertEqual(resp.json()['error'], 'invalid_client')

    def test_non_system_configured_client_fails_closed(self):
        self.mail_client.is_system = False
        self.mail_client.save(update_fields=['is_system'])
        resp = self._exchange()
        self.assertEqual(resp.status_code, 500, resp.content)
        self.assertEqual(resp.json()['error'], 'invalid_client')

    def test_revoked_subject_access_cannot_mint(self):
        from datetime import timedelta
        from django.utils import timezone

        profile = self.user.profile
        profile.access_revoked_before = timezone.now() + timedelta(seconds=1)
        profile.save(update_fields=['access_revoked_before'])
        resp = self._exchange()
        self.assertEqual(resp.status_code, 401, resp.content)
        self.assertEqual(resp.json()['error'], 'invalid_grant')

    def test_revoked_mail_client_fails_closed(self):
        from django.utils import timezone
        self.mail_client.access_revoked_before = timezone.now()
        self.mail_client.save(update_fields=['access_revoked_before'])
        resp = self._exchange()
        self.assertEqual(resp.status_code, 400, resp.content)
        self.assertEqual(resp.json()['error'], 'invalid_client')


    def test_delegated_token_cannot_be_reexchanged(self):
        """MAIL-74: output of exchange is not a valid subject for another exchange."""
        first = self._exchange()
        self.assertEqual(first.status_code, 200, first.content)
        delegated = first.json()['access_token']
        second = self._exchange(token=delegated)
        self.assertEqual(second.status_code, 403, second.content)
        self.assertEqual(second.json()['error'], 'invalid_grant')

    def test_delegated_token_resolves_online_userinfo(self):
        """The minimal token still carries the private subject key userinfo needs."""
        minted = self._exchange()
        self.assertEqual(minted.status_code, 200, minted.content)
        self.api.credentials(
            HTTP_AUTHORIZATION=f"Bearer {minted.json()['access_token']}"
        )
        response = self.api.get('/api/oauth/userinfo')
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json()['email'],
            mailbox_address_for_user(self.user),
        )

    def test_delegated_userinfo_maps_external_login_to_managed_mailbox(self):
        # Clear the profile object cached by the user-creation signal so the
        # user post-save hook re-reads the active profile rather than saving
        # its original pending snapshot.
        self.user.refresh_from_db()
        self.user.email = 'mail74-user@gmail.com'
        self.user.save(update_fields=['email'])

        minted = self._exchange()
        self.assertEqual(minted.status_code, 200, minted.content)
        self.api.credentials(
            HTTP_AUTHORIZATION=f"Bearer {minted.json()['access_token']}"
        )
        response = self.api.get('/api/oauth/userinfo')

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['email'], 'mail74-user@shizuha.com')

    def test_normal_userinfo_preserves_external_login_email(self):
        self.user.refresh_from_db()
        self.user.email = 'mail74-user@gmail.com'
        self.user.save(update_fields=['email'])
        self.api.credentials(HTTP_AUTHORIZATION=f'Bearer {self.subject_access}')

        response = self.api.get('/api/oauth/userinfo')

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['email'], 'mail74-user@gmail.com')

    def test_delegated_token_embeds_the_canonical_mailbox_even_if_allowlist_empty(self):
        """MAIL-122: replaces `test_delegated_token_never_embeds_email_...`.

        That test asserted the exact behaviour this change reverses, and it was
        correct under the MAIL-74 contract (Stalwart resolves email online via
        /userinfo). It became a stale assertion when the outage proved that
        contract makes every JMAP/SMTP auth depend on Stalwart pod -> public-ID
        reachability AFTER a valid token is minted; Stalwart v0.16.13 treats a
        failed /userinfo as fatal to authentication.

        The claim must be present UNCONDITIONALLY -- not gated on the
        online-userinfo allowlist or the client name -- because Stalwart
        authenticates offline from it. Hence the emptied allowlist and renamed
        client are retained from the original: they prove no gate can suppress
        it.
        """
        with self.settings(OAUTH_ONLINE_USERINFO_CLIENT_NAMES=frozenset()):
            # Also rename client so client_name-based gates cannot help.
            self.mail_client.client_name = 'renamed-mail-display'
            self.mail_client.save(update_fields=['client_name'])
            resp = self._exchange()
        self.assertEqual(resp.status_code, 200, resp.content)
        claims = jwt.decode(resp.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(claims.get('email'), 'mail74-user@shizuha.com')
        self.assertEqual(claims['aud'], 'mail74-shizuha-mail-client')

    def test_delegated_token_carries_the_managed_mailbox_not_the_external_login(self):
        """The security half: the claim must never leak an external address.

        A user's `email` may be an external/login address (`...@gmail.com`) and
        `/userinfo` legitimately returns it -- asserted directly above in
        `test_userinfo_returns_external_email...`. The delegated token is a
        different contract: it authenticates a MANAGED mailbox to Stalwart, so
        it must carry `<local>@shizuha.com` and never the login address.

        Without this, the obvious implementation (`'email': user.email`) passes
        the presence test above while handing Stalwart an identity it does not
        own -- an auth bypass shaped like a fix.
        """
        # NOTE: queryset .update(), not self.user.save(). The `post_save` receiver
        # `save_user_profile` re-saves the User's CACHED `.profile`, which still
        # holds the pre-setUp lifecycle — so `self.user.save()` silently reverts
        # setUp's ACTIVE profile and the exchange 403s on lifecycle, failing this
        # test for a reason unrelated to the claim it asserts.
        User.objects.filter(pk=self.user.pk).update(email='mail74-user@gmail.com')
        resp = self._exchange()
        self.assertEqual(resp.status_code, 200, resp.content)
        claims = jwt.decode(resp.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(claims.get('email'), 'mail74-user@shizuha.com')
        self.assertNotEqual(claims.get('email'), 'mail74-user@gmail.com')

    def test_legacy_identity_whose_username_is_an_email_yields_a_single_at(self):
        """External-login users, per the required regression.

        A legacy identity may have an email-shaped USERNAME. Naive templating
        (`f'{username}@shizuha.com'`) produces `a@b.com@shizuha.com`, which is
        unroutable -- so this class of user would stay broken after the fix
        while every other test passed.
        """
        # .update() for the same cached-profile reason as above.
        User.objects.filter(pk=self.user.pk).update(username='legacy-user@externalcorp.com')
        resp = self._exchange()
        self.assertEqual(resp.status_code, 200, resp.content)
        claims = jwt.decode(resp.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(claims.get('email'), 'legacy-user@shizuha.com')
        self.assertEqual(claims.get('email', '').count('@'), 1)

    def test_stalwart_consumer_authenticates_offline_with_userinfo_unavailable(self):
        """MAIL-122's actual acceptance, at the real boundary.

        The two tests above prove the claim's VALUE. This proves the PROPERTY
        the outage was about: that the token is self-sufficient, so a consumer
        configured `claimUsername=email` never has to reach ID again.

        A presence assertion cannot show that -- the claim could be present and
        the consumer still fail if it had to call /userinfo. So this performs
        exactly what Stalwart does: verify RS256 against the published JWKS,
        check audience, and read `claimUsername` -- with /userinfo forced to
        raise, proving it is not on the authentication path.
        """
        from unittest import mock
        from identity.oauth_keys import get_signing_material

        resp = self._exchange()
        self.assertEqual(resp.status_code, 200, resp.content)
        token = resp.json()['access_token']

        # Make the dependency the outage exposed provably unavailable.
        with mock.patch(
            'identity.oauth_views.UserinfoView.get',
            side_effect=AssertionError('/userinfo must not be on the auth path'),
        ):
            claims = jwt.decode(
                token,
                get_signing_material()['public_pem'],
                algorithms=['RS256'],
                audience='mail74-shizuha-mail-client',
            )

        # claimUsername=email — the identity Stalwart authenticates.
        self.assertEqual(claims['email'], 'mail74-user@shizuha.com')
        self.assertEqual(claims['token_use'], 'mail_delegated')
        self.assertIn('email', claims['scope'])

    def test_subject_user_access_revocation_fails_closed(self):
        from django.utils import timezone
        profile = self.user.profile
        profile.access_revoked_before = timezone.now()
        profile.save(update_fields=['access_revoked_before'])
        resp = self._exchange()
        # Subject auth or grant must fail closed for revoked user access.
        self.assertIn(resp.status_code, (401, 403), resp.content)
