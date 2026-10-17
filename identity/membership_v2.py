"""PLAT-5343 slice 1 — ID subject-assertion emission (HLD v12 §4.1).

ID constructs a short-lived, audience/scope-bound subject assertion from the
**already-authenticated mint principal** and presents it, with ID's dedicated
internal service credential, to Admin's v2 membership-composition route:

    POST /api/internal/v2/project-memberships:resolve
    X-Internal-Service: shizuha-id
    X-Internal-Service-Token: <dedicated credential>
    X-Shizuha-Subject-Assertion: <compact signed assertion>

Trust-contract properties (pinned by tests):

- The assertion is signed with ID's **dedicated internal-signing key** (never
  the user-token key) under the S1 algorithm allowlist — EdDSA (Ed25519) only
  on the issuing side; receivers additionally accept ES256.
- Required claims: ``iss=shizuha-id``, ``aud=shizuha-admin``,
  ``scope=membership-projection:resolve``, decimal ``sub`` (string of digits —
  RFC 7519 StringOrURI), canonical ``email`` when known, ``iat``, ``exp`` no
  more than five seconds later, and a fresh ``jti``.
- **Confused-deputy proof (matrix row 11):** the assertion is constructed
  exclusively from the authenticated principal object. No request body, query
  parameter, or tenant token can supply or override ``sub``/``email`` — the
  emitter takes the principal and nothing else.

Cutover (§4.4 step 3): emission activates only when
``SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION`` is enabled AND the signing key and
service credential are configured; otherwise the mint keeps the v1 path.
Once v2 is selected, Admin does not fall back to the circular v1 path — the
flag exists so the image lands safely before the config flip, and its removal
belongs to the later v1-removal slice (§4.4 step 5).
"""
import logging
import os
import time
import uuid

import jwt
from django.conf import settings

logger = logging.getLogger('identity.membership_v2')

ASSERTION_MAX_LIFETIME_SECONDS = 5
ASSERTION_SCOPE = 'membership-projection:resolve'
ASSERTION_ISSUER = 'shizuha-id'
ASSERTION_AUDIENCE = 'shizuha-admin'


class AssertionEmissionUnavailable(Exception):
    """The v2 path is selected but cannot mint an assertion (fail closed)."""


def v2_enabled():
    """Whether the v2 projection path is selected for this deployment."""
    if not str(getattr(settings, 'SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION', '') or
               os.environ.get('SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION', '')).strip().lower() \
            in ('1', 'true', 'yes', 'on'):
        return False
    # A selected v2 path without its material is a misconfiguration: fail the
    # selection (not silently fall back) so the mint refuses and retries.
    return True


def _signing_key():
    key = str(getattr(settings, 'SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY', '') or
              os.environ.get('SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY', '') or '').strip()
    return key.replace('\\n', '\n') if key else ''


def _service_credential():
    return str(getattr(settings, 'SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL', '') or
               os.environ.get('SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL', '') or '').strip()


def emit_subject_assertion(user):
    """Mint the ID subject assertion for the Admin v2 composition route.

    ``user`` is the already-authenticated mint principal (Django user). Its
    ``id`` and ``email`` are the ONLY identity inputs — request data can never
    reach this function (matrix row 11).
    """
    signing_key = _signing_key()
    if not signing_key:
        raise AssertionEmissionUnavailable('signing key not configured')
    now = int(time.time())
    claims = {
        'iss': ASSERTION_ISSUER,
        'aud': ASSERTION_AUDIENCE,
        'scope': ASSERTION_SCOPE,
        'sub': str(int(user.id)),
        'iat': now,
        'exp': now + ASSERTION_MAX_LIFETIME_SECONDS,
        'jti': str(uuid.uuid4()),
    }
    email = (getattr(user, 'email', '') or '').strip().lower()
    if email:
        claims['email'] = email
    return jwt.encode(claims, signing_key, algorithm='EdDSA')


def v2_request_headers(user):
    """Headers for the Admin v2 call: bound credential + subject assertion."""
    credential = _service_credential()
    if not credential:
        raise AssertionEmissionUnavailable('service credential not configured')
    return {
        'X-Internal-Service': 'shizuha-id',
        'X-Internal-Service-Token': credential,
        'X-Shizuha-Subject-Assertion': emit_subject_assertion(user),
    }
