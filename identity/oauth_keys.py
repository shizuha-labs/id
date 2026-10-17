"""
RSA keypair + JWKS support for OAuth 2.0 RS256 signing (Phase 5).

Keys are persisted under a data directory (env: SHIZUHA_OAUTH_KEY_DIR, default
/var/shizuha/oauth-keys) so they survive container restarts. `kid` is derived
from the SHA-256 of the DER-encoded public key — deterministic and stable.
"""
import base64
import hashlib
import json
import logging
import os
import threading
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_CACHE: dict | None = None


def _key_dir() -> Path:
    d = Path(os.environ.get('SHIZUHA_OAUTH_KEY_DIR', '/var/shizuha/oauth-keys'))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _private_path() -> Path:
    return _key_dir() / 'jwt-rs256-private.pem'


def _public_path() -> Path:
    return _key_dir() / 'jwt-rs256-public.pem'


def _b64url_uint(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(
        n.to_bytes(byte_length, 'big')
    ).rstrip(b'=').decode('ascii')


def _derive_kid(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def _load_or_generate() -> dict:
    priv_path, pub_path = _private_path(), _public_path()
    if priv_path.exists() and pub_path.exists():
        private_pem = priv_path.read_bytes()
        public_pem = pub_path.read_bytes()
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = private_key.public_key()
        logger.info("OAuth RS256 keypair loaded from disk")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_path.write_bytes(private_pem)
        priv_path.chmod(0o600)
        pub_path.write_bytes(public_pem)
        logger.info("OAuth RS256 keypair generated + persisted")

    kid = _derive_kid(public_key)
    numbers = public_key.public_numbers()
    jwk = {
        'kty': 'RSA',
        'use': 'sig',
        'alg': 'RS256',
        'kid': kid,
        'n': _b64url_uint(numbers.n),
        'e': _b64url_uint(numbers.e),
    }
    return {
        'private_pem': private_pem.decode('ascii'),
        'public_pem': public_pem.decode('ascii'),
        'kid': kid,
        'jwk': jwk,
    }


def get_signing_material() -> dict:
    """Return {private_pem, public_pem, kid, jwk}, caching after first load."""
    global _CACHE
    if _CACHE is None:
        with _LOCK:
            if _CACHE is None:
                _CACHE = _load_or_generate()
    return _CACHE


def build_jwks() -> dict:
    return {'keys': [get_signing_material()['jwk']]}
