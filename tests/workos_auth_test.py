"""Test cases for the WorkOS AuthKit token verifier."""

import asyncio
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt as pyjwt
from jwt import PyJWKClientError

from ads_mcp.workos_auth import WorkOSTokenVerifier

ISSUER = "https://test.authkit.app"


def _generate_rsa_keypair():
    """Generate a test RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


PRIVATE_KEY, PUBLIC_KEY = _generate_rsa_keypair()


def _make_jwt(claims: dict, key=PRIVATE_KEY) -> str:
    """Create a signed JWT with the given claims."""
    defaults = {
        "iss": ISSUER,
        "sub": "user_123",
        "azp": "client_abc",
        "scope": "openid profile email",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    defaults.update(claims)
    return pyjwt.encode(defaults, key, algorithm="RS256")


def _mock_jwks_client(verifier):
    """Patch the JWKS client to return our test public key."""
    mock_signing_key = mock.MagicMock()
    mock_signing_key.key = PUBLIC_KEY.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier.jwks_client = mock.MagicMock()
    verifier.jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key


class TestWorkOSTokenVerifier(unittest.TestCase):
    """Test cases for WorkOSTokenVerifier."""

    def setUp(self):
        self.verifier = WorkOSTokenVerifier(issuer_url=ISSUER)
        _mock_jwks_client(self.verifier)

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_jwks_url(self):
        """JWKS URL follows WorkOS .well-known convention."""
        verifier = WorkOSTokenVerifier(issuer_url="https://example.authkit.app")
        self.assertEqual(
            verifier.jwks_url,
            "https://example.authkit.app/oauth2/jwks",
        )

    def test_jwks_url_strips_trailing_slash(self):
        """Trailing slash on issuer URL is stripped."""
        verifier = WorkOSTokenVerifier(issuer_url="https://example.authkit.app/")
        self.assertEqual(
            verifier.jwks_url,
            "https://example.authkit.app/oauth2/jwks",
        )

    def test_valid_token(self):
        """A valid JWT returns an AccessToken with correct fields."""
        token = _make_jwt({})
        result = self._run(self.verifier.verify_token(token))

        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, "user_123")
        self.assertEqual(result.scopes, ["openid", "profile", "email"])
        self.assertIsNotNone(result.expires_at)
        self.assertEqual(result.token, token)

    def test_expired_token(self):
        """An expired JWT returns None."""
        token = _make_jwt({"exp": int(time.time()) - 3600})
        result = self._run(self.verifier.verify_token(token))

        self.assertIsNone(result)

    def test_invalid_signature(self):
        """A JWT signed with a different key returns None."""
        other_private_key, _ = _generate_rsa_keypair()
        token = _make_jwt({}, key=other_private_key)
        result = self._run(self.verifier.verify_token(token))

        self.assertIsNone(result)

    def test_wrong_issuer(self):
        """A JWT with a wrong issuer returns None."""
        token = _make_jwt({"iss": "https://wrong.authkit.app"})
        result = self._run(self.verifier.verify_token(token))

        self.assertIsNone(result)

    def test_sub_used_as_client_id(self):
        """client_id is always taken from sub claim."""
        token = _make_jwt({"sub": "user_456"})
        payload = pyjwt.decode(token, options={"verify_signature": False})
        del payload["azp"]
        token_no_azp = pyjwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

        result = self._run(self.verifier.verify_token(token_no_azp))

        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, "user_456")

    def test_no_azp_no_sub(self):
        """When both azp and sub are missing, client_id is 'unknown'."""
        payload = {
            "iss": ISSUER,
            "scope": "openid",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = pyjwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

        result = self._run(self.verifier.verify_token(token))

        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, "unknown")

    def test_no_scope(self):
        """When scope is missing, scopes is an empty list."""
        payload = {
            "iss": ISSUER,
            "sub": "user_123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = pyjwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

        result = self._run(self.verifier.verify_token(token))

        self.assertIsNotNone(result)
        self.assertEqual(result.scopes, [])

    def test_jwks_connection_error_returns_none(self):
        """JWKS client connection failure returns None, not crash."""
        self.verifier.jwks_client.get_signing_key_from_jwt.side_effect = (
            PyJWKClientError("Connection failed")
        )
        token = _make_jwt({})
        result = self._run(self.verifier.verify_token(token))

        self.assertIsNone(result)

    def test_jwks_no_matching_key_returns_none(self):
        """JWKS client unable to find matching key returns None."""
        self.verifier.jwks_client.get_signing_key_from_jwt.side_effect = (
            PyJWKClientError("Unable to find a signing key")
        )
        token = _make_jwt({})
        result = self._run(self.verifier.verify_token(token))

        self.assertIsNone(result)
