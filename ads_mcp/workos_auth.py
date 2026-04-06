"""WorkOS AuthKit JWT token verifier for the MCP server.

Validates JWTs issued by WorkOS AuthKit via their JWKS endpoint.
Implements the TokenVerifier protocol expected by the MCP SDK.
"""

import asyncio
import logging

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)


class WorkOSTokenVerifier:
    """Verifies JWTs issued by WorkOS AuthKit via JWKS."""

    def __init__(self, issuer_url: str):
        self.issuer_url = issuer_url.rstrip("/")
        self.jwks_url = f"{self.issuer_url}/oauth2/jwks"
        self.jwks_client = PyJWKClient(self.jwks_url, cache_keys=True)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            signing_key = await asyncio.to_thread(
                self.jwks_client.get_signing_key_from_jwt, token
            )
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.issuer_url,
                options={"verify_aud": False},
            )
            return AccessToken(
                token=token,
                client_id=payload.get("sub", "unknown"),
                scopes=payload.get("scope", "").split() if payload.get("scope") else [],
                expires_at=payload.get("exp"),
            )
        except jwt.ExpiredSignatureError:
            logger.warning("WorkOS JWT expired")
            return None
        except jwt.PyJWTError as e:
            logger.warning("WorkOS JWT verification failed: %s", e)
            return None
        except Exception as e:
            logger.warning("WorkOS token verification error: %s", e)
            return None
