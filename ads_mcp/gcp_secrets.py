"""Fetch secrets from GCP Secret Manager with local env var fallback."""

import logging
import os
from functools import lru_cache

_logger = logging.getLogger(__name__)

_SECRET_MAP = {
    "ENCRYPTION_KEY": "adviso-encryption-key",
    "GOOGLE_ADS_DEVELOPER_TOKEN": "google-ads-developer-token",
    "GOOGLE_CLIENT_ID": "google-ads-client-id",
    "GOOGLE_CLIENT_SECRET": "google-ads-client-secret",
    "GOOGLE_ADS_LOGIN_CUSTOMER_ID": "google-ads-login-customer-id",
}

_GCP_PROJECT = os.getenv("GCP_PROJECT", "adviso-chat-staging")


@lru_cache(maxsize=None)
def _get_client():
    from google.cloud import secretmanager

    return secretmanager.SecretManagerServiceClient()


def get_secret(env_key: str) -> str | None:
    """Fetch a secret by its env var name.

    Tries env var first (for local dev), then GCP Secret Manager.
    Returns None if not found in either.
    """
    value = os.environ.get(env_key)
    if value is not None:
        return value

    gcp_name = _SECRET_MAP.get(env_key)
    if gcp_name is None:
        return None

    try:
        client = _get_client()
        name = f"projects/{_GCP_PROJECT}/secrets/{gcp_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception:
        _logger.debug("Secret %s not found in Secret Manager", gcp_name)
        return None


def require_secret(env_key: str) -> str:
    """Fetch a required secret. Raises ValueError if not found."""
    value = get_secret(env_key)
    if value is None:
        raise ValueError(
            f"{env_key} is required. Set it as an env var or in GCP Secret Manager "
            f"(secret: {_SECRET_MAP.get(env_key, '?')})"
        )
    return value
