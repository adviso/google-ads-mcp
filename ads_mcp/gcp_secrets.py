"""Fetch secrets from GCP Secret Manager with local env var fallback."""

import logging
import os
from functools import lru_cache

from ads_mcp.environment import environment

_logger = logging.getLogger(__name__)

_SECRET_MAP = {
    "ADVISO_ENCRYPTION_KEY": "adviso-encryption-key",
    "GOOGLE_ADS_DEVELOPER_TOKEN": "google-ads-developer-token",
    "GOOGLE_CLIENT_ID": "google-ads-client-id",
    "GOOGLE_CLIENT_SECRET": "google-ads-client-secret",
}

_GCP_PROJECT = environment.get("GCP_PROJECT")


class SecretManager:
    @lru_cache(maxsize=None)
    def __init__(self):
        from google.cloud import secretmanager

        self.client = secretmanager.SecretManagerServiceClient()

    def get_secret(self, env_key: str) -> str | None:
        gcp_name = _SECRET_MAP.get(env_key)
        if gcp_name is None:
            return None

        try:
            client = self.client
            name = f"projects/{_GCP_PROJECT}/secrets/{gcp_name}/versions/latest"
            response = client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
        except Exception:
            _logger.warning(
                "Failed to fetch secret %s from Secret Manager", gcp_name, exc_info=True
            )
            return None

    def init_secrets(self):
        for env_key in _SECRET_MAP.items():
            value = self.get_secret(env_key[0])
            if value is not None:
                environment.variables[env_key[0]] = value


secret_manager = SecretManager()
