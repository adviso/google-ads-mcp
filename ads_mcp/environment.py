"""Environment + Secret Manager bootstrap for the Google Ads MCP."""

from google_mcp_common.environment import Environment
from google_mcp_common.gcp_secrets import SecretManager

VARIABLES = [
    "ENV",
    "GCP_PROJECT",
    "GOOGLE_ADS_MCP_SERVER_HOST",
    "GOOGLE_ADS_MCP_SERVER_PATH",
    "GOOGLE_ADS_MCP_SERVER_PORT",
    "WORKOS_AUTHKIT_ISSUER_URL",
]

CONCATENATED = {
    "GOOGLE_ADS_MCP_SERVER_URL": [
        "GOOGLE_ADS_MCP_SERVER_HOST",
        "GOOGLE_ADS_MCP_SERVER_PATH",
    ],
}

SECRET_MAP = {
    "ADVISO_ENCRYPTION_KEY": "adviso-encryption-key",
    "GOOGLE_ADS_DEVELOPER_TOKEN": "google-ads-developer-token",
    "GOOGLE_CLIENT_ID": "google-ads-client-id",
    "GOOGLE_CLIENT_SECRET": "google-ads-client-secret",
}

environment = Environment(
    variables=VARIABLES,
    concatenated=CONCATENATED,
    optional_empty=("GOOGLE_ADS_MCP_SERVER_PATH",),
)

secret_manager = SecretManager(
    environment=environment,
    secret_map=SECRET_MAP,
    gcp_project=environment.get("GCP_PROJECT"),
)
