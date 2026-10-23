"""OAuth tools for Google Ads authentication via conversational flow."""

import logging

from google_mcp_common import storage
from google_mcp_common.oauth_flow import (
    allow_insecure_transport_for_localhost,
    build_authorization_url,
)
from google_mcp_common.utils import get_user_id
from mcp.server.fastmcp import Context

from ads_mcp.coordinator import mcp
from ads_mcp.environment import environment

logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/adwords"]


def get_client_config() -> dict:
    """Build the OAuth client config from env or GCP Secret Manager."""
    return {
        "web": {
            "client_id": environment.get("GOOGLE_CLIENT_ID"),
            "client_secret": environment.get("GOOGLE_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }


def get_redirect_uri() -> str:
    return f"{environment.get('GOOGLE_ADS_MCP_SERVER_URL')}/oauth/callback"


@mcp.tool()
def auth_google_ads(ctx: Context) -> str:
    """Start the Google Ads OAuth authentication flow.

    Returns an authorization URL that the user must open in their browser.
    After granting access, the server handles the callback automatically.
    """
    user_id = get_user_id(ctx)

    try:
        client_config = get_client_config()
    except KeyError as e:
        return f"Missing environment variable: {e}. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."

    redirect_uri = get_redirect_uri()
    allow_insecure_transport_for_localhost(redirect_uri)

    authorization_url, state, code_verifier = build_authorization_url(
        client_config=client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )

    storage.save_pending_auth(user_id, state, code_verifier, SCOPES)

    return (
        f"Open this URL in your browser to authenticate:\n\n{authorization_url}\n\n"
        "After granting access, this tab will show a success message "
        "and you can close it."
    )
