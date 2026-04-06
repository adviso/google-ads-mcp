"""OAuth tools for Google Ads authentication via conversational flow."""

import logging
import os

import ads_mcp.storage as storage
import google_auth_oauthlib.flow
from ads_mcp.coordinator import mcp

logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/adwords"]


def _get_client_config() -> dict:
    """Build the OAuth client config from environment variables."""
    return {
        "web": {
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }


def _get_redirect_uri() -> str:
    return f"{os.environ.get('GOOGLE_ADS_MCP_HOST', 'http://localhost:3000')}/oauth/callback"


@mcp.tool()
def start_google_ads_auth() -> str:
    """Start the Google Ads OAuth authentication flow.

    Returns an authorization URL that the user must open in their browser.
    After granting access, the browser redirects to a localhost URL (which will
    show a connection error — that's expected). The user must copy the full URL
    from the browser address bar and pass it to complete_google_ads_auth.
    """
    try:
        client_config = _get_client_config()
    except KeyError as e:
        return f"Missing environment variable: {e}. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."

    redirect_uri = _get_redirect_uri()

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config=client_config,
        scopes=SCOPES,
    )
    flow.redirect_uri = redirect_uri

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
    )

    storage.save_pending_auth(state, flow.code_verifier, SCOPES)

    return (
        f"Open this URL in your browser to authenticate:\n\n{authorization_url}\n\n"
        "After granting access, your browser will redirect to a localhost URL "
        "(the page will show a connection error — that's normal).\n"
        "Copy the FULL URL from the browser address bar and pass it to "
        "the complete_google_ads_auth tool."
    )


@mcp.tool()
def complete_google_ads_auth(callback_url: str) -> str:
    """Complete the Google Ads OAuth flow by exchanging the authorization code for tokens.

    Args:
        callback_url: The full URL from the browser address bar after the OAuth redirect.
                      Contains the authorization code and state parameters.
    """
    pending = storage.load_pending_auth()
    if pending is None:
        return (
            "No pending authentication found. "
            "Run start_google_ads_auth first to begin the OAuth flow."
        )

    try:
        client_config = _get_client_config()
    except KeyError as e:
        return f"Missing environment variable: {e}."

    redirect_uri = _get_redirect_uri()

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config=client_config,
        scopes=pending["scopes"],
        state=pending["state"],
        code_verifier=pending["code_verifier"],
    )
    flow.redirect_uri = redirect_uri

    try:
        flow.fetch_token(authorization_response=callback_url)
    except Exception as e:
        error_msg = str(e)
        if "Mismatching" in error_msg or "state" in error_msg.lower():
            return (
                "State mismatch detected (possible CSRF). "
                "Please restart the authentication flow with start_google_ads_auth."
            )
        return f"OAuth token exchange failed: {error_msg}"

    credentials = flow.credentials

    # Validate granted scopes
    requested = set(pending["scopes"])
    granted = set(credentials.granted_scopes or [])
    missing = requested - granted
    if missing:
        return (
            f"Google did not grant all required scopes.\n"
            f"Missing: {', '.join(sorted(missing))}\n"
            f"Granted: {', '.join(sorted(granted))}\n"
            "Please re-authenticate and grant all requested permissions."
        )

    credentials_data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": list(credentials.scopes or []),
        "granted_scopes": list(credentials.granted_scopes or []),
    }
    storage.save_tokens(credentials_data)
    storage.clear_pending_auth()

    return (
        f"Authentication successful!\n"
        f"Granted scopes: {', '.join(sorted(granted))}\n"
        "You can now use Google Ads tools."
    )
