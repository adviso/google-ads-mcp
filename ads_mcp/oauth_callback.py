"""FastAPI router for the OAuth callback endpoint."""

import logging

import google_auth_oauthlib.flow
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

import ads_mcp.storage as storage
from ads_mcp.tools.auth import (
    SCOPES,
    allow_insecure_transport_for_localhost,
    get_client_config,
    get_redirect_uri,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_SUCCESS_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
  <div style="text-align: center;">
    <h1>Authentication Successful</h1>
    <p>Your Google Ads account has been connected. You can close this tab.</p>
  </div>
</body>
</html>
"""

_ERROR_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
  <div style="text-align: center;">
    <h1>Authentication Failed</h1>
    <p>{message}</p>
  </div>
</body>
</html>
"""


@router.get("/oauth/callback")
async def oauth_callback(code: str = "", state: str = "") -> HTMLResponse:
    if not code or not state:
        return HTMLResponse(
            _ERROR_HTML.format(message="Missing code or state parameter."),
            status_code=400,
        )

    result = storage.load_pending_auth_by_state(state)
    if result is None:
        return HTMLResponse(
            _ERROR_HTML.format(
                message="Authentication session expired or not found. Please start the flow again."
            ),
            status_code=400,
        )

    user_id, pending = result

    try:
        client_config = get_client_config()
    except KeyError:
        return HTMLResponse(
            _ERROR_HTML.format(message="Server configuration error."),
            status_code=500,
        )

    redirect_uri = get_redirect_uri()
    allow_insecure_transport_for_localhost(redirect_uri)

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config=client_config,
        scopes=pending["scopes"],
        state=pending["state"],
        code_verifier=pending["code_verifier"],
    )
    flow.redirect_uri = redirect_uri

    try:
        flow.fetch_token(code=code)
    except Exception as e:
        logger.exception("OAuth token exchange failed")
        return HTMLResponse(
            _ERROR_HTML.format(message=f"Token exchange failed: {e}"),
            status_code=500,
        )

    credentials = flow.credentials

    requested = set(pending["scopes"])
    granted = set(credentials.granted_scopes or [])
    missing = requested - granted
    if missing:
        return HTMLResponse(
            _ERROR_HTML.format(
                message=f"Google did not grant all required scopes. Missing: {', '.join(sorted(missing))}"
            ),
            status_code=400,
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
    storage.save_tokens(user_id, credentials_data)
    storage.clear_pending_auth(user_id)

    return HTMLResponse(_SUCCESS_HTML)
