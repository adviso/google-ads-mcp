# Copyright 2026 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module declaring the singleton MCP instance.

The singleton allows other modules to register their tools with the same MCP
server using `@mcp.tool` annotations, thereby 'coordinating' the bootstrapping
of the server.
"""

import logging
import os

from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)
_auth_kwargs = {}

_issuer_url = os.getenv("WORKOS_AUTHKIT_ISSUER_URL")
_server_url = os.getenv("GOOGLE_ADS_MCP_SERVER_URL")

if bool(_issuer_url) != bool(_server_url):
    _logger.warning(
        "Partial WorkOS auth config: WORKOS_AUTHKIT_ISSUER_URL=%s, "
        "GOOGLE_ADS_MCP_SERVER_URL=%s. Auth will NOT be enabled.",
        "set" if _issuer_url else "missing",
        "set" if _server_url else "missing",
    )

if _issuer_url and _server_url:
    from pydantic import AnyHttpUrl
    from mcp.server.auth.settings import AuthSettings
    from ads_mcp.workos_auth import WorkOSTokenVerifier

    _auth_kwargs = {
        "auth": AuthSettings(
            issuer_url=AnyHttpUrl(_issuer_url),
            resource_server_url=AnyHttpUrl(_server_url),
            required_scopes=[],
        ),
        "token_verifier": WorkOSTokenVerifier(issuer_url=_issuer_url),
    }

mcp = FastMCP(
    "Google Ads Server",
    host="0.0.0.0",
    port=int(os.getenv("GOOGLE_ADS_MCP_PORT", "8000")),
    **_auth_kwargs,
)
