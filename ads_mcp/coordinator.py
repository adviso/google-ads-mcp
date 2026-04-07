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

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from ads_mcp.environment import environment
from ads_mcp.workos_auth import WorkOSTokenVerifier

_logger = logging.getLogger(__name__)
_auth_kwargs = {}

_name = "Google Ads Server"
_host = "0.0.0.0"
_port = int(environment.get("GOOGLE_ADS_MCP_SERVER_PORT") or 8000)
_issuer_url = str(environment.get("WORKOS_AUTHKIT_ISSUER_URL"))
_server_url = str(environment.get("GOOGLE_ADS_MCP_SERVER_URL"))
_is_local = environment.get("ENV") == "local"

if _is_local:
    mcp = FastMCP(
        _name,
        host=_host,
        port=_port,
    )
else:
    mcp = FastMCP(
        _name,
        host=_host,
        port=_port,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(_issuer_url),
            resource_server_url=AnyHttpUrl(_server_url),
            required_scopes=[],
        ),
        token_verifier=WorkOSTokenVerifier(issuer_url=_issuer_url),
    )
