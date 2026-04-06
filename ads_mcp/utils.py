#!/usr/bin/env python

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

"""Common utilities used by the MCP server."""

from typing import Any
import proto
import logging
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.fastmcp import Context
from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.v23.services.services.google_ads_service import (
    GoogleAdsServiceClient,
)

from google.ads.googleads.util import get_nested_attr
from ads_mcp.mcp_header_interceptor import MCPHeaderInterceptor
import ads_mcp.storage as storage
import os
import importlib.resources

# filename for generated field information used by search
_GAQL_FILENAME = "gaql_resources.txt"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Fallback user ID when WorkOS auth is not configured (single-user mode).
_DEFAULT_USER_ID = "default"


def get_user_id(ctx: Context) -> str:
    """Extract authenticated user_id from the verified AccessToken.

    Uses the cryptographically verified AccessToken from the auth middleware
    (WorkOS JWT sub claim), not the unverified ctx.client_id from request _meta.
    Falls back to a single-user default when auth is not active.
    """
    access_token = get_access_token()
    if access_token and access_token.client_id:
        return access_token.client_id
    return _DEFAULT_USER_ID


def _get_developer_token() -> str:
    """Returns the developer token from env or GCP Secret Manager."""
    from ads_mcp.gcp_secrets import require_secret

    return require_secret("GOOGLE_ADS_DEVELOPER_TOKEN")


def _get_login_customer_id() -> str | None:
    """Returns login customer id from env or GCP Secret Manager."""
    from ads_mcp.gcp_secrets import get_secret

    return get_secret("GOOGLE_ADS_LOGIN_CUSTOMER_ID")


def _get_googleads_client(user_id: str) -> GoogleAdsClient:
    tokens = storage.load_tokens(user_id)
    if tokens is None:
        raise RuntimeError(
            "No OAuth tokens found. Run the start_google_ads_auth tool first."
        )
    config = {
        "refresh_token": tokens["refresh_token"],
        "client_id": tokens["client_id"],
        "client_secret": tokens["client_secret"],
        "developer_token": _get_developer_token(),
        "use_proto_plus": True,
    }
    login_customer_id = _get_login_customer_id()
    if login_customer_id:
        config["login_customer_id"] = login_customer_id
    return GoogleAdsClient.load_from_dict(config)


def get_googleads_service(serviceName: str, user_id: str) -> GoogleAdsServiceClient:
    return _get_googleads_client(user_id).get_service(
        serviceName, interceptors=[MCPHeaderInterceptor()]
    )


def get_googleads_type(typeName: str, user_id: str):
    return _get_googleads_client(user_id).get_type(typeName)


def get_googleads_client(user_id: str):
    return _get_googleads_client(user_id)


def format_output_value(value: Any) -> Any:
    if isinstance(value, proto.Enum):
        return value.name
    else:
        return value


def format_output_row(row: proto.Message, attributes):
    return {
        attr: format_output_value(get_nested_attr(row, attr))
        for attr in attributes
    }


def get_gaql_resources_filepath():
    package_root = importlib.resources.files("ads_mcp")
    file_path = package_root.joinpath(_GAQL_FILENAME)
    return file_path
