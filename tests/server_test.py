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

"""Test cases for the server module."""

import unittest
from unittest import mock


class TestServerInitialization(unittest.TestCase):
    """Test cases for the server module."""

    def test_server_initialization(self):
        """Tests that the MCP server instance is initialized.

        This servers as a smoke test to confirm there are no obvious issues
        with initialization, such as missing imports.
        """
        from ads_mcp import server

        self.assertIsNotNone(server.mcp, "MCP server instance not initialized")

    @mock.patch.dict(
        "os.environ",
        {
            "WORKOS_AUTHKIT_ISSUER_URL": "https://test.authkit.app",
            "GOOGLE_ADS_MCP_SERVER_URL": "https://mcp.example.com",
        },
    )
    def test_server_initialization_with_workos_auth(self):
        """Tests that the MCP server initializes with WorkOS auth env vars."""
        import importlib
        from ads_mcp import workos_auth, coordinator, server

        importlib.reload(workos_auth)
        importlib.reload(coordinator)
        importlib.reload(server)

        try:
            self.assertIsNotNone(server.mcp, "MCP server instance not initialized")
            self.assertIsNotNone(
                coordinator._auth_kwargs.get("token_verifier"),
                "token_verifier should be set when WorkOS env vars are present",
            )
        finally:
            # Restore modules to their original state (no auth) to avoid
            # leaking state into other tests.
            importlib.reload(workos_auth)
            importlib.reload(coordinator)
            importlib.reload(server)
