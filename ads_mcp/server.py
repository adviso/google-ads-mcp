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

"""Entry point for the MCP server."""

import asyncio
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from ads_mcp.coordinator import mcp
from ads_mcp.environment import environment
from ads_mcp.oauth_callback import router as oauth_router
import ads_mcp.storage as storage

# The following imports are necessary to register the tools with the `mcp`
# object, even though they are not directly used in this file.
# The `# noqa: F401` comment tells the linter to ignore the "unused import"
# warning.
from ads_mcp.tools import auth, search, core, get_resource_metadata  # noqa: F401
from ads_mcp.resources import (
    discovery,
    metrics,
    release_notes,
    segments,
)  # noqa: F401

# Build the MCP Starlette app (lazily initializes the session manager).
mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(lifespan=lifespan)
app.include_router(oauth_router)
app.mount("/", mcp_app)


def run_server() -> None:
    storage.init_db()
    port = int(environment.get("GOOGLE_ADS_MCP_SERVER_PORT") or 8000)
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    asyncio.run(server.serve())


if __name__ == "__main__":
    run_server()
