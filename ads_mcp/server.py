"""Entry point for the MCP server."""

import asyncio
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from google_mcp_common import storage
from google_mcp_common.oauth_callback import make_oauth_callback_router

from ads_mcp.coordinator import mcp
from ads_mcp.environment import environment
from ads_mcp.tools.auth import get_client_config, get_redirect_uri

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


oauth_router = make_oauth_callback_router(
    get_client_config=get_client_config,
    get_redirect_uri=get_redirect_uri,
    product_label="Google Ads",
)

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
