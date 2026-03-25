"""Discovery document resource."""

import urllib.request

from ads_mcp.coordinator import mcp


@mcp.resource(
    uri="resource://discovery-document",
    mime_type="application/json",
    annotations={"readOnlyHint": True, "idempotentHint": True},
)
def get_discovery_document() -> str:
    """Retrieve the Google Ads API discovery document.

    Provides the discovery document for the Google Ads API v23, which
    describes the API surface, including resources, methods, and
    schemas.
    Host LLMs should access this resource to understand the structure of
    the Google Ads API and discover available features.

    Returns:
        str: The discovery document in JSON format.
    """
    url = "https://googleads.googleapis.com/$discovery/rest?version=v23"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(req) as response:
        return response.read().decode("utf-8")
