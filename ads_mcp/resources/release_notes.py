"""Release notes resource."""

import urllib.request

from ads_mcp.coordinator import mcp


@mcp.resource(
    uri="resource://release-notes",
    mime_type="text/html",
    annotations={"readOnlyHint": True, "idempotentHint": True},
)
def get_release_notes() -> str:
    """Retrieve the Google Ads API release notes.

    Provides the official release notes for the Google Ads API, detailing new
    features, changes, deprecations, and bug fixes across all API versions.
    Host LLMs should access this resource to check for breaking changes,
    determine if a specific feature is supported in a given API version, or
    troubleshoot issues by consulting recent API updates.

    Returns:
        str: The release notes in HTML format.
    """
    url = "https://developers.google.com/google-ads/api/docs/release-notes"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(req) as response:
        return response.read().decode("utf-8")
