"""Metrics resource."""

import urllib.request

from ads_mcp.coordinator import mcp


@mcp.resource(
    uri="resource://metrics",
    mime_type="text/html",
    annotations={"readOnlyHint": True, "idempotentHint": True},
)
def get_metrics() -> str:
    """Retrieve the Google Ads API metrics documentation.

    Provides the official documentation for metrics in the Google Ads API,
    listing all available metrics that can be queried to analyze performance
    data.
    Host LLMs should access this resource to identify which metrics are
    available and how they are calculated.

    Returns:
        str: The metrics documentation in HTML format.
    """
    url = "https://developers.google.com/google-ads/api/fields/v23/metrics"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(req) as response:
        return response.read().decode("utf-8")
