import json
import subprocess
import sys
import threading
import os
from typing import Any, Dict, List, Optional


def start_server_process() -> subprocess.Popen:
    """Starts the MCP server as a subprocess."""
    return subprocess.Popen(
        [sys.executable, "-m", "ads_mcp.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=0,  # Unbuffered
    )


def send_request(
    process: subprocess.Popen,
    method: str,
    params: Optional[Dict[str, Any]] = None,
    req_id: Optional[int] = 1,
) -> None:
    """Sends a JSON-RPC request or notification to the server."""
    request = {
        "jsonrpc": "2.0",
        "method": method,
    }
    if req_id is not None:
        request["id"] = req_id

    if params:
        request["params"] = params

    json_req = json.dumps(request)
    process.stdin.write(json_req + "\n")
    process.stdin.flush()


def read_response(process: subprocess.Popen) -> Dict[str, Any]:
    """Reads a JSON-RPC response from the server."""
    for line in process.stdout:
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    raise RuntimeError("Server closed connection without response")


def get_tools_list() -> Dict[str, Any]:
    """Runs the server and retrieves the list of tools."""
    process = start_server_process()
    try:
        # Initialize
        send_request(
            process,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
            req_id=1,
        )

        # Read initialize response
        response = read_response(process)
        if "error" in response:
            raise RuntimeError(f"Initialize failed: {response['error']}")

        # Send initialized notification
        send_request(
            process, "notifications/initialized", req_id=None
        )  # Notifications don't have ID, but send_request adds it.
        # Actually notifications shouldn't have ID. Let's send manually or adjust send_request.
        # But for this simple smoke test, we can just skip the notification usually, or send it correctly.
        # Let's just request tools/list.

        send_request(process, "tools/list", req_id=2)
        response = read_response(process)

        if "error" in response:
            raise RuntimeError(f"tools/list failed: {response['error']}")

        return response["result"]
    finally:
        if process.stdin:
            process.stdin.close()
        if process.stdout:
            process.stdout.close()
        process.terminate()
        process.wait()


def inject_customer_id(prompt: str) -> str:
    """Replaces {customer_id} placeholder with GOOGLE_ADS_CUSTOMER_ID env var."""
    customer_id = os.environ.get("GOOGLE_ADS_CUSTOMER_ID", "1234567890")
    return prompt.replace("{customer_id}", customer_id)


def call_tool(name: str, arguments: dict) -> Dict[str, Any]:
    """Runs the server and calls a specific tool."""
    process = start_server_process()
    try:
        # Initialize
        send_request(
            process,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
            req_id=1,
        )

        # Read initialize response
        response = read_response(process)
        if "error" in response:
            raise RuntimeError(f"Initialize failed: {response['error']}")

        # Send initialized notification
        send_request(process, "notifications/initialized", req_id=None)

        # Call tool
        send_request(
            process,
            "tools/call",
            {"name": name, "arguments": arguments},
            req_id=2,
        )
        response = read_response(process)

        if "error" in response:
            raise RuntimeError(f"tools/call failed: {response['error']}")

        return response["result"]
    finally:
        if process.stdin:
            process.stdin.close()
        if process.stdout:
            process.stdout.close()
        process.terminate()
        process.wait()
