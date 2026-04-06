"""JSON file storage for OAuth pending auth and tokens.

Single-user storage with atomic writes and restrictive file permissions.
"""

import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_PENDING_AUTH_FILE = "pending_auth.json"
_TOKENS_FILE = "tokens.json"


def _get_data_dir() -> Path:
    """Return the data directory, creating it if needed."""
    data_dir = Path(os.environ.get("GOOGLE_ADS_MCP_DATA_DIR", "~/.google_ads_mcp")).expanduser()
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def _atomic_write_json(path: Path, data: dict) -> None:
    """Write JSON atomically (tmp + rename) with 600 permissions."""
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp_path, path)
    except BaseException:
        os.unlink(tmp_path)
        raise


def save_pending_auth(state: str, code_verifier: str, scopes: list[str]) -> None:
    """Save pending OAuth auth data."""
    path = _get_data_dir() / _PENDING_AUTH_FILE
    _atomic_write_json(
        path,
        {
            "state": state,
            "code_verifier": code_verifier,
            "scopes": scopes,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )


def load_pending_auth() -> dict | None:
    """Load pending auth data, or None if not found."""
    path = _get_data_dir() / _PENDING_AUTH_FILE
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def clear_pending_auth() -> None:
    """Delete pending auth file if it exists."""
    path = _get_data_dir() / _PENDING_AUTH_FILE
    path.unlink(missing_ok=True)


def save_tokens(credentials_data: dict) -> None:
    """Save OAuth tokens."""
    path = _get_data_dir() / _TOKENS_FILE
    _atomic_write_json(path, credentials_data)


def load_tokens() -> dict | None:
    """Load stored tokens, or None if not found."""
    path = _get_data_dir() / _TOKENS_FILE
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)
