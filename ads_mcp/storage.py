"""SQLite storage for OAuth credentials with AES-256-GCM encryption.

Multi-user storage keyed by WorkOS user ID (JWT sub claim).
"""

import base64
import json
import logging
import os
import sqlite3
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

logger = logging.getLogger(__name__)

_db_path: str | None = None
_encryption_key: bytes | None = None

_SQLITE_BUSY_TIMEOUT_MS = 5000


def _validate_user_id(user_id: str) -> None:
    """Reject None, empty, or placeholder user IDs."""
    if not user_id or user_id == "unknown":
        raise ValueError(
            "Valid user_id required. Received: %r. "
            "Ensure WorkOS authentication is configured." % user_id
        )


def _get_encryption_key() -> bytes:
    """Read and validate ENCRYPTION_KEY from env or GCP Secret Manager."""
    global _encryption_key
    if _encryption_key is not None:
        return _encryption_key

    from ads_mcp.gcp_secrets import require_secret

    raw = require_secret("ENCRYPTION_KEY")

    try:
        key = base64.b64decode(raw)
    except Exception:
        raise ValueError("ENCRYPTION_KEY must be valid base64")

    if len(key) != 32:
        raise ValueError("ENCRYPTION_KEY must be 32 bytes (base64-encoded)")

    _encryption_key = key
    return _encryption_key


def _encrypt(data: dict, user_id: str) -> tuple[bytes, bytes]:
    """Encrypt a dict as JSON using AES-256-GCM. Returns (nonce, ciphertext).

    user_id is bound as AAD to prevent cross-user credential swapping.
    """
    plaintext = json.dumps(data).encode()
    nonce = os.urandom(12)
    ciphertext = AESGCM(_get_encryption_key()).encrypt(
        nonce, plaintext, user_id.encode()
    )
    return nonce, ciphertext


def _decrypt(nonce: bytes, ciphertext: bytes, user_id: str) -> dict:
    """Decrypt AES-256-GCM ciphertext back to a dict.

    user_id must match the AAD used during encryption.
    """
    plaintext = AESGCM(_get_encryption_key()).decrypt(
        nonce, ciphertext, user_id.encode()
    )
    return json.loads(plaintext)


def _get_connection() -> sqlite3.Connection:
    """Open a connection to the database with explicit busy timeout."""
    if _db_path is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return sqlite3.connect(_db_path, timeout=_SQLITE_BUSY_TIMEOUT_MS / 1000)


def init_db(db_path: str | None = None) -> None:
    """Initialize the database: validate key, create tables."""
    global _db_path, _encryption_key
    # Reset cached key so validation runs fresh
    _encryption_key = None
    _get_encryption_key()

    if db_path is None:
        data_dir = Path(
            os.environ.get("GOOGLE_ADS_MCP_DATA_DIR", "~/.google_ads_mcp")
        ).expanduser()
        data_dir.mkdir(parents=True, exist_ok=True)
        # Restrict directory to owner only
        os.chmod(data_dir, stat.S_IRWXU)
        db_path = str(data_dir / "credentials.db")

    _db_path = db_path

    conn = sqlite3.connect(_db_path, timeout=_SQLITE_BUSY_TIMEOUT_MS / 1000)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS user_credentials (
                user_id TEXT PRIMARY KEY,
                encrypted_tokens BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS pending_auth (
                user_id TEXT PRIMARY KEY,
                state TEXT NOT NULL UNIQUE,
                code_verifier TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL
            )"""
        )
        conn.commit()
    finally:
        conn.close()

    # Restrict DB file to owner only (skip for in-memory / test DBs)
    if db_path != ":memory:" and os.path.exists(db_path):
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)


def save_tokens(user_id: str, credentials_data: dict) -> None:
    """Encrypt and store OAuth tokens for a user (upsert)."""
    _validate_user_id(user_id)
    nonce, ciphertext = _encrypt(credentials_data, user_id)
    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO user_credentials (user_id, encrypted_tokens, nonce, created_at, updated_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(user_id) DO UPDATE SET
                encrypted_tokens=excluded.encrypted_tokens,
                nonce=excluded.nonce,
                updated_at=datetime('now')""",
            (user_id, ciphertext, nonce),
        )
        conn.commit()
    finally:
        conn.close()


def load_tokens(user_id: str) -> dict | None:
    """Load and decrypt OAuth tokens for a user, or None if not found."""
    _validate_user_id(user_id)
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT nonce, encrypted_tokens FROM user_credentials WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    return _decrypt(row[0], row[1], user_id)


def delete_tokens(user_id: str) -> None:
    """Delete stored tokens for a user."""
    _validate_user_id(user_id)
    conn = _get_connection()
    try:
        conn.execute("DELETE FROM user_credentials WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def save_pending_auth(
    user_id: str, state: str, code_verifier: str, scopes: list[str]
) -> None:
    """Save pending OAuth auth data with 10-minute TTL. Cleans expired entries."""
    _validate_user_id(user_id)
    conn = _get_connection()
    try:
        conn.execute("DELETE FROM pending_auth WHERE expires_at < datetime('now')")
        conn.execute(
            """INSERT OR REPLACE INTO pending_auth
            (user_id, state, code_verifier, scopes, created_at, expires_at)
            VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+10 minutes'))""",
            (user_id, state, code_verifier, json.dumps(scopes)),
        )
        conn.commit()
    finally:
        conn.close()


def load_pending_auth(user_id: str) -> dict | None:
    """Load pending auth data if not expired, or None."""
    _validate_user_id(user_id)
    conn = _get_connection()
    try:
        row = conn.execute(
            """SELECT state, code_verifier, scopes, created_at
            FROM pending_auth WHERE user_id = ? AND expires_at > datetime('now')""",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    return {
        "state": row[0],
        "code_verifier": row[1],
        "scopes": json.loads(row[2]),
        "created_at": row[3],
    }


def clear_pending_auth(user_id: str) -> None:
    """Delete pending auth for a user."""
    _validate_user_id(user_id)
    conn = _get_connection()
    try:
        conn.execute("DELETE FROM pending_auth WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()
