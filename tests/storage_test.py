"""Test cases for the SQLite encrypted storage module."""

import base64
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

import ads_mcp.storage as storage


def _make_test_key() -> str:
    """Generate a valid base64-encoded 32-byte key for tests."""
    return base64.b64encode(os.urandom(32)).decode()


class TestStorage(unittest.TestCase):
    """Test cases for ads_mcp.storage."""

    def setUp(self):
        self.test_key = _make_test_key()
        self.env_patch = mock.patch.dict(
            "os.environ", {"ENCRYPTION_KEY": self.test_key}
        )
        self.env_patch.start()
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db_path = self._tmp.name
        storage.init_db(db_path=self.db_path)

    def tearDown(self):
        self.env_patch.stop()
        # Reset module state
        storage._db_path = None
        storage._encryption_key = None
        os.unlink(self.db_path)

    def test_init_db_creates_tables(self):
        """Tables user_credentials and pending_auth exist after init."""
        conn = storage._get_connection()
        try:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        finally:
            conn.close()
        table_names = [t[0] for t in tables]
        self.assertIn("user_credentials", table_names)
        self.assertIn("pending_auth", table_names)

    def test_init_db_raises_without_encryption_key(self):
        """init_db raises ValueError when ENCRYPTION_KEY is not set."""
        storage._encryption_key = None
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError) as cm:
                storage.init_db(db_path=":memory:")
            self.assertIn("ENCRYPTION_KEY environment variable is required", str(cm.exception))

    def test_init_db_raises_with_invalid_key_size(self):
        """init_db raises ValueError when key is not 32 bytes."""
        storage._encryption_key = None
        bad_key = base64.b64encode(os.urandom(16)).decode()
        with mock.patch.dict("os.environ", {"ENCRYPTION_KEY": bad_key}):
            with self.assertRaises(ValueError) as cm:
                storage.init_db(db_path=":memory:")
            self.assertIn("ENCRYPTION_KEY must be 32 bytes", str(cm.exception))

    def test_save_load_tokens_roundtrip(self):
        """save_tokens then load_tokens returns the same data."""
        data = {"refresh_token": "rt_abc", "client_id": "cid", "client_secret": "cs"}
        storage.save_tokens("user_1", data)
        loaded = storage.load_tokens("user_1")
        self.assertEqual(loaded, data)

    def test_load_tokens_nonexistent_user(self):
        """load_tokens for a non-existent user returns None."""
        self.assertIsNone(storage.load_tokens("nonexistent_user"))

    def test_rejects_unknown_user_id(self):
        """Storage functions reject the placeholder 'unknown' user_id."""
        with self.assertRaises(ValueError):
            storage.save_tokens("unknown", {"token": "x"})
        with self.assertRaises(ValueError):
            storage.load_tokens("unknown")

    def test_rejects_empty_user_id(self):
        """Storage functions reject empty or None user_id."""
        with self.assertRaises(ValueError):
            storage.save_tokens("", {"token": "x"})
        with self.assertRaises((ValueError, TypeError)):
            storage.save_tokens(None, {"token": "x"})

    def test_save_tokens_upsert(self):
        """Second save_tokens for same user replaces the first."""
        data1 = {"refresh_token": "old"}
        data2 = {"refresh_token": "new"}
        storage.save_tokens("user_1", data1)
        storage.save_tokens("user_1", data2)
        self.assertEqual(storage.load_tokens("user_1"), data2)

    def test_delete_tokens(self):
        """delete_tokens removes the user's credentials."""
        storage.save_tokens("user_1", {"token": "x"})
        storage.delete_tokens("user_1")
        self.assertIsNone(storage.load_tokens("user_1"))

    def test_user_isolation(self):
        """Each user's tokens are isolated from other users."""
        data_a = {"user": "A"}
        data_b = {"user": "B"}
        storage.save_tokens("user_A", data_a)
        storage.save_tokens("user_B", data_b)
        self.assertEqual(storage.load_tokens("user_A"), data_a)
        self.assertEqual(storage.load_tokens("user_B"), data_b)

    def test_encrypted_at_rest(self):
        """Raw encrypted_tokens column is not readable JSON."""
        storage.save_tokens("user_1", {"secret": "value"})
        conn = storage._get_connection()
        try:
            row = conn.execute(
                "SELECT encrypted_tokens FROM user_credentials WHERE user_id = ?",
                ("user_1",),
            ).fetchone()
        finally:
            conn.close()
        raw = row[0]
        # The raw bytes should not be valid JSON
        self.assertIsInstance(raw, bytes)
        with self.assertRaises(Exception):
            import json
            json.loads(raw)

    def test_save_load_pending_auth_roundtrip(self):
        """save_pending_auth then load_pending_auth returns correct data."""
        storage.save_pending_auth("user_1", "state_abc", "verifier_xyz", ["scope1", "scope2"])
        loaded = storage.load_pending_auth("user_1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["state"], "state_abc")
        self.assertEqual(loaded["code_verifier"], "verifier_xyz")
        self.assertEqual(loaded["scopes"], ["scope1", "scope2"])

    def test_load_pending_auth_expired(self):
        """Expired pending_auth entries return None."""
        conn = storage._get_connection()
        try:
            conn.execute(
                """INSERT INTO pending_auth (user_id, state, code_verifier, scopes, created_at, expires_at)
                VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '-1 minute'))""",
                ("user_1", "old_state", "old_verifier", '["scope"]'),
            )
            conn.commit()
        finally:
            conn.close()
        self.assertIsNone(storage.load_pending_auth("user_1"))

    def test_save_pending_auth_cleans_expired(self):
        """save_pending_auth removes expired entries before inserting."""
        conn = storage._get_connection()
        try:
            conn.execute(
                """INSERT INTO pending_auth (user_id, state, code_verifier, scopes, created_at, expires_at)
                VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '-1 minute'))""",
                ("expired_user", "old_state", "old_verifier", '["scope"]'),
            )
            conn.commit()
        finally:
            conn.close()

        storage.save_pending_auth("new_user", "new_state", "new_verifier", ["scope"])

        conn = storage._get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM pending_auth").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 1)

    def test_cross_user_credential_swap_blocked(self):
        """Swapping encrypted tokens between users fails due to AAD binding."""
        from cryptography.exceptions import InvalidTag

        storage.save_tokens("user_A", {"secret": "A"})
        storage.save_tokens("user_B", {"secret": "B"})

        conn = storage._get_connection()
        try:
            row_a = conn.execute(
                "SELECT nonce, encrypted_tokens FROM user_credentials WHERE user_id = ?",
                ("user_A",),
            ).fetchone()
            # Swap user_A's ciphertext into user_B's row
            conn.execute(
                "UPDATE user_credentials SET encrypted_tokens = ?, nonce = ? WHERE user_id = ?",
                (row_a[1], row_a[0], "user_B"),
            )
            conn.commit()
        finally:
            conn.close()

        # Decrypting with user_B's AAD must fail
        with self.assertRaises(InvalidTag):
            storage.load_tokens("user_B")

    def test_clear_pending_auth(self):
        """clear_pending_auth removes the user's pending auth."""
        storage.save_pending_auth("user_1", "state", "verifier", ["scope"])
        storage.clear_pending_auth("user_1")
        self.assertIsNone(storage.load_pending_auth("user_1"))


if __name__ == "__main__":
    unittest.main()
