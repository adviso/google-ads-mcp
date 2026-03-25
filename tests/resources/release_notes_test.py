"""Tests for the release_notes resource."""

import unittest
import urllib.request
from unittest import mock

from ads_mcp.resources import release_notes


class ReleaseNotesTest(unittest.TestCase):
    @mock.patch("urllib.request.urlopen")
    def test_get_release_notes(self, mock_urlopen):
        # Setup mock response
        mock_response = mock.MagicMock()
        mock_response.read.return_value = b"Mock release notes content"
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        # Call function
        result = release_notes.get_release_notes()

        # Assertions
        self.assertEqual(result, "Mock release notes content")

        # Verify urlopen was called correctly
        mock_urlopen.assert_called_once()
        args, _ = mock_urlopen.call_args
        request_obj = args[0]

        self.assertIsInstance(request_obj, urllib.request.Request)
        self.assertEqual(
            request_obj.full_url,
            "https://developers.google.com/google-ads/api/docs/release-notes",
        )
        self.assertEqual(request_obj.headers.get("User-agent"), "Mozilla/5.0")
