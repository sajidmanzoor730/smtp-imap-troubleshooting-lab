import json
import unittest
from unittest.mock import patch

from maillab.oauth import OAuthTokenError, refresh_access_token


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class OAuthRefreshTests(unittest.TestCase):
    @patch("maillab.oauth.urlopen")
    def test_refresh_token_exchange(self, urlopen):
        urlopen.return_value = _Response({"access_token": "fresh-token", "expires_in": 3600})
        token = refresh_access_token(
            "https://oauth.example.test/token", "client-id", "refresh-secret",
            "client-secret", "mail.scope",
        )
        self.assertEqual(token, "fresh-token")
        request = urlopen.call_args.args[0]
        body = request.data.decode()
        self.assertIn("grant_type=refresh_token", body)
        self.assertIn("refresh_token=refresh-secret", body)
        self.assertIn("client_secret=client-secret", body)
        self.assertNotIn("refresh-secret", repr(request.headers))

    def test_rejects_non_https_endpoint(self):
        with self.assertRaisesRegex(OAuthTokenError, "HTTPS"):
            refresh_access_token("http://oauth.example.test/token", "id", "refresh")

    @patch("maillab.oauth.urlopen")
    def test_missing_access_token_is_safe_error(self, urlopen):
        urlopen.return_value = _Response({"error": "invalid_grant"})
        with self.assertRaisesRegex(OAuthTokenError, "invalid_grant"):
            refresh_access_token("https://oauth.example.test/token", "id", "refresh")


if __name__ == "__main__":
    unittest.main()
