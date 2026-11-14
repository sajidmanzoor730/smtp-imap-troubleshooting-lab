import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

from maillab.cli import main
from maillab.mock import SmtpMock


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def test_explain_text(self):
        code, out = run("explain", "454", "4.7.0", "TLS", "not", "available")
        self.assertEqual(code, 0)
        self.assertIn("TLS", out)
        self.assertIn("Next steps", out)

    def test_explain_json(self):
        _, out = run("explain", "535", "--json")
        self.assertEqual(json.loads(out)["category"], "auth")

    def test_smtp_probe_json_and_exit_code(self):
        with SmtpMock("starttls_unavailable") as srv:
            code, out = run("smtp", "127.0.0.1", "--port", str(srv.port), "--timeout", "3", "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["diagnosis"]["code"], 454)

    def test_smtp_probe_success_exit_zero(self):
        with SmtpMock("ok") as srv:
            code, _ = run("smtp", "127.0.0.1", "--port", str(srv.port), "--mode", "plain", "--timeout", "3")
        self.assertEqual(code, 0)

    def test_password_read_from_environment(self):
        os.environ["MAILLAB_TEST_PW"] = "secret"
        try:
            with SmtpMock("ok") as srv:
                code, out = run("smtp", "127.0.0.1", "--port", str(srv.port), "--mode", "plain",
                                "--user", "lab", "--password-env", "MAILLAB_TEST_PW",
                                "--allow-insecure-auth", "--timeout", "3")
        finally:
            del os.environ["MAILLAB_TEST_PW"]
        self.assertEqual(code, 0, out)
        self.assertNotIn("secret", out)

    def test_oauth2_token_read_from_environment_and_redacted(self):
        os.environ["MAILLAB_TEST_TOKEN"] = "mock-access-token"
        try:
            with SmtpMock("ok") as srv:
                code, out = run("smtp", "127.0.0.1", "--port", str(srv.port), "--mode", "plain",
                                "--user", "lab", "--oauth2-token-env", "MAILLAB_TEST_TOKEN",
                                "--allow-insecure-auth", "--timeout", "3")
        finally:
            del os.environ["MAILLAB_TEST_TOKEN"]
        self.assertEqual(code, 0, out)
        self.assertNotIn("mock-access-token", out)
        self.assertIn("AUTH XOAUTH2 <bearer token hidden>", out)

    @patch("maillab.cli.refresh_access_token", return_value="mock-access-token")
    def test_refresh_token_env_is_exchanged_without_logging_secrets(self, refresh):
        os.environ["MAILLAB_TEST_REFRESH"] = "refresh-secret"
        os.environ["MAILLAB_TEST_CLIENT"] = "client-id"
        os.environ["MAILLAB_TEST_CLIENT_SECRET"] = "client-secret"
        try:
            with SmtpMock("ok") as srv:
                code, out = run(
                    "smtp", "127.0.0.1", "--port", str(srv.port), "--mode", "plain",
                    "--user", "lab", "--oauth2-refresh-token-env", "MAILLAB_TEST_REFRESH",
                    "--oauth2-token-url", "https://oauth.example.test/token",
                    "--oauth2-client-id-env", "MAILLAB_TEST_CLIENT",
                    "--oauth2-client-secret-env", "MAILLAB_TEST_CLIENT_SECRET",
                    "--allow-insecure-auth", "--timeout", "3",
                )
        finally:
            for name in ("MAILLAB_TEST_REFRESH", "MAILLAB_TEST_CLIENT", "MAILLAB_TEST_CLIENT_SECRET"):
                os.environ.pop(name, None)
        self.assertEqual(code, 0, out)
        self.assertNotIn("refresh-secret", out)
        self.assertNotIn("client-secret", out)
        refresh.assert_called_once()

    def test_missing_password_env_exits(self):
        with self.assertRaises(SystemExit):
            run("smtp", "127.0.0.1", "--user", "lab", "--password-env", "MAILLAB_DOES_NOT_EXIST")


if __name__ == "__main__":
    unittest.main()
