import contextlib
import io
import json
import os
import unittest

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

    def test_missing_password_env_exits(self):
        with self.assertRaises(SystemExit):
            run("smtp", "127.0.0.1", "--user", "lab", "--password-env", "MAILLAB_DOES_NOT_EXIST")


if __name__ == "__main__":
    unittest.main()
