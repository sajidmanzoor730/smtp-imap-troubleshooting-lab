import unittest

from maillab.imap import ImapProbe
from maillab.mock import ImapMock


def probe(server, **kw):
    kw.setdefault("timeout", 3.0)
    kw.setdefault("mode", "plain")
    return ImapProbe("127.0.0.1", server.port, **kw).run()


class ImapProbeTests(unittest.TestCase):
    def test_login_and_select(self):
        with ImapMock("ok") as srv:
            r = probe(srv, username="lab", password="secret", allow_insecure_auth=True)
        self.assertTrue(r.ok, r.to_text())
        self.assertIn("IMAP4rev1", r.capabilities)

    def test_xoauth2_login_and_token_redaction(self):
        with ImapMock("ok") as srv:
            r = probe(srv, username="lab", bearer_token="mock-access-token", allow_insecure_auth=True)
        self.assertTrue(r.ok, r.to_text())
        self.assertIn("AUTHENTICATE XOAUTH2 <bearer token hidden>", r.to_text())
        self.assertNotIn("mock-access-token", r.to_text())

    def test_bad_login_is_auth_category(self):
        with ImapMock("ok") as srv:
            r = probe(srv, username="lab", password="wrong", allow_insecure_auth=True)
        self.assertFalse(r.ok)
        self.assertEqual(r.diagnosis.category, "auth")

    def test_refuses_plain_credentials(self):
        with ImapMock("ok") as srv:
            r = probe(srv, username="lab", password="secret")
        self.assertEqual(r.failed_at, "login")

    def test_blackhole_times_out(self):
        with ImapMock("blackhole") as srv:
            r = probe(srv, timeout=0.5)
        self.assertFalse(r.ok)
        self.assertEqual(r.diagnosis.category, "network")


if __name__ == "__main__":
    unittest.main()
