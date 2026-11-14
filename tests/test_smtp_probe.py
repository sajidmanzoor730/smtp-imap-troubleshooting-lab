import unittest

from maillab.mock import SmtpMock
from maillab.smtp import SmtpProbe

from .helpers import make_tls_context


def probe(server, **kw):
    kw.setdefault("timeout", 3.0)
    kw.setdefault("mode", "plain")
    return SmtpProbe("127.0.0.1", server.port, **kw).run()


class PlainModeTests(unittest.TestCase):
    def test_healthy_server_full_envelope(self):
        with SmtpMock("ok") as srv:
            r = probe(srv, username="lab", password="secret", allow_insecure_auth=True,
                      mail_from="a@example.test", rcpt_to="b@example.test")
        self.assertTrue(r.ok, r.to_text())
        self.assertIn("AUTH LOGIN", r.capabilities)

    def test_credentials_refused_without_tls(self):
        with SmtpMock("ok") as srv:
            r = probe(srv, username="lab", password="secret")
        self.assertFalse(r.ok)
        self.assertEqual(r.failed_at, "auth")
        self.assertIn("unencrypted", r.diagnosis.summary)

    def test_wrong_password_gives_535_auth(self):
        with SmtpMock("ok") as srv:
            r = probe(srv, username="lab", password="nope", allow_insecure_auth=True)
        self.assertFalse(r.ok)
        self.assertEqual(r.diagnosis.code, 535)
        self.assertEqual(r.diagnosis.category, "auth")

    def test_auth_fail_mode(self):
        with SmtpMock("auth_fail") as srv:
            r = probe(srv, username="lab", password="secret", allow_insecure_auth=True)
        self.assertEqual(r.diagnosis.code, 535)

    def test_password_never_in_transcript(self):
        with SmtpMock("ok") as srv:
            r = probe(srv, username="lab", password="secret", allow_insecure_auth=True)
        self.assertNotIn("c2VjcmV0", r.to_text())  # base64("secret")
        self.assertIn("<password hidden>", r.to_text())

    def test_relay_denied(self):
        with SmtpMock("relay_denied") as srv:
            r = probe(srv, mail_from="a@example.test", rcpt_to="b@example.test")
        self.assertEqual(r.failed_at, "rcpt to")
        self.assertIn("Relay denied", r.diagnosis.summary)

    def test_greylist(self):
        with SmtpMock("greylist") as srv:
            r = probe(srv, mail_from="a@example.test", rcpt_to="b@example.test")
        self.assertEqual(r.diagnosis.category, "transient")

    def test_banner_421(self):
        with SmtpMock("banner_421") as srv:
            r = probe(srv)
        self.assertEqual(r.failed_at, "banner")
        self.assertEqual(r.diagnosis.code, 421)

    def test_no_auth_advertised(self):
        with SmtpMock("no_auth") as srv:
            r = probe(srv, username="lab", password="secret", allow_insecure_auth=True)
        self.assertEqual(r.failed_at, "auth")

    def test_blackhole_times_out_after_connect(self):
        with SmtpMock("blackhole") as srv:
            r = probe(srv, timeout=0.5)
        self.assertFalse(r.ok)
        self.assertEqual(r.failed_at, "banner")
        self.assertEqual(r.diagnosis.category, "network")

    def test_connection_refused(self):
        with SmtpMock("ok") as srv:
            port = srv.port
        r = SmtpProbe("127.0.0.1", port, "plain", timeout=1.0).run()
        self.assertEqual(r.failed_at, "tcp connect")
        self.assertEqual(r.diagnosis.summary, "Connection refused")


class StarttlsFailureTests(unittest.TestCase):
    """The failure class from the voicemail-to-email case study."""

    def test_454_on_starttls(self):
        with SmtpMock("starttls_unavailable") as srv:
            r = probe(srv, mode="starttls")
        self.assertEqual(r.failed_at, "starttls")
        self.assertEqual(r.diagnosis.code, 454)
        self.assertEqual(r.diagnosis.category, "tls")

    def test_reset_during_starttls(self):
        with SmtpMock("starttls_reset") as srv:
            r = probe(srv, mode="starttls")
        self.assertFalse(r.ok)
        self.assertEqual(r.failed_at, "starttls")
        self.assertEqual(r.diagnosis.category, "network")

    def test_starttls_not_advertised(self):
        with SmtpMock("ok") as srv:
            r = probe(srv, mode="starttls")
        self.assertEqual(r.failed_at, "starttls")
        self.assertIn("does not advertise", r.diagnosis.summary)


class RealTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = make_tls_context()
        if cls.ctx is None:
            raise unittest.SkipTest("openssl not available")

    def test_starttls_then_auth(self):
        with SmtpMock("ok", tls_context=self.ctx) as srv:
            r = probe(srv, mode="starttls", username="lab", password="secret", verify_tls=False,
                      mail_from="a@example.test", rcpt_to="b@example.test")
        self.assertTrue(r.ok, r.to_text())
        self.assertTrue(r.tls_version.startswith("TLS"))

    def test_certificate_verification_failure_on_self_signed(self):
        with SmtpMock("ok", tls_context=self.ctx) as srv:
            r = probe(srv, mode="starttls", verify_tls=True)
        self.assertFalse(r.ok)
        self.assertIn("certificate", r.diagnosis.summary.lower())

    def test_implicit_tls(self):
        with SmtpMock("ok", tls_context=self.ctx, implicit_tls=True) as srv:
            r = probe(srv, mode="implicit", username="lab", password="secret", verify_tls=False)
        self.assertTrue(r.ok, r.to_text())

    def test_auth_before_starttls_gets_530(self):
        with SmtpMock("ok", tls_context=self.ctx) as srv:
            r = probe(srv, mode="plain", username="lab", password="secret", allow_insecure_auth=True)
        self.assertEqual(r.diagnosis.code, 530)


if __name__ == "__main__":
    unittest.main()
