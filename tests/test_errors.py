import socket
import ssl
import unittest

from maillab.errors import classify, classify_imap, classify_network, enhanced_status


class ClassifyTests(unittest.TestCase):
    def test_454_tls_is_tls_category(self):
        d = classify(454, "4.7.0 TLS not available due to temporary reason")
        self.assertEqual(d.category, "tls")
        self.assertEqual(d.enhanced, "4.7.0")

    def test_454_auth_is_transient(self):
        self.assertEqual(classify(454, "4.7.0 Temporary authentication failure").category, "transient")

    def test_535_is_auth(self):
        self.assertEqual(classify(535, "5.7.8 Authentication credentials invalid").category, "auth")

    def test_530_requires_starttls(self):
        d = classify(530, "5.7.0 Must issue a STARTTLS command first")
        self.assertEqual(d.category, "tls")

    def test_relay_denied_is_policy(self):
        d = classify(554, "5.7.1 Relay access denied")
        self.assertEqual(d.category, "policy")
        self.assertIn("Relay denied", d.summary)

    def test_user_unknown_is_recipient(self):
        self.assertEqual(classify(550, "5.1.1 User unknown").category, "recipient")

    def test_spam_block_is_policy(self):
        self.assertEqual(classify(550, "5.7.1 Message blocked as spam").category, "policy")

    def test_greylist_is_transient(self):
        self.assertEqual(classify(451, "4.7.1 Greylisted").category, "transient")

    def test_size_exceeded(self):
        self.assertEqual(classify(552, "5.3.4 Message size exceeds limit").category, "content")

    def test_generic_fallbacks(self):
        self.assertEqual(classify(499).category, "transient")
        self.assertEqual(classify(599).category, "policy")
        self.assertEqual(classify(250).category, "ok")

    def test_enhanced_status_parsing(self):
        self.assertEqual(enhanced_status("550 5.7.1 nope"), "5.7.1")
        self.assertIsNone(enhanced_status("550 nope"))


class NetworkTests(unittest.TestCase):
    def test_timeout_on_connect_means_filtered(self):
        d = classify_network(socket.timeout(), "tcp connect")
        self.assertIn("blocked or filtered", d.summary)

    def test_refused(self):
        self.assertEqual(classify_network(ConnectionRefusedError()).summary, "Connection refused")

    def test_reset(self):
        self.assertIn("reset", classify_network(ConnectionResetError(), "starttls").summary)

    def test_dns(self):
        self.assertEqual(classify_network(socket.gaierror()).summary, "DNS lookup failed")

    def test_cert_error_before_generic_ssl(self):
        self.assertIn("certificate", classify_network(ssl.SSLCertVerificationError()).summary)

    def test_ssl_eof(self):
        self.assertIn("closed", classify_network(ssl.SSLEOFError()).summary)


class ImapTests(unittest.TestCase):
    def test_auth_failed(self):
        self.assertEqual(classify_imap("[AUTHENTICATIONFAILED] Invalid credentials").category, "auth")

    def test_unavailable(self):
        self.assertEqual(classify_imap("[UNAVAILABLE] Too many connections").category, "transient")


if __name__ == "__main__":
    unittest.main()
