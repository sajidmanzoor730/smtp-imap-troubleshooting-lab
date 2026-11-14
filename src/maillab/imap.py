"""IMAP probe: connect, capabilities, optional TLS, login and read-only mailbox select."""

from __future__ import annotations

import imaplib
import ssl
import time

from .errors import classify_imap, classify_network, diagnose_insecure_auth, diagnose_no_starttls
from .result import ProbeResult, Step

MODES = ("ssl", "starttls", "plain")


class ImapProbe:
    def __init__(
        self,
        host: str,
        port: int | None = None,
        mode: str = "ssl",
        username: str | None = None,
        password: str | None = None,
        mailbox: str = "INBOX",
        timeout: float = 10.0,
        verify_tls: bool = True,
        allow_insecure_auth: bool = False,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.host = host
        self.port = port if port is not None else (993 if mode == "ssl" else 143)
        self.mode = mode
        self.username = username
        self.password = password
        self.mailbox = mailbox
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.allow_insecure_auth = allow_insecure_auth
        self._stage = "tcp connect"
        self._client: imaplib.IMAP4 | None = None

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def run(self) -> ProbeResult:
        result = ProbeResult("imap", self.host, self.port, self.mode)
        try:
            self._run(result)
        except imaplib.IMAP4.error as exc:
            result.fail(self._stage, classify_imap(str(exc)), f"IMAP4.error: {exc}")
        except Exception as exc:  # noqa: BLE001 - classified below
            result.fail(self._stage, classify_network(exc, self._stage), f"{type(exc).__name__}: {exc}")
        finally:
            self._close()
        return result

    def _close(self) -> None:
        client, self._client = self._client, None
        if client is None:
            return
        try:
            client.logout()
        except Exception:  # noqa: BLE001
            try:
                client.shutdown()
            except Exception:  # noqa: BLE001
                pass

    def _run(self, result: ProbeResult) -> None:
        start = time.monotonic()
        self._stage = "tcp connect"
        if self.mode == "ssl":
            self._stage = "tls handshake"
            client: imaplib.IMAP4 = imaplib.IMAP4_SSL(
                self.host, self.port, ssl_context=self._context(), timeout=self.timeout
            )
            result.tls_version = client.socket().version()
        else:
            client = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
        self._client = client
        greeting = client.welcome.decode("utf-8", "replace")
        result.add(Step("connect and greeting", None, None, [greeting], (time.monotonic() - start) * 1000))

        self._stage = "capability"
        start = time.monotonic()
        _, data = client.capability()
        caps = data[0].decode().split()
        result.capabilities = caps
        result.add(Step("capability", "CAPABILITY", None, [" ".join(caps)], (time.monotonic() - start) * 1000))

        if self.mode == "starttls":
            self._stage = "starttls"
            start = time.monotonic()
            if "STARTTLS" not in caps:
                result.fail("starttls", diagnose_no_starttls())
                return
            client.starttls(self._context())
            result.tls_version = client.socket().version()
            result.add(Step("starttls", "STARTTLS", None, [result.tls_version or ""], (time.monotonic() - start) * 1000))

        if self.username is not None and self.password is not None:
            encrypted = self.mode in ("ssl", "starttls")
            if not encrypted and not self.allow_insecure_auth:
                result.fail("login", diagnose_insecure_auth())
                return
            self._stage = "login"
            start = time.monotonic()
            _, data = client.login(self.username, self.password)
            result.add(
                Step("login", "LOGIN <user> <password hidden>", None, [d.decode() for d in data], (time.monotonic() - start) * 1000)
            )

            self._stage = "select"
            start = time.monotonic()
            _, data = client.select(self.mailbox, readonly=True)
            result.add(
                Step("select (read-only)", f"EXAMINE {self.mailbox}", None, [f"{data[0].decode()} messages"], (time.monotonic() - start) * 1000)
            )
