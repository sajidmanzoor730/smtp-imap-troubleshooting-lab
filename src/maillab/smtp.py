"""Step-by-step SMTP probe that records the full client/server exchange.

The transcript mirrors what Wireshark shows (banner, EHLO, STARTTLS, AUTH,
MAIL FROM, RCPT TO), so a probe run can be compared side by side with a
packet capture of the same session.
"""

from __future__ import annotations

import base64
import socket
import ssl
import time

from .errors import (
    classify,
    classify_network,
    diagnose_insecure_auth,
    diagnose_no_starttls,
)
from .result import ProbeResult, Step

MODES = ("starttls", "implicit", "plain")


class _Conn:
    """Line-oriented reader/writer for SMTP replies on a socket."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self._buf = b""

    def _readline(self) -> str:
        while b"\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed by server")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\r\n", 1)
        return line.decode("utf-8", "replace")

    def read_reply(self) -> tuple[int, list[str]]:
        lines: list[str] = []
        while True:
            line = self._readline()
            lines.append(line)
            if len(line) < 4 or line[3] != "-":
                break
        try:
            code = int(lines[-1][:3])
        except ValueError as exc:
            raise ConnectionError(f"malformed SMTP reply: {lines[-1]!r}") from exc
        return code, lines

    def send(self, command: str) -> None:
        self.sock.sendall(command.encode("utf-8") + b"\r\n")


class SmtpProbe:
    def __init__(
        self,
        host: str,
        port: int = 587,
        mode: str = "starttls",
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
        helo: str = "maillab.local",
        mail_from: str | None = None,
        rcpt_to: str | None = None,
        verify_tls: bool = True,
        allow_insecure_auth: bool = False,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.host = host
        self.port = port
        self.mode = mode
        self.username = username
        self.password = password
        self.timeout = timeout
        self.helo = helo
        self.mail_from = mail_from
        self.rcpt_to = rcpt_to
        self.verify_tls = verify_tls
        self.allow_insecure_auth = allow_insecure_auth
        self._sock: socket.socket | None = None
        self._conn: _Conn | None = None
        self._stage = "tcp connect"
        self._encrypted = False

    # -- public -----------------------------------------------------------

    def run(self) -> ProbeResult:
        result = ProbeResult("smtp", self.host, self.port, self.mode)
        try:
            self._run(result)
        except Exception as exc:  # noqa: BLE001 - classified below
            result.fail(self._stage, classify_network(exc, self._stage), f"{type(exc).__name__}: {exc}")
        finally:
            self._close()
        return result

    # -- internals --------------------------------------------------------

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _wrap(self, sock: socket.socket) -> ssl.SSLSocket:
        return self._context().wrap_socket(sock, server_hostname=self.host)

    def _close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _cmd(
        self,
        result: ProbeResult,
        label: str,
        command: str,
        expect: set[int],
        shown: str | None = None,
    ) -> tuple[bool, int, list[str]]:
        assert self._conn is not None
        self._stage = label
        start = time.monotonic()
        self._conn.send(command)
        code, lines = self._conn.read_reply()
        ok = code in expect
        result.add(Step(label, shown or command, code, lines, (time.monotonic() - start) * 1000, ok))
        if not ok:
            result.fail(label, classify(code, " ".join(lines)))
        return ok, code, lines

    def _capabilities(self, lines: list[str]) -> list[str]:
        return [line[4:].strip() for line in lines[1:]]

    def _run(self, result: ProbeResult) -> None:
        start = time.monotonic()
        self._stage = "tcp connect"
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock = sock
        result.add(
            Step("tcp connect", None, None, [f"connected to {self.host}:{self.port}"], (time.monotonic() - start) * 1000)
        )

        if self.mode == "implicit":
            self._stage = "tls handshake"
            start = time.monotonic()
            tls_sock = self._wrap(sock)
            self._sock = sock = tls_sock
            self._encrypted = True
            result.tls_version = tls_sock.version()
            result.add(
                Step("tls handshake", None, None, [f"{result.tls_version}, cipher {tls_sock.cipher()[0]}"], (time.monotonic() - start) * 1000)
            )

        self._conn = _Conn(sock)

        self._stage = "banner"
        start = time.monotonic()
        code, lines = self._conn.read_reply()
        ok = code == 220
        result.add(Step("banner", None, code, lines, (time.monotonic() - start) * 1000, ok))
        if not ok:
            result.fail("banner", classify(code, " ".join(lines)))
            return

        ok, _, lines = self._cmd(result, "ehlo", f"EHLO {self.helo}", {250})
        if not ok:
            return
        result.capabilities = self._capabilities(lines)

        if self.mode == "starttls":
            if not any(c.upper() == "STARTTLS" for c in result.capabilities):
                result.fail("starttls", diagnose_no_starttls())
                return
            ok, _, _ = self._cmd(result, "starttls", "STARTTLS", {220})
            if not ok:
                return
            self._stage = "tls handshake"
            start = time.monotonic()
            assert self._sock is not None
            tls_sock = self._wrap(self._sock)
            self._sock = tls_sock
            self._conn = _Conn(tls_sock)
            self._encrypted = True
            result.tls_version = tls_sock.version()
            result.add(
                Step("tls handshake", None, None, [f"{result.tls_version}, cipher {tls_sock.cipher()[0]}"], (time.monotonic() - start) * 1000)
            )
            ok, _, lines = self._cmd(result, "ehlo (after tls)", f"EHLO {self.helo}", {250})
            if not ok:
                return
            result.capabilities = self._capabilities(lines)

        if self.username is not None and self.password is not None:
            if not self._authenticate(result):
                return

        if self.mail_from and self.rcpt_to:
            if not self._envelope(result):
                return

        self._stage = "quit"
        try:
            self._cmd(result, "quit", "QUIT", {221})
            if not result.ok and result.failed_at == "quit":
                # A failing QUIT is cosmetic; do not fail the probe on it.
                result.ok, result.failed_at, result.diagnosis = True, None, None
        except OSError:
            pass

    def _authenticate(self, result: ProbeResult) -> bool:
        assert self.username is not None and self.password is not None
        if not self._encrypted and not self.allow_insecure_auth:
            result.fail("auth", diagnose_insecure_auth())
            return False
        if not any(c.upper().startswith("AUTH") for c in result.capabilities):
            result.fail("auth", classify(504, "5.5.4 AUTH not advertised by server"))
            return False
        ok, _, _ = self._cmd(result, "auth login", "AUTH LOGIN", {334})
        if not ok:
            return False
        user_b64 = base64.b64encode(self.username.encode()).decode()
        ok, _, _ = self._cmd(result, "auth username", user_b64, {334}, shown="<username, base64>")
        if not ok:
            return False
        pass_b64 = base64.b64encode(self.password.encode()).decode()
        ok, _, _ = self._cmd(result, "auth password", pass_b64, {235}, shown="<password hidden>")
        return ok

    def _envelope(self, result: ProbeResult) -> bool:
        ok, _, _ = self._cmd(result, "mail from", f"MAIL FROM:<{self.mail_from}>", {250})
        if not ok:
            return False
        ok, _, _ = self._cmd(result, "rcpt to", f"RCPT TO:<{self.rcpt_to}>", {250, 251})
        if not ok:
            return False
        ok, _, _ = self._cmd(result, "rset", "RSET", {250})
        return ok
