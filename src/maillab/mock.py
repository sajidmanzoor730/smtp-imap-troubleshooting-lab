"""Fault-injecting mock SMTP and IMAP servers for reproducing failures safely.

Nothing here talks to the internet. Each mode reproduces one real-world failure
so a probe, a packet capture and a runbook can be practised against it.

SMTP modes:
    ok                    healthy server (STARTTLS offered only when a TLS context is given)
    auth_fail             AUTH always returns 535
    starttls_unavailable  STARTTLS advertised, then refused with 454 4.7.0
    starttls_reset        STARTTLS advertised, then the connection is reset (firewall-like)
    banner_421            421 service not available instead of a banner
    relay_denied          RCPT TO refused with 554 5.7.1 relay denied
    greylist              RCPT TO refused with 451 4.7.1 try again later
    blackhole             accepts the TCP connection and never answers
    no_auth               server does not advertise AUTH

Valid test credentials: user "lab", password "secret".
"""

from __future__ import annotations

import asyncio
import base64
import ssl
import threading

SMTP_MODES = (
    "ok",
    "auth_fail",
    "starttls_unavailable",
    "starttls_reset",
    "banner_421",
    "relay_denied",
    "greylist",
    "blackhole",
    "no_auth",
)
IMAP_MODES = ("ok", "auth_fail", "blackhole")

LAB_USER = "lab"
LAB_PASSWORD = "secret"


class _ThreadedServer:
    """Runs an asyncio server on a background thread; usable as a context manager."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, listen_ssl: ssl.SSLContext | None = None) -> None:
        self.host = host
        self.port = port
        self._listen_ssl = listen_ssl
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._thread: threading.Thread | None = None

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:  # pragma: no cover
        raise NotImplementedError

    async def _safe_handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self.handle(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    def start(self) -> "_ThreadedServer":
        ready = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)

            async def main() -> None:
                self._stop = asyncio.Event()
                server = await asyncio.start_server(self._safe_handle, self.host, self.port, ssl=self._listen_ssl)
                self.port = server.sockets[0].getsockname()[1]
                ready.set()
                await self._stop.wait()
                server.close()

            loop.run_until_complete(main())
            loop.close()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        if not ready.wait(5):
            raise RuntimeError("mock server failed to start")
        return self

    def stop(self) -> None:
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread:
            self._thread.join(5)

    def __enter__(self) -> "_ThreadedServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


async def _send(writer: asyncio.StreamWriter, line: str) -> None:
    writer.write(line.encode() + b"\r\n")
    await writer.drain()


class SmtpMock(_ThreadedServer):
    def __init__(
        self,
        mode: str = "ok",
        host: str = "127.0.0.1",
        port: int = 0,
        tls_context: ssl.SSLContext | None = None,
        implicit_tls: bool = False,
    ) -> None:
        if mode not in SMTP_MODES:
            raise ValueError(f"mode must be one of {SMTP_MODES}")
        super().__init__(host, port, tls_context if implicit_tls else None)
        self.mode = mode
        self.tls_context = tls_context
        self.implicit_tls = implicit_tls
        self.transcript: list[str] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._stop is not None
        if self.mode == "blackhole":
            await self._stop.wait()
            return
        if self.mode == "banner_421":
            await _send(writer, "421 4.3.2 Service not available, closing transmission channel")
            return
        await _send(writer, "220 mock.maillab ESMTP ready")
        tls_active = self.implicit_tls
        while True:
            raw = await reader.readline()
            if not raw:
                return
            command = raw.decode("utf-8", "replace").strip()
            self.transcript.append(command)
            verb = command.upper().split(" ", 1)[0]

            if verb in ("EHLO", "HELO"):
                caps = ["mock.maillab", "SIZE 10485760"]
                offers_tls = self.mode in ("starttls_unavailable", "starttls_reset") or (
                    self.tls_context is not None and not tls_active
                )
                if offers_tls and not tls_active:
                    caps.append("STARTTLS")
                if self.mode != "no_auth":
                    caps.append("AUTH LOGIN XOAUTH2")
                for cap in caps[:-1]:
                    await _send(writer, f"250-{cap}")
                await _send(writer, f"250 {caps[-1]}")
            elif verb == "STARTTLS":
                if self.mode == "starttls_unavailable":
                    await _send(writer, "454 4.7.0 TLS not available due to temporary reason")
                elif self.mode == "starttls_reset":
                    writer.transport.abort()
                    return
                elif self.tls_context is not None:
                    await _send(writer, "220 2.0.0 Ready to start TLS")
                    await writer.start_tls(self.tls_context)
                    tls_active = True
                else:
                    await _send(writer, "502 5.5.1 STARTTLS not supported")
            elif verb == "AUTH":
                if self.tls_context is not None and not tls_active:
                    await _send(writer, "530 5.7.0 Must issue a STARTTLS command first")
                elif command.upper() == "AUTH LOGIN":
                    await _send(writer, "334 VXNlcm5hbWU6")
                    user = base64.b64decode((await reader.readline()).strip() or b"").decode("utf-8", "replace")
                    await _send(writer, "334 UGFzc3dvcmQ6")
                    password = base64.b64decode((await reader.readline()).strip() or b"").decode("utf-8", "replace")
                    if self.mode != "auth_fail" and user == LAB_USER and password == LAB_PASSWORD:
                        await _send(writer, "235 2.7.0 Authentication successful")
                    else:
                        await _send(writer, "535 5.7.8 Authentication credentials invalid")
                elif command.upper().startswith("AUTH XOAUTH2 "):
                    try:
                        encoded = command.split(" ", 2)[2]
                        payload = base64.b64decode(encoded, validate=True).decode("utf-8")
                    except (ValueError, UnicodeDecodeError, IndexError):
                        payload = ""
                    expected = f"user={LAB_USER}\\x01auth=Bearer mock-access-token\\x01\\x01"
                    if self.mode != "auth_fail" and payload == expected:
                        await _send(writer, "235 2.7.0 Authentication successful")
                    else:
                        await _send(writer, "535 5.7.8 OAuth2 credentials invalid")
                else:
                    await _send(writer, "504 5.5.4 Unrecognized authentication type")
            elif verb == "MAIL":
                await _send(writer, "250 2.1.0 OK")
            elif verb == "RCPT":
                if self.mode == "relay_denied":
                    await _send(writer, "554 5.7.1 Relay access denied")
                elif self.mode == "greylist":
                    await _send(writer, "451 4.7.1 Greylisted, please try again later")
                else:
                    await _send(writer, "250 2.1.5 OK")
            elif verb == "DATA":
                await _send(writer, "354 End data with <CR><LF>.<CR><LF>")
                while (await reader.readline()).strip() != b".":
                    pass
                await _send(writer, "250 2.0.0 Queued")
            elif verb in ("RSET", "NOOP"):
                await _send(writer, "250 2.0.0 OK")
            elif verb == "QUIT":
                await _send(writer, "221 2.0.0 Bye")
                return
            else:
                await _send(writer, "502 5.5.2 Command not recognized")


class ImapMock(_ThreadedServer):
    def __init__(
        self,
        mode: str = "ok",
        host: str = "127.0.0.1",
        port: int = 0,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        if mode not in IMAP_MODES:
            raise ValueError(f"mode must be one of {IMAP_MODES}")
        super().__init__(host, port, tls_context)
        self.mode = mode
        self.transcript: list[str] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._stop is not None
        if self.mode == "blackhole":
            await self._stop.wait()
            return
        await _send(writer, "* OK [CAPABILITY IMAP4rev1] mock.maillab ready")
        while True:
            raw = await reader.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").strip()
            self.transcript.append(line)
            parts = line.split(" ", 2)
            if len(parts) < 2:
                await _send(writer, "* BAD missing command")
                continue
            tag, verb = parts[0], parts[1].upper()
            args = parts[2] if len(parts) > 2 else ""
            if verb == "CAPABILITY":
                await _send(writer, "* CAPABILITY IMAP4rev1 AUTH=PLAIN")
                await _send(writer, f"{tag} OK CAPABILITY completed")
            elif verb == "LOGIN":
                bits = args.replace('"', "").split(" ")
                good = len(bits) == 2 and bits[0] == LAB_USER and bits[1] == LAB_PASSWORD
                if self.mode != "auth_fail" and good:
                    await _send(writer, f"{tag} OK LOGIN completed")
                else:
                    await _send(writer, f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")
            elif verb in ("SELECT", "EXAMINE"):
                await _send(writer, "* 3 EXISTS")
                await _send(writer, "* 0 RECENT")
                await _send(writer, f"{tag} OK [READ-ONLY] {verb} completed")
            elif verb == "LOGOUT":
                await _send(writer, "* BYE Logging out")
                await _send(writer, f"{tag} OK LOGOUT completed")
                return
            else:
                await _send(writer, f"{tag} BAD command not recognized")
