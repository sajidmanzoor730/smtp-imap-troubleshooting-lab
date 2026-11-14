"""Turn raw SMTP/IMAP replies and network exceptions into actionable diagnoses.

The rules follow the usual L2 troubleshooting order: decide first whether the
failure is network, TLS, authentication, policy or content, then give the next
concrete check instead of repeating the error text.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any

_ENHANCED = re.compile(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b")


@dataclass(frozen=True)
class Diagnosis:
    category: str  # network | tls | auth | policy | recipient | content | protocol | transient | ok
    summary: str
    code: int | None = None
    enhanced: str | None = None
    likely_causes: tuple[str, ...] = field(default_factory=tuple)
    next_steps: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "summary": self.summary,
            "code": self.code,
            "enhanced": self.enhanced,
            "likely_causes": list(self.likely_causes),
            "next_steps": list(self.next_steps),
        }


def enhanced_status(text: str) -> str | None:
    match = _ENHANCED.search(text)
    return match.group(0) if match else None


# (codes, keywords, category, summary, causes, steps). First match wins, so
# keyword-specific rules sit above the generic rule for the same code.
_Rule = tuple[frozenset[int], tuple[str, ...], str, str, tuple[str, ...], tuple[str, ...]]

_RULES: list[_Rule] = [
    (
        frozenset({454, 421, 530, 535, 538}),
        ("tls", "ssl", "starttls", "handshake", "encryption", "certificate"),
        "tls",
        "TLS/STARTTLS could not be negotiated",
        (
            "Server cannot start TLS (certificate, config or resource problem)",
            "A firewall or SMTP inspection feature is interfering with STARTTLS",
            "Client and server share no TLS version or cipher",
        ),
        (
            "Capture on port 587 and look for the STARTTLS reply and the TLS ClientHello after it",
            "Test the same host from another network to separate a customer firewall from a server fault",
            "Try implicit TLS on 465 as a workaround and confirm with the customer",
            "Check the certificate chain and supported TLS versions with openssl s_client",
        ),
    ),
    (
        frozenset({454}),
        ("authentication", "auth"),
        "transient",
        "Temporary authentication failure",
        (
            "Auth backend (LDAP, database) briefly unavailable",
            "Rate limiting after repeated failed logins",
        ),
        ("Retry after a short delay", "Check the auth backend and server logs for the same timestamp"),
    ),
    (
        frozenset({530}),
        (),
        "auth",
        "Authentication or STARTTLS is required before this command",
        (
            "Client tried AUTH or MAIL before STARTTLS",
            "Server requires authentication for submission",
        ),
        (
            "Issue STARTTLS first, then EHLO again, then AUTH",
            "Confirm the client uses the submission port (587/465), not 25",
        ),
    ),
    (
        frozenset({535, 534, 538}),
        (),
        "auth",
        "Authentication failed",
        (
            "Wrong username or password",
            "Account needs an app password (MFA enabled) or SMTP AUTH is disabled",
            "Mechanism mismatch (server expects PLAIN or XOAUTH2, client sent LOGIN)",
        ),
        (
            "Re-test with a known-good credential on a test account",
            "Check the provider's SMTP AUTH and app-password settings",
            "Compare the AUTH mechanisms advertised in the EHLO reply",
        ),
    ),
    (
        frozenset({550, 551, 553, 554}),
        ("relay", "relaying"),
        "policy",
        "Relay denied: the server will not forward mail for this sender or recipient",
        (
            "Not authenticated, or authenticated as a different domain",
            "Client connected to a MX host instead of a submission server",
        ),
        (
            "Authenticate on port 587 or 465 before MAIL FROM",
            "Check that the sender domain is allowed for this account",
        ),
    ),
    (
        frozenset({550, 551, 553, 554}),
        ("user unknown", "no such user", "mailbox unavailable", "does not exist", "5.1.1", "invalid recipient"),
        "recipient",
        "Recipient mailbox does not exist or is unavailable",
        ("Typo in the address", "Mailbox deleted or disabled", "Directory not synced"),
        ("Verify the address with the recipient", "Test with another known-good recipient"),
    ),
    (
        frozenset({550, 553, 554}),
        ("spam", "blocked", "blacklist", "blocklist", "rbl", "reputation", "dmarc", "spf", "dkim", "policy", "denied"),
        "policy",
        "Message rejected by a reputation, authentication or content policy",
        (
            "Sending IP on a blocklist or without reverse DNS",
            "SPF, DKIM or DMARC failing for the sending domain",
            "Content or volume triggered a spam filter",
        ),
        (
            "Check SPF, DKIM and DMARC alignment for the From domain",
            "Check the sending IP against the receiving provider's postmaster guidance",
            "Compare against a message that was delivered",
        ),
    ),
    (
        frozenset({552}),
        (),
        "content",
        "Message or mailbox size limit exceeded",
        ("Attachment too large", "Recipient mailbox full"),
        ("Compare message size to the SIZE value in the EHLO reply", "Retry without the attachment"),
    ),
    (
        frozenset({421}),
        (),
        "transient",
        "Service not available, server is closing the channel",
        (
            "Too many connections or rate limit from this IP",
            "Server shutting down or overloaded",
            "A middlebox is closing the session",
        ),
        ("Retry with backoff", "Check connection limits and server status", "Test from a different source IP"),
    ),
    (
        frozenset({450, 451, 452}),
        (),
        "transient",
        "Temporary failure, the sender should retry",
        (
            "Greylisting on the receiving side",
            "Local resource problem (queue, disk, rate limit)",
        ),
        (
            "Wait for the normal retry interval before escalating",
            "If it persists beyond the retry window, treat it as a policy block",
        ),
    ),
    (
        frozenset({500, 501, 502, 503, 504}),
        (),
        "protocol",
        "Protocol error: command unknown, malformed or out of sequence",
        (
            "Commands sent out of order (for example AUTH before EHLO)",
            "Client and server disagree on an extension",
        ),
        ("Replay the exact command sequence in a packet capture", "Compare with a client that works"),
    ),
]


def classify(code: int, text: str = "") -> Diagnosis:
    """Classify an SMTP-style reply code with its text."""
    low = text.lower()
    enhanced = enhanced_status(text)
    if 200 <= code < 300:
        return Diagnosis("ok", "Success", code, enhanced)
    for codes, keywords, category, summary, causes, steps in _RULES:
        if code in codes and (not keywords or any(k in low for k in keywords)):
            return Diagnosis(category, summary, code, enhanced, causes, steps)
    if 400 <= code < 500:
        return Diagnosis(
            "transient",
            f"Temporary failure ({code})",
            code,
            enhanced,
            ("Server-side condition that may clear on retry",),
            ("Retry later and read the full reply text for detail",),
        )
    if 500 <= code < 600:
        return Diagnosis(
            "policy",
            f"Permanent failure ({code})",
            code,
            enhanced,
            ("Rejected by the server; retrying will not help",),
            ("Read the full reply text and check the enhanced status code",),
        )
    return Diagnosis("protocol", f"Unexpected reply ({code})", code, enhanced)


def diagnose_no_starttls() -> Diagnosis:
    return Diagnosis(
        "tls",
        "Server does not advertise STARTTLS",
        None,
        None,
        (
            "Server does not offer STARTTLS on this port",
            "A firewall or proxy is stripping the STARTTLS capability from the EHLO reply",
        ),
        (
            "Compare the EHLO reply seen locally with one captured on the server side",
            "Try the implicit TLS port (465) if the provider supports it",
        ),
    )


def diagnose_insecure_auth() -> Diagnosis:
    return Diagnosis(
        "protocol",
        "Refusing to send credentials over an unencrypted connection",
        None,
        None,
        ("Probe was run in plain mode with credentials",),
        ("Use starttls or implicit mode, or allow insecure auth for a lab server",),
    )


def classify_network(exc: BaseException, stage: str = "connect") -> Diagnosis:
    """Classify a socket, DNS or TLS exception raised during a probe."""
    if isinstance(exc, socket.gaierror):
        return Diagnosis(
            "network",
            "DNS lookup failed",
            None,
            None,
            ("Hostname typo or missing record", "Resolver unreachable"),
            ("Resolve the name with dig or nslookup", "Check the MX or A record"),
        )
    if isinstance(exc, ssl.SSLCertVerificationError):
        return Diagnosis(
            "tls",
            "TLS certificate verification failed",
            None,
            None,
            (
                "Self-signed or expired certificate",
                "Hostname does not match the certificate",
                "Missing intermediate certificate",
            ),
            (
                "Inspect the chain with openssl s_client -showcerts",
                "Confirm the hostname the client uses matches the certificate",
            ),
        )
    if isinstance(exc, ssl.SSLEOFError):
        return Diagnosis(
            "tls",
            "Peer closed the connection during the TLS handshake",
            None,
            None,
            ("Firewall or inspection device dropped the handshake", "Server rejected the ClientHello"),
            ("Capture the handshake and look for a TCP reset after the ClientHello", "Test from another network"),
        )
    if isinstance(exc, ssl.SSLError):
        return Diagnosis(
            "tls",
            "TLS handshake failed",
            None,
            None,
            ("No common TLS version or cipher", "Server is not speaking TLS on this port"),
            ("Run openssl s_client against the port", "Check the protocol versions each side supports"),
        )
    if isinstance(exc, ConnectionRefusedError):
        return Diagnosis(
            "network",
            "Connection refused",
            None,
            None,
            ("Nothing is listening on this port", "A firewall is actively rejecting the connection"),
            ("Confirm the port and service with the provider", "Test from another network"),
        )
    if isinstance(exc, (TimeoutError, socket.timeout)):
        if stage == "tcp connect":
            return Diagnosis(
                "network",
                "Connection timed out: port likely blocked or filtered",
                None,
                None,
                ("Firewall silently dropping packets to this port", "Host unreachable or route problem"),
                (
                    "Check whether other ports on the host respond",
                    "Capture and look for unanswered SYN packets",
                    "Test from another network",
                ),
            )
        if stage == "tls handshake":
            return Diagnosis(
                "tls",
                "TLS handshake stalled",
                None,
                None,
                ("Middlebox holding or dropping handshake packets",),
                ("Capture the handshake and check for retransmissions after the ClientHello",),
            )
        return Diagnosis(
            "network",
            f"No response from the server during '{stage}'",
            None,
            None,
            ("Server or middlebox accepted the connection but is not answering", "Application hung or overloaded"),
            ("Capture the session and check which side stopped sending", "Check server health"),
        )
    if isinstance(exc, (ConnectionError, BrokenPipeError)):
        return Diagnosis(
            "network",
            f"Connection closed or reset during '{stage}'",
            None,
            None,
            ("Firewall or inspection device reset the session", "Server closed the connection on a policy or error"),
            ("Capture the session and look for a TCP RST and who sent it", "Test from another network"),
        )
    return Diagnosis(
        "network",
        f"Network error during '{stage}': {type(exc).__name__}",
        None,
        None,
        ("Unclassified socket error",),
        ("Read the exception text and capture the session",),
    )


def classify_imap(text: str) -> Diagnosis:
    """Classify an IMAP NO/BAD response text."""
    low = text.lower()
    if "authenticationfailed" in low or "invalid credentials" in low or "login failed" in low:
        return Diagnosis(
            "auth",
            "IMAP authentication failed",
            None,
            None,
            (
                "Wrong username or password",
                "App password required when MFA is on",
                "IMAP access disabled for the account",
            ),
            ("Retest with a known-good credential", "Check the provider's IMAP and app-password settings"),
        )
    if "application-specific password" in low or "app password" in low:
        return Diagnosis(
            "auth",
            "Provider requires an app-specific password",
            None,
            None,
            ("MFA is enabled on the account",),
            ("Generate an app password and retry",),
        )
    if "unavailable" in low or "too many" in low or "throttl" in low:
        return Diagnosis(
            "transient",
            "IMAP service temporarily unavailable or rate limited",
            None,
            None,
            ("Too many connections", "Backend maintenance"),
            ("Retry with backoff", "Check the per-user connection limit"),
        )
    if "nonexistent" in low or "does not exist" in low or "no such mailbox" in low:
        return Diagnosis(
            "protocol",
            "Mailbox does not exist",
            None,
            None,
            ("Wrong folder name or delimiter",),
            ("LIST the folders and use the exact name returned",),
        )
    return Diagnosis(
        "protocol",
        "IMAP command rejected",
        None,
        None,
        ("Command not allowed in this state or not supported",),
        ("Replay the sequence in a capture and compare with a working client",),
    )
