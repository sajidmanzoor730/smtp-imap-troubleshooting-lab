"""Command line interface: maillab smtp | imap | explain | mock."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Sequence

from . import __version__
from .errors import classify
from .imap import MODES as IMAP_PROBE_MODES
from .imap import ImapProbe
from .mock import IMAP_MODES, SMTP_MODES, ImapMock, SmtpMock
from .smtp import MODES as SMTP_PROBE_MODES
from .smtp import SmtpProbe


def _password(args: argparse.Namespace) -> str | None:
    """Passwords come from an environment variable, never from argv (shell history, ps)."""
    if not args.password_env:
        return None
    value = os.environ.get(args.password_env)
    if value is None:
        raise SystemExit(f"error: environment variable {args.password_env} is not set")
    return value


def _emit(result, as_json: bool) -> int:
    print(json.dumps(result.to_dict(), indent=2) if as_json else result.to_text())
    return 0 if result.ok else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="maillab", description="SMTP/IMAP troubleshooting toolkit")
    parser.add_argument("--version", action="version", version=f"maillab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    smtp = sub.add_parser("smtp", help="probe an SMTP server step by step")
    smtp.add_argument("host")
    smtp.add_argument("--port", type=int, default=587)
    smtp.add_argument("--mode", choices=SMTP_PROBE_MODES, default="starttls")
    smtp.add_argument("--user")
    smtp.add_argument("--password-env", help="name of the environment variable holding the password")
    smtp.add_argument("--mail-from")
    smtp.add_argument("--rcpt-to")
    smtp.add_argument("--timeout", type=float, default=10.0)
    smtp.add_argument("--insecure-skip-verify", action="store_true", help="skip certificate checks (lab only)")
    smtp.add_argument("--allow-insecure-auth", action="store_true", help="allow AUTH without TLS (lab only)")
    smtp.add_argument("--json", action="store_true")

    imap = sub.add_parser("imap", help="probe an IMAP server")
    imap.add_argument("host")
    imap.add_argument("--port", type=int)
    imap.add_argument("--mode", choices=IMAP_PROBE_MODES, default="ssl")
    imap.add_argument("--user")
    imap.add_argument("--password-env")
    imap.add_argument("--mailbox", default="INBOX")
    imap.add_argument("--timeout", type=float, default=10.0)
    imap.add_argument("--insecure-skip-verify", action="store_true")
    imap.add_argument("--allow-insecure-auth", action="store_true")
    imap.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain", help="explain an SMTP reply code")
    explain.add_argument("code", type=int)
    explain.add_argument("text", nargs="*", help="reply text, for example: 4.7.0 TLS not available")
    explain.add_argument("--json", action="store_true")

    mock = sub.add_parser("mock", help="run a fault-injecting mock server for practice")
    mock.add_argument("protocol", choices=("smtp", "imap"))
    mock.add_argument("--mode", default="ok")
    mock.add_argument("--host", default="127.0.0.1")
    mock.add_argument("--port", type=int, default=2525)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "smtp":
        probe = SmtpProbe(
            args.host,
            args.port,
            args.mode,
            args.user,
            _password(args),
            args.timeout,
            mail_from=args.mail_from,
            rcpt_to=args.rcpt_to,
            verify_tls=not args.insecure_skip_verify,
            allow_insecure_auth=args.allow_insecure_auth,
        )
        return _emit(probe.run(), args.json)

    if args.command == "imap":
        probe = ImapProbe(
            args.host,
            args.port,
            args.mode,
            args.user,
            _password(args),
            args.mailbox,
            args.timeout,
            verify_tls=not args.insecure_skip_verify,
            allow_insecure_auth=args.allow_insecure_auth,
        )
        return _emit(probe.run(), args.json)

    if args.command == "explain":
        diagnosis = classify(args.code, " ".join(args.text))
        if args.json:
            print(json.dumps(diagnosis.to_dict(), indent=2))
        else:
            print(f"{diagnosis.category.upper()}: {diagnosis.summary}")
            for heading, items in (("Likely causes", diagnosis.likely_causes), ("Next steps", diagnosis.next_steps)):
                if items:
                    print(f"{heading}:")
                    for item in items:
                        print(f"  - {item}")
        return 0

    if args.command == "mock":
        modes = SMTP_MODES if args.protocol == "smtp" else IMAP_MODES
        if args.mode not in modes:
            print(f"error: mode must be one of {', '.join(modes)}", file=sys.stderr)
            return 2
        server_cls = SmtpMock if args.protocol == "smtp" else ImapMock
        server = server_cls(mode=args.mode, host=args.host, port=args.port)
        server.start()
        print(f"mock {args.protocol} ({args.mode}) listening on {server.host}:{server.port}  user=lab password=secret")
        print("Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.stop()
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
