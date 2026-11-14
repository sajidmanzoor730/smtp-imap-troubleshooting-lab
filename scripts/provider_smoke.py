#!/usr/bin/env python3
"""Opt-in, read-only SMTP/IMAP OAuth2 smoke test for Gmail or Microsoft 365."""

from __future__ import annotations

import json
import os
import sys

from maillab.imap import ImapProbe
from maillab.oauth import OAuthTokenError, refresh_access_token
from maillab.smtp import SmtpProbe


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def main() -> int:
    provider = required("MAILLAB_PROVIDER").lower()
    username = required("MAILLAB_TEST_USER")
    client_id = required("MAILLAB_CLIENT_ID")
    refresh_token = required("MAILLAB_REFRESH_TOKEN")
    client_secret = os.environ.get("MAILLAB_CLIENT_SECRET")

    if provider == "gmail":
        token_url = "https://oauth2.googleapis.com/token"
        smtp_host, smtp_port = "smtp.gmail.com", 587
        imap_host, imap_port = "imap.gmail.com", 993
        scope = None
    elif provider in ("m365", "microsoft365"):
        tenant = required("MAILLAB_TENANT_ID")
        token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        smtp_host, smtp_port = "smtp.office365.com", 587
        imap_host, imap_port = "outlook.office365.com", 993
        scope = (
            "https://outlook.office.com/IMAP.AccessAsUser.All "
            "https://outlook.office.com/SMTP.Send offline_access"
        )
    else:
        raise SystemExit("MAILLAB_PROVIDER must be gmail or m365")

    try:
        token = refresh_access_token(token_url, client_id, refresh_token, client_secret, scope)
    except OAuthTokenError as exc:
        print(json.dumps({"provider": provider, "oauth_refresh": "FAIL", "reason": str(exc)}))
        return 1

    smtp = SmtpProbe(
        smtp_host, smtp_port, "starttls", username=username, bearer_token=token, timeout=20
    ).run()
    imap = ImapProbe(
        imap_host, imap_port, "ssl", username=username, bearer_token=token, timeout=20
    ).run()

    report = {
        "provider": provider,
        "oauth_refresh": "PASS",
        "smtp": {"status": "PASS" if smtp.ok else "FAIL", "result": smtp.to_dict()},
        "imap": {"status": "PASS" if imap.ok else "FAIL", "result": imap.to_dict()},
        "safety": "No message body sent; IMAP mailbox selection is read-only.",
    }
    print(json.dumps(report, indent=2))
    return 0 if smtp.ok and imap.ok else 1


if __name__ == "__main__":
    sys.exit(main())
