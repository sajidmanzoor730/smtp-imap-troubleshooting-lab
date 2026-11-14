# Provider compatibility and validation record

This document defines a repeatable compatibility test plan. It is deliberately not a claim that every listed provider has been tested. Automated integration tests use the local fault-injecting mock server; they do not authenticate to external mail providers.

## Current verified scope

| Capability | Evidence in this repository | Status |
|---|---|---|
| SMTP plain session and envelope check | Local SMTP mock integration tests | Automated local test |
| SMTP STARTTLS and implicit TLS | Local TLS-enabled mock with generated test certificate | Automated local test |
| SMTP AUTH LOGIN | Local mock success/failure modes | Automated local test |
| SMTP AUTH XOAUTH2 | Local mock success/failure and token-redaction tests | Automated local test |
| SMTP error handling (535, 554, 451, 421, 454) | Fault-injecting mock scenarios and diagnosis rules | Automated local test |
| IMAP SSL/STARTTLS/login/read-only select | Local IMAP mock integration tests | Automated local test |
| Gmail, Microsoft 365, Yahoo, generic hosted mail | No external provider test evidence committed | Not yet verified |
| SPF, DKIM and DMARC | Operator runbook only; no DNS parser or message-signature verifier | Manual investigation only |
| Inbox placement and spam reputation | Not measured by this project | Out of scope |

## Provider test worksheet

Complete a separate row for each provider, account type and date. Use a dedicated test mailbox and approved test tenant. Never commit access tokens, passwords, private keys, customer addresses or unredacted transcripts.

| Field | Record |
|---|---|
| Provider / product / tenant type | |
| Test date (UTC) | |
| Endpoint and port | |
| TLS mode and negotiated version | |
| EHLO/Capabilities (sanitised) | |
| Authentication method (password / OAuth2) | |
| Authentication result and SMTP code | |
| Envelope result (MAIL FROM / RCPT TO) | |
| DNS resolver and MX/SPF/DKIM/DMARC observations | |
| Provider request/correlation ID (redacted if needed) | |
| Result / limitation / follow-up | |

## Repeatable test procedure

1. Confirm the provider's current official endpoint, supported ports, TLS requirements and authentication policy from its documentation.
2. Use a dedicated test account and a short-lived OAuth2 token where applicable. Grant only the minimum scope required.
3. Run a connection-only probe first. Record the banner, EHLO capabilities and TLS result.
4. Test authentication separately. Do not use --allow-insecure-auth against a real provider.
5. If approved, perform the envelope-only check using test sender and recipient addresses. The probe stops after RCPT TO and sends RSET; it does not submit a message body.
6. Correlate the timestamp and provider-side logs. Redact addresses, tokens, server identifiers and tenant details before sharing.
7. Record the result in the worksheet. Mark a provider as verified only after a repeatable successful run and evidence review.

## OAuth2 example

    export MAILLAB_TOKEN='short-lived-access-token'
    maillab smtp smtp.example.test --port 587 --mode starttls --user test-user@example.test --oauth2-token-env MAILLAB_TOKEN
    unset MAILLAB_TOKEN

The token is read from the environment, never from command-line arguments. The transcript redacts the XOAUTH2 response. OAuth2 access tokens are bearer credentials: protect shell history, process environment, CI logs and terminal recordings, and use a short-lived token with least-privilege scopes. The local mock accepts only the documented lab token mock-access-token; that value is for local tests only and is not a real provider credential.

## Known limitations

- OAuth2 token acquisition, refresh, consent and provider-specific scopes are not implemented. Supply a token obtained through the provider's approved flow.
- The mock validates a fixed lab token and does not emulate a real OAuth authorization server.
- Provider-specific throttling, IP reputation, SMTPUTF8, DSN, message submission, spam filtering and inbox placement are not simulated.
- A successful TCP/TLS/AUTH/envelope probe is not proof that a message will be accepted after DATA or delivered to an inbox.
