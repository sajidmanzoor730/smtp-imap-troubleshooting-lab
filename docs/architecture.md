# Architecture and design

## System overview

MailLab is a dependency-free Python CLI application. The implementation is divided into five responsibilities:

| Module | Responsibility | Important boundary |
|---|---|---|
| `cli.py` | Parse arguments, load credentials from environment variables, select a probe, render output | Does not implement protocol state machines |
| `smtp.py` | SMTP socket session, STARTTLS/implicit TLS, AUTH and envelope check | Does not submit message content |
| `imap.py` | IMAP connection, capabilities, TLS, authentication and read-only mailbox selection | Does not fetch, move, delete or modify messages |
| `errors.py` | Classify SMTP replies, IMAP responses and transport exceptions | Recommendations are diagnostic guidance, not proof of root cause |
| `result.py` | Store steps, timing, capabilities, TLS version and diagnosis | Output should be treated as potentially sensitive operational data |
| `mock.py` | Local asyncio-based SMTP and IMAP test servers | Intended for loopback lab use, not production hosting |
| `oauth.py` | Exchange a previously issued refresh token for an access token | Does not perform consent or authorization-code login |

## SMTP probe lifecycle

1. Resolve the host and open a TCP connection.
2. For implicit TLS, negotiate TLS immediately.
3. Read and record the SMTP greeting.
4. Send EHLO and collect server capabilities.
5. For STARTTLS mode, verify that STARTTLS is advertised, request it, negotiate TLS, and issue EHLO again.
6. If credentials were supplied, verify the connection is encrypted unless the explicit lab override is enabled; then use AUTH LOGIN or XOAUTH2.
7. If both sender and recipient were supplied, perform MAIL FROM and RCPT TO, then send RSET.
8. Send QUIT when possible and return the structured result.

The envelope check is not a message-delivery test. No DATA command or message body is sent.

## IMAP probe lifecycle

1. Connect using implicit TLS or a plain TCP session.
2. Read the greeting and request CAPABILITY.
3. In STARTTLS mode, require the advertised capability, negotiate TLS and refresh capabilities.
4. If credentials were supplied, require encryption unless the lab override is enabled; authenticate with LOGIN or XOAUTH2.
5. Select the configured mailbox in read-only mode.
6. Close the session.

The probe does not read message bodies or mutate mailbox contents.

## Diagnosis model

A probe result contains the protocol, host, port, mode, ordered steps, timing, capabilities, negotiated TLS version and—when a step fails—a diagnosis.

The diagnosis model provides:
- a category such as `network`, `tls`, `auth`, `policy`, `recipient`, `transient`, `content` or `protocol`;
- a concise summary;
- the SMTP reply and enhanced status code when available;
- likely causes;
- recommended next steps.

A category is a reasoned interpretation of the observed response. It should not be treated as a definitive root-cause determination without server logs, packet evidence or provider-side correlation.

## Authentication and secrets

The CLI accepts environment-variable *names* for passwords, access tokens, refresh tokens, OAuth client IDs and optional client secrets. Secret values are not accepted as command-line argument values.

SMTP AUTH payloads are masked in the transcript. The IMAP XOAUTH2 step is represented with a fixed redacted label rather than the bearer token. The OAuth helper requires an HTTPS token endpoint and avoids printing provider response bodies.

Environment variables are a safer interface than command-line arguments, but they are not a full secrets manager. Avoid shared shells, shell tracing, process dumps, CI debug logs and persistent terminal recordings when handling credentials. Prefer short-lived, least-privilege credentials.

## TLS defaults

TLS verification uses the platform trust store and hostname checking by default. Disabling certificate verification is an explicit lab/debug option and must not be used as a production workaround.

Credentials are refused over plain connections unless `--allow-insecure-auth` is explicitly passed. That switch exists for local mock exercises and is not appropriate for real mail providers.

## Test strategy

The default test suite is deterministic and local:
- reply-code and exception-classification unit tests;
- SMTP and IMAP probe integration tests against local mock servers;
- TLS handshake tests using generated test certificates;
- authentication redaction tests;
- OAuth refresh request tests using mocked HTTP responses;
- CLI parsing, environment loading and exit-code tests.

The provider smoke workflow is separate and opt-in. It requires a dedicated mailbox and secrets configured by the repository owner. A local CI pass does not establish Gmail or Microsoft 365 compatibility.

## Extension points

New scenarios should be introduced with:
1. a clearly named mock mode;
2. a test that proves the probe's observed failure stage and category;
3. a runbook entry describing evidence and next action;
4. a lab exercise that can be repeated on loopback;
5. a note about any provider-specific or security limitations.

Keep probes conservative: read-only wherever possible, no message submission by default, bounded timeouts, TLS verification enabled, and no secret values in output.
