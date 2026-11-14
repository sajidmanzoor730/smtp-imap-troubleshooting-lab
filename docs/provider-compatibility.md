# Provider compatibility and validation record

This document defines a repeatable compatibility test plan. It is deliberately not a claim that every listed provider has been tested. The default CI suite uses local fault-injecting mocks. A separate manual GitHub Actions workflow can authenticate to a dedicated Gmail or Microsoft 365 test mailbox using OAuth2 refresh-token credentials.

## Current verified scope

| Capability | Evidence in this repository | Status |
|---|---|---|
| SMTP plain session and envelope check | Local SMTP mock integration tests | Automated local test |
| SMTP STARTTLS and implicit TLS | Local TLS-enabled mock with generated test certificate | Automated local test |
| SMTP AUTH LOGIN | Local mock success/failure modes | Automated local test |
| SMTP AUTH XOAUTH2 | Local mock success/failure and token-redaction tests | Automated local test |
| SMTP error handling (535, 554, 451, 421, 454) | Fault-injecting mock scenarios and diagnosis rules | Automated local test |
| IMAP SSL/STARTTLS/login/read-only select | Local IMAP mock integration tests | Automated local test |
| Gmail / Microsoft 365 | Opt-in workflow: `.github/workflows/provider-integration.yml`; run report is retained in the Actions log | Requires authorised mailbox and configured repository secrets; not yet run from this repository |\n| Yahoo / other hosted mail | No provider-specific endpoint profile or external test evidence | Not yet verified |
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

## OAuth2 token refresh

The CLI can either accept a short-lived access token or exchange a refresh token at an HTTPS token endpoint. The latter performs token refresh only; the initial user consent/authorisation-code flow remains the operator's responsibility. The client secret is optional for public OAuth clients.

    export MAILLAB_REFRESH='refresh-token'
    export MAILLAB_CLIENT_ID='oauth-client-id'
    export MAILLAB_CLIENT_SECRET='oauth-client-secret'
    maillab smtp smtp.example.test --port 587 --mode starttls --user test-user@example.test \\
      --oauth2-refresh-token-env MAILLAB_REFRESH \\
      --oauth2-token-url https://oauth.example.test/token \\
      --oauth2-client-id-env MAILLAB_CLIENT_ID \\
      --oauth2-client-secret-env MAILLAB_CLIENT_SECRET
    unset MAILLAB_REFRESH MAILLAB_CLIENT_ID MAILLAB_CLIENT_SECRET

The same options are available for `maillab imap`. Provider-specific endpoints and scopes must match the consented refresh-token grant. Never use `--allow-insecure-auth` against a real provider.

## Running real-provider checks

1. Create a dedicated test mailbox and register an OAuth client with the provider.
2. Complete the provider's supported user-consent flow with offline access and the required protocol scopes. Store the resulting refresh token in GitHub Actions secrets.
3. Add repository secrets: `MAILLAB_TEST_USER`, `MAILLAB_CLIENT_ID`, `MAILLAB_CLIENT_SECRET` (if required), and `MAILLAB_REFRESH_TOKEN`. For Microsoft 365 also add `MAILLAB_TENANT_ID`.
4. Open **Actions → Provider integration smoke test → Run workflow**, select `gmail` or `m365`, and review the sanitised run output.
5. The script checks SMTP STARTTLS + XOAUTH2 and IMAP SSL + XOAUTH2, then performs a read-only IMAP INBOX selection. It does not send a message or change mailbox contents.

Gmail uses `smtp.gmail.com:587` and `imap.gmail.com:993`. Microsoft 365 uses `smtp.office365.com:587` and `outlook.office365.com:993`. Microsoft Entra permissions and Exchange tenant policy must permit the requested delegated IMAP/SMTP access.

The token is read from the environment, never from command-line arguments. The transcript redacts the XOAUTH2 response. OAuth2 access tokens are bearer credentials: protect shell history, process environment, CI logs and terminal recordings, and use a short-lived token with least-privilege scopes. The local mock accepts only the documented lab token mock-access-token; that value is for local tests only and is not a real provider credential.

## Known limitations

- The refresh helper exchanges an already-issued refresh token; it does not implement interactive consent, authorization-code callback handling, refresh-token rotation persistence or revocation.
- The mock validates a fixed lab token and does not emulate a real OAuth authorization server. Provider smoke tests are opt-in and require user-configured credentials/secrets; no real-provider success is claimed until a run passes.
- Provider-specific throttling, IP reputation, SMTPUTF8, DSN, message submission, spam filtering and inbox placement are not simulated.
- A successful TCP/TLS/AUTH/envelope probe is not proof that a message will be accepted after DATA or delivered to an inbox.
