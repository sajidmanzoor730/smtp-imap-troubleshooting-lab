# Incident playbooks

These playbooks demonstrate how a support engineer can move from a customer symptom to a reproducible test and a defensible escalation. All hostnames and addresses below are reserved examples.

## Playbook 1 — SMTP submission fails during STARTTLS

**Customer symptom:** An application reports that it cannot establish a secure SMTP session on port 587.

**Evidence to collect**
- Timestamp with timezone and source network.
- SMTP hostname, port and configured security mode.
- Whether the same endpoint works from a second network.
- Exact server response to STARTTLS.
- Certificate and TLS handshake details, with private data removed.

**Reproduce locally**

```bash
maillab mock smtp --mode starttls_unavailable --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode starttls --json
```

**Interpretation:** TCP and the SMTP greeting succeed; STARTTLS is advertised but the server refuses the request with a temporary `454`. This points to the TLS service/configuration path, not DNS reachability.

**Next checks**
1. Compare EHLO capabilities from the failing client and a known-good network.
2. Inspect server-side TLS logs and certificate configuration.
3. Capture the session and confirm whether a TLS ClientHello was sent.
4. Test implicit TLS on port 465 only if the provider supports it; treat it as a diagnostic comparison, not an assumed permanent workaround.

**Escalation payload:** timestamp, endpoint/port, failing stage, reply code, sanitised JSON output, capture filter, source network and tests already completed.

## Playbook 2 — SMTP authentication rejected

**Customer symptom:** The TCP and TLS session complete, but the server rejects credentials.

**Reproduce locally**

```bash
maillab mock smtp --mode auth_fail --port 2525
export MAILLAB_PW='wrong'
maillab smtp 127.0.0.1 --port 2525 --mode plain \
  --user lab --password-env MAILLAB_PW --allow-insecure-auth
unset MAILLAB_PW
```

The plain mode and insecure-auth override are used only because the mock is local. Never copy that flag into a real-provider command.

**Interpretation:** A `535` reply is an authentication rejection. It does not by itself prove that the password is wrong.

**Next checks**
1. Confirm the account identity and whether the account is active.
2. Check provider policy: app password requirement, SMTP AUTH enablement, MFA and allowed authentication mechanism.
3. Compare server-advertised AUTH mechanisms with the client mechanism.
4. For OAuth2, confirm the correct tenant, audience, delegated scopes, token expiry and consented mailbox.
5. Do not paste tokens or passwords into tickets; use a redacted transcript.

## Playbook 3 — SMTP relay denied

**Customer symptom:** The client authenticates or connects, but the recipient command is rejected.

**Reproduce locally**

```bash
maillab mock smtp --mode relay_denied --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode plain \
  --mail-from sender@example.test --rcpt-to recipient@example.test
```

**Interpretation:** The mock returns `554 5.7.1` at RCPT TO. The failure is policy-related, not a TCP or TLS failure.

**Next checks**
1. Confirm the client is using the provider's submission endpoint rather than a receiving MX host.
2. Verify whether authentication is required before the envelope.
3. Confirm sender/domain authorisation and relay policy with the mail administrator.
4. Preserve the exact stage and enhanced status code for escalation.

## Playbook 4 — IMAP authentication failure

**Customer symptom:** The user can reach the mailbox server but the client cannot authenticate.

**Reproduce locally**

```bash
maillab mock imap --mode auth_fail --port 1430
export MAILLAB_PW='wrong'
maillab imap 127.0.0.1 --port 1430 --mode plain \
  --user lab --password-env MAILLAB_PW --allow-insecure-auth
unset MAILLAB_PW
```

**Next checks**
1. Confirm IMAP access is enabled for the mailbox and tenant.
2. Verify whether basic password authentication is blocked by policy.
3. If using OAuth2, verify the provider-specific IMAP scope and delegated access.
4. Check concurrent-connection limits and provider-side sign-in logs.
5. Confirm mailbox name only after authentication succeeds; MailLab selects in read-only mode.

## Ticket handoff template

Copy this structure into an incident ticket. Replace example values and remove secrets/customer data.

```text
Summary:
Impact / affected users:
First observed (timezone):
Last known good:
Protocol / endpoint / port:
Configured TLS mode:
Failure stage:
Exact response / enhanced status:
MailLab category:
Tests performed:
Packet evidence (sanitised):
Provider/server correlation ID:
What was ruled out:
Workaround tested:
Next owner / requested action:
```

## Evidence handling

- Redact usernames, sender/recipient addresses, hostnames where sensitive, tenant IDs, tokens and message identifiers.
- A packet capture may contain base64-encoded credentials on legacy AUTH flows; base64 is not encryption.
- Capture only with approval and a defined retention period.
- Do not attach a full mailbox export or message body when a protocol-level transcript is sufficient.
