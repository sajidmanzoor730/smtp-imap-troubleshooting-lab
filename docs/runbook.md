# Email delivery troubleshooting runbook

Use this order. Stop at the first layer that fails; do not skip ahead.

## 0. Collect

- Exact error text and time (with time zone) from the customer or the logs.
- Which port and security mode the sender uses (25, 587 STARTTLS, 465 implicit TLS).
- What changed recently: firewall, certificate, credentials, provider settings, source IP.

## 1. Network: can the client reach the port?

```
maillab smtp mail.example.test --port 587 --mode starttls
```

| Symptom | Meaning | Action |
|---------|---------|--------|
| Timeout at `tcp connect` | Port filtered or host unreachable | Test from another network; check firewall rules |
| Connection refused | Nothing listening or active reject | Confirm port and service |
| Reset or close at `banner` | Middlebox or server policy closing the session | Capture; look for who sent the RST |
| DNS failure | Name does not resolve | Check the A/MX record |

## 2. TLS: does STARTTLS or implicit TLS complete?

| Symptom | Meaning | Action |
|---------|---------|--------|
| `Server does not advertise STARTTLS` | Capability missing or stripped | Compare EHLO reply at both ends |
| `454` after STARTTLS | Server refused TLS | Server logs, certificate config |
| Reset or silence after STARTTLS `220` | Handshake dropped in the path | Capture the ClientHello; test another network |
| Certificate verification failed | Chain, expiry or hostname problem | `openssl s_client -connect host:587 -starttls smtp` |

Workaround to confirm the diagnosis: try implicit TLS on 465. If 465 works and 587 does not,
the problem is specific to STARTTLS handling in the path.

## 3. Authentication

| Symptom | Meaning | Action |
|---------|---------|--------|
| `535` | Credentials rejected | Test account, app password, AUTH enabled |
| `530` | Auth or STARTTLS required first | Fix command order |
| `454` with "authentication" | Temporary auth backend problem | Retry; check backend |

## 4. Envelope and policy

| Symptom | Meaning | Action |
|---------|---------|--------|
| `554 ... relay denied` | Not allowed to relay | Authenticate on the submission port |
| `550 5.1.1` | Recipient does not exist | Verify the address |
| `550 5.7.1` spam or policy | Reputation or authentication policy | SPF, DKIM, DMARC, sending IP |
| `451` / `452` | Temporary | Wait for retry; escalate if it persists |

## 5. Escalation checklist

Include in the ticket: exact error and time, port and mode, the `maillab --json` output or
packet capture, what you ruled out, and the workaround tested. Remove credentials and customer
addresses from anything attached.
