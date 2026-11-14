# Case study: voicemail-to-email not reaching the customer

A sanitized write-up of a support case from my L2 VoIP support work. No customer names, addresses or
hostnames are included. The mock server in this repo reproduces the failure class so it can be practised.

## Symptom

A customer reported that voicemail-to-email messages from the VoIP service were not arriving.
Voicemail itself worked; only the email notification was missing.

## Investigation

1. **Application logs.** The Node.js service that sends the notification logged
   `SMTP 454 TLS handshake failed` for that customer's outbound mail server.
2. **Packet capture.** A Wireshark capture of the connection showed the session on port 587 reaching
   STARTTLS, and the STARTTLS negotiation being blocked.
3. **Cause.** The customer had made a firewall change that interfered with STARTTLS on port 587.

## Fix

- Applied **port 465 (implicit TLS)** as a workaround.
- Asked the customer to **allowlist the service IP** on their side.

## What I would check first next time

Run the probe against the customer's server on both ports and compare:

```bash
maillab smtp customer-mail.example.test --port 587 --mode starttls
maillab smtp customer-mail.example.test --port 465 --mode implicit
```

If 465 passes and 587 fails at `starttls`, the path or the server's STARTTLS handling is the problem,
not the credentials or the message.

## Reproduce locally

```bash
maillab mock smtp --mode starttls_unavailable --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode starttls
```

The `starttls_reset` mode reproduces the firewall-style variant where the connection is reset instead of
refused with a `454`. See the [lab guide](lab-guide.md) for the matching Wireshark capture.

## Lessons

- Read the layer before the error text: a TLS error on a mail connection is not an authentication problem.
- Separate customer-side and service-side causes by testing the same host from another network.
- Offer a working alternative (port 465) while the root cause is fixed, and document it in the runbook.
