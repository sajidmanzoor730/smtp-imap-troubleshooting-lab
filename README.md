# SMTP/IMAP Troubleshooting Lab

[![CI](https://github.com/sajidmanzoor730/smtp-imap-troubleshooting-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/sajidmanzoor730/smtp-imap-troubleshooting-lab/actions/workflows/ci.yml)

A zero-dependency Python toolkit for diagnosing email delivery problems the way an L2 support engineer does:
decide whether the failure is **network, TLS, authentication, policy or content**, then take the next concrete step.

It includes:

- **Probes** that walk an SMTP or IMAP session step by step and print the exchange like a packet capture.
- **A diagnosis engine** that maps reply codes and socket/TLS errors to likely causes and next steps.
- **A fault-injecting mock server** that reproduces real failures (STARTTLS refused, reset mid-STARTTLS, 535, relay denied, greylisting, blackholed ports) so you can practise safely.
- **Runbooks and Wireshark filter guides** for the same failure classes.
- **Modern authentication coverage** including SMTP AUTH LOGIN and XOAUTH2 bearer-token authentication with transcript redaction.
- **A test suite** that runs local protocol failure modes and authentication paths against the probes.

Python 3.11+, standard library only. Use it only against servers and accounts you own or are authorised to test.

## Quick start

```bash
git clone https://github.com/sajidmanzoor730/smtp-imap-troubleshooting-lab.git
cd smtp-imap-troubleshooting-lab
python3 -m pip install -e .

# Explain a reply code
maillab explain 454 "4.7.0 TLS not available due to temporary reason"

# Probe a server you own (password comes from an environment variable, never argv)
export MAILLAB_PW='app-password'
maillab smtp smtp.example.test --port 587 --mode starttls --user me@example.test --password-env MAILLAB_PW

# Practise locally: start a mock server that refuses STARTTLS
maillab mock smtp --mode starttls_unavailable --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode starttls

# Probe a provider with a short-lived OAuth2 access token (never pass it as an argument)
export MAILLAB_TOKEN='short-lived-access-token'
maillab smtp smtp.example.test --port 587 --mode starttls --user me@example.test --oauth2-token-env MAILLAB_TOKEN
unset MAILLAB_TOKEN
```

Example output against the `starttls_unavailable` mock:

```
SMTP probe 127.0.0.1:2525 (starttls)

[ok  ] tcp connect (1 ms)
       S: connected to 127.0.0.1:2525
[ok  ] banner (0 ms)
       S: 220 mock.maillab ESMTP ready
[ok  ] ehlo (0 ms)
       C: EHLO maillab.local
       S: 250-mock.maillab
       S: 250-SIZE 10485760
       S: 250-STARTTLS
       S: 250 AUTH LOGIN
[FAIL] starttls (0 ms)
       C: STARTTLS
       S: 454 4.7.0 TLS not available due to temporary reason

Result: failed at 'starttls'
Category: tls
Diagnosis: TLS/STARTTLS could not be negotiated [454 4.7.0]
Likely causes:
  - Server cannot start TLS (certificate, config or resource problem)
  - A firewall or SMTP inspection feature is interfering with STARTTLS
  - Client and server share no TLS version or cipher
Next steps:
  - Capture on port 587 and look for the STARTTLS reply and the TLS ClientHello after it
  - Test the same host from another network to separate a customer firewall from a server fault
  - Try implicit TLS on 465 as a workaround and confirm with the customer
  - Check the certificate chain and supported TLS versions with openssl s_client
```

Exit code is `0` when every check passes and `1` when a check fails, so probes can be used in scripts. Add `--json` for machine-readable output.

## Failure modes in the mock server

| Mode | Reproduces | Expected diagnosis |
|------|-----------|--------------------|
| `starttls_unavailable` | `454 4.7.0` after STARTTLS | tls |
| `starttls_reset` | connection reset right after STARTTLS (firewall-like) | network |
| `auth_fail` | `535` on AUTH LOGIN or XOAUTH2 | auth |
| `no_auth` | AUTH not advertised | auth |
| `relay_denied` | `554 5.7.1` on RCPT TO | policy |
| `greylist` | `451 4.7.1` on RCPT TO | transient |
| `banner_421` | `421` instead of a banner | transient |
| `blackhole` | TCP accepted, no reply | network (timeout) |
| `ok` | healthy server | passes |

Mock credentials: user `lab`, password `secret`. The mock listens on `127.0.0.1` by default.

## Documentation

- [Lab guide](docs/lab-guide.md): exercises pairing each failure mode with a Wireshark capture
- [Case study: voicemail-to-email failure](docs/case-study-voicemail-to-email.md)
- [Troubleshooting runbook](docs/runbook.md)
- [Wireshark filters](docs/wireshark-filters.md)
- [SMTP/IMAP reply code reference](docs/smtp-error-codes.md)
- [DNS and email-authentication investigation](docs/dns-email-authentication.md): MX, SPF, DKIM, DMARC and TLS reporting checks
- [Provider compatibility worksheet](docs/provider-compatibility.md): verified local scope and a repeatable external-provider test plan

## Project layout

```
src/maillab/
  errors.py   reply-code and exception classification
  smtp.py     SMTP probe (starttls | implicit | plain)
  imap.py     IMAP probe (ssl | starttls | plain)
  mock.py     fault-injecting SMTP and IMAP mock servers
  result.py   shared result and transcript types
  cli.py      maillab smtp | imap | explain | mock
tests/        unit and integration tests against the mock servers
docs/         runbook, filters, reference, lab guide, case study
captures/     sanitized captures from your own lab runs
```

## Design choices

- **Passwords and OAuth2 tokens never appear on the command line.** They are read from environment variables; authentication payloads are masked in transcripts.
- **OAuth2 token acquisition is intentionally external.** The SMTP probe supports XOAUTH2 with a supplied access token; it does not implement provider consent, refresh or scope management.
- **Credentials are refused over unencrypted connections** unless you pass `--allow-insecure-auth`, which is meant for the local mock only.
- **TLS verification is on by default.** `--insecure-skip-verify` exists for lab servers with self-signed certificates.
- **Probes never send a message body.** The envelope check stops after `RCPT TO` and sends `RSET`.

## Development

```bash
make test
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under MIT.
