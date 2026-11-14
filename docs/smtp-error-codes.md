# SMTP reply codes quick reference

Codes are grouped by first digit: `2xx` success, `3xx` waiting for more input, `4xx` temporary failure
(retry), `5xx` permanent failure (do not retry). Many servers add an enhanced status such as `5.7.1`.
`maillab explain <code> <text>` applies the same rules used here.

| Code | Meaning | First check |
|------|---------|-------------|
| 220 | Service ready (banner, or ready for TLS) | none |
| 235 | Authentication successful | none |
| 250 | Requested action completed | none |
| 334 | Server challenge during AUTH | none |
| 354 | Start mail input (after DATA) | none |
| 421 | Service not available, closing channel | connection limits, server health, middlebox |
| 450 / 451 / 452 | Temporary mailbox, local error or storage problem | greylisting, queue, rate limit |
| 454 | Temporary failure (often TLS not available, or temporary auth failure) | read the text: TLS or auth? |
| 500 / 501 / 502 / 503 / 504 | Syntax, unknown command, bad sequence, unsupported parameter | command order, extensions |
| 530 | Authentication or STARTTLS required | send STARTTLS, then AUTH |
| 534 / 538 | Mechanism too weak, encryption required | TLS first, mechanism |
| 535 | Authentication failed | credentials, app password, AUTH disabled |
| 550 | Mailbox unavailable or rejected by policy | read enhanced code and text |
| 551 / 553 | User not local, mailbox name not allowed | address syntax, relay rules |
| 552 | Exceeded size or storage | message size, mailbox quota |
| 554 | Transaction failed (relay denied, spam, policy) | relay settings, SPF/DKIM/DMARC |

## Enhanced status classes

| Class | Meaning |
|-------|---------|
| x.1.x | Addressing problems (for example 5.1.1 unknown mailbox) |
| x.2.x | Mailbox problems (full, disabled) |
| x.3.x | Mail system problems |
| x.4.x | Network and routing |
| x.5.x | Protocol problems |
| x.6.x | Content or media problems |
| x.7.x | Security or policy (auth, TLS, blocks) |

## IMAP responses

| Response | Meaning | First check |
|----------|---------|-------------|
| `NO [AUTHENTICATIONFAILED]` | Login rejected | credentials, app password, IMAP enabled |
| `NO [UNAVAILABLE]` | Backend temporarily unavailable | retry with backoff |
| `NO [NONEXISTENT]` | Mailbox not found | LIST for the exact name |
| `BAD` | Malformed command or wrong state | command sequence |
