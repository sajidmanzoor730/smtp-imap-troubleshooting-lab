# Security policy

## Intended use

MailLab is a diagnostic and educational tool. Use it only against mail servers, domains, mailboxes and networks that you own or are explicitly authorised to test.

## Safe defaults

- TLS certificate and hostname verification are enabled by default.
- Authentication over unencrypted connections is refused unless `--allow-insecure-auth` is explicitly enabled for a controlled lab.
- Passwords and OAuth2 secrets are supplied through environment variables.
- Authentication payloads are redacted from probe transcripts.
- SMTP envelope verification stops after `RCPT TO` and sends `RSET`; it does not send a message body.
- IMAP mailbox selection is read-only.
- The provider smoke workflow is opt-in and should use a dedicated test mailbox.

## Credential handling

Do not commit credentials, refresh tokens, client secrets, private keys, customer addresses or unredacted packet captures. Environment variables reduce accidental exposure in shell history compared with literal command-line values, but they are not a substitute for a managed secret store. Avoid shell tracing and verbose CI logs while secrets are present.

The fixed mock credentials `lab` / `secret` are public test values and must never be reused for a real account.

## Reporting a vulnerability

Please do not open a public issue containing a working exploit, credential, token, private customer data or sensitive provider endpoint. Contact the repository maintainer privately through GitHub's private vulnerability reporting feature if it is enabled for this repository. If it is unavailable, use the maintainer's verified contact method listed on their GitHub profile.

Include the affected version/commit, reproduction steps, expected impact and a safe proof of concept. Allow time for investigation before public disclosure.
