# DNS and email-authentication investigation

This guide complements the SMTP/IMAP probes. A successful SMTP connection does not prove that a domain is configured to send trustworthy mail or that a message will reach an inbox. DNS and authentication-policy checks are a separate investigation layer.

Use a domain and selector supplied by the domain owner. Do not guess DKIM selectors or publish customer domains, message IDs, or private records in screenshots.

## 1. Find the receiving mail exchangers (MX)

    dig MX example.com
    nslookup -type=MX example.com

Check whether an MX answer exists, whether each MX target resolves to A/AAAA records, and whether preference values match the expected provider. An MX record identifies inbound routing; it does not identify the SMTP submission endpoint for an authenticated application.

## 2. Inspect SPF

    dig TXT example.com

Find the single SPF policy beginning with v=spf1. Confirm that the actual sending service is authorised and DNS lookup limits are not exceeded.

- More than one SPF record at the same owner name can cause a PermError.
- A missing include or incorrect sending IP can cause SPF failure.
- Do not add a second SPF TXT record to fix an existing one; merge authorised mechanisms into the single policy with the domain administrator.
- SPF authenticates the SMTP envelope domain, not necessarily the visible From header.

## 3. Inspect DKIM

DKIM is published at a selector-specific name: selector._domainkey.example.com. Ask the mail provider or domain administrator for the exact selector.

    dig TXT selector._domainkey.example.com

Check that the TXT value contains the expected public key and that the signing service uses the matching private key. A DNS lookup alone cannot prove that a particular message was correctly signed; inspect its DKIM-Signature and the receiving system's Authentication-Results header.

## 4. Inspect DMARC

    dig TXT _dmarc.example.com

Review the p= policy (none, quarantine, reject), rua aggregate-report destination, SPF/DKIM alignment with the visible From domain, and any subdomain policy (sp=). Do not recommend changing a production domain directly to p=reject during an incident. Review aggregate reports and confirm all legitimate sending sources first.

## 5. Check TLS reporting policies when relevant

    dig TXT _mta-sts.example.com
    dig TXT _smtp._tls.example.com

MTA-STS and TLS-RPT are separate from SMTP AUTH and the TLS handshake tested by maillab. Their DNS records can help investigate transport-security policy and reporting, but this project does not fetch HTTPS policy files or parse TLS aggregate reports.

## 6. Correlate DNS and SMTP evidence

Collect a timestamp with timezone, resolver used, query name/type, full answer and TTL. Compare DNS findings with the SMTP probe stage and JSON output, TLS certificate/handshake evidence, provider logs, and a receiving system's Authentication-Results header.

    openssl s_client -starttls smtp -connect smtp.example.com:587 -servername smtp.example.com
    openssl s_client -connect smtp.example.com:465 -servername smtp.example.com

## Scope and limitations

The maillab CLI does not perform DNS queries itself, validate SPF/DKIM/DMARC cryptographically, send mail, or determine inbox placement. This runbook documents an operator workflow using standard DNS/TLS tools. DNS answers vary by resolver, cache and propagation state; preserve the resolver and timestamp in incident notes.
