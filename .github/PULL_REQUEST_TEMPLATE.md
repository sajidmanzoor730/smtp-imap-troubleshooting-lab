## Summary
Describe the change and the support problem it addresses.

## Validation
- [ ] Added or updated tests.
- [ ] Ran `python -m unittest discover -s tests -t . -v`.
- [ ] Updated relevant runbook or lab documentation.
- [ ] Confirmed no credentials, tokens, customer data or unredacted captures are included.

## Safety review
- [ ] TLS verification remains enabled by default.
- [ ] No message body is sent by the SMTP probe.
- [ ] IMAP operations remain read-only unless explicitly reviewed.
- [ ] Output does not expose passwords or OAuth tokens.
