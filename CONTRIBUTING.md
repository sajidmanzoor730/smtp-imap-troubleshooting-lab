# Contributing

1. Fork and branch from `main`.
2. Add or update tests with every change: `make test` must pass.
3. New failure modes belong in three places: a mock mode in `src/maillab/mock.py`,
   a rule in `src/maillab/errors.py`, and a section in `docs/runbook.md`.
4. Never commit raw packet captures, real addresses, hostnames, credentials or customer data.
   Only commit sanitized captures from test accounts (see `captures/README.md`).
