# Captures

This folder holds **sanitized** packet captures from the lab exercises in `docs/lab-guide.md`.

No captures are included in the repository by default. Add your own after each lab run.

## Rules before committing a capture

- Capture only traffic between your own test client and a test account or the local mock server.
- AUTH LOGIN and AUTH PLAIN are base64, not encrypted. Anyone can decode them, so use a throwaway
  password and rotate it afterwards.
- Remove unrelated traffic: filter in Wireshark and use File > Export Specified Packets.
- Replace real hostnames and addresses with `example.test` / `example.com` where you can.
- Put the file in `captures/sanitized/` and list it in the table below.

| File | What it shows | Wireshark filter used |
|------|---------------|-----------------------|
| (add your own) | | |
