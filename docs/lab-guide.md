# Lab guide

Each exercise pairs a mock failure mode with a Wireshark capture so you learn what the failure looks
like on the wire as well as in the probe output. Everything runs on your own machine against the local
mock server. Use only test accounts and throwaway passwords.

## Setup

```bash
python3 -m pip install -e .
```

In Wireshark, start a capture on the **loopback** interface (`lo` on Linux/macOS, the Npcap loopback
adapter on Windows). Use the filter `tcp.port == 2525`.

Start a mock server in one terminal and probe it from another.

## Exercise 1: healthy session

```bash
maillab mock smtp --mode ok --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode plain --mail-from a@example.test --rcpt-to b@example.test
```

In Wireshark use `smtp.req.command` and follow the TCP stream. You should see the banner, `EHLO`,
the capability list, `MAIL FROM`, `RCPT TO` and `RSET`/`QUIT`, each followed by a `2xx` reply.

## Exercise 2: STARTTLS refused (454)

```bash
maillab mock smtp --mode starttls_unavailable --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode starttls
```

Filter: `smtp.response.code == 454`. Note that `STARTTLS` was advertised in the EHLO reply and then
refused, and that no TLS ClientHello follows.

## Exercise 3: connection reset during STARTTLS

```bash
maillab mock smtp --mode starttls_reset --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode starttls
```

Filter: `tcp.flags.reset == 1`. Compare with exercise 2: here there is no reply at all, only a TCP reset.
This is what a path device dropping the session looks like from the client.

## Exercise 4: authentication failure (535)

```bash
export MAILLAB_PW=wrong
maillab mock smtp --mode ok --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode plain --user lab --password-env MAILLAB_PW --allow-insecure-auth
```

Filter: `smtp.response.code == 535`. In the stream, the username and password lines are base64.
Decode one to see why captures with credentials must never be published.

## Exercise 5: relay denied and greylisting

```bash
maillab mock smtp --mode relay_denied --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode plain --mail-from a@example.test --rcpt-to b@example.test
```

Repeat with `--mode greylist` and compare the `554 5.7.1` (permanent) and `451 4.7.1` (temporary) replies.

## Exercise 6: silent port (blackhole)

```bash
maillab mock smtp --mode blackhole --port 2525
maillab smtp 127.0.0.1 --port 2525 --mode plain --timeout 3
```

The connection succeeds but no banner arrives, and the probe fails at `banner`. Compare with a firewall
that drops the SYN, where the failure is at `tcp connect`.

## Exercise 7: IMAP

```bash
maillab mock imap --mode ok --port 1430
export MAILLAB_PW=secret
maillab imap 127.0.0.1 --port 1430 --mode plain --user lab --password-env MAILLAB_PW --allow-insecure-auth
```

Filter: `imap`. Repeat with `--mode auth_fail` to see `NO [AUTHENTICATIONFAILED]`.

## After each exercise

1. Save a filtered, sanitized capture to `captures/sanitized/` (see `captures/README.md`).
2. Write down the filter you used and what the capture proved.
3. Run `maillab explain <code> <text>` for the reply you saw and compare with your own reading.
