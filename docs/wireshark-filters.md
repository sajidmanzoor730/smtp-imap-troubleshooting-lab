# Wireshark filters for mail troubleshooting

Display filters (type in the filter bar). Check field names in your Wireshark version if one is rejected.

## SMTP

| Goal | Filter |
|------|--------|
| All SMTP on the standard ports | `tcp.port == 25 \|\| tcp.port == 587 \|\| tcp.port == 465` |
| SMTP commands | `smtp.req.command` |
| One specific command | `smtp.req.command == "STARTTLS"` |
| A specific reply code | `smtp.response.code == 454` |
| All error replies | `smtp.response.code >= 400` |
| Server capabilities (EHLO reply) | `smtp.response.code == 250` |
| Follow one session | right-click a packet, Follow, TCP Stream |

## TLS (after STARTTLS or on port 465)

| Goal | Filter |
|------|--------|
| ClientHello | `tls.handshake.type == 1` |
| ServerHello | `tls.handshake.type == 2` |
| Server certificate | `tls.handshake.type == 11` |
| TLS alerts | `tls.alert_message` |
| Negotiated version in the hello | `tls.handshake.version` |

## TCP health

| Goal | Filter |
|------|--------|
| Resets | `tcp.flags.reset == 1` |
| Retransmissions | `tcp.analysis.retransmission` |
| SYN with no answer | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Zero window | `tcp.analysis.zero_window` |

## IMAP

| Goal | Filter |
|------|--------|
| IMAP traffic | `imap` |
| Login attempts | `imap.request contains "LOGIN"` |
| Failed responses | `imap.response contains "NO" \|\| imap.response contains "BAD"` |

## Reading a STARTTLS failure

1. Find the EHLO reply and confirm `STARTTLS` is listed.
2. Find the `STARTTLS` command and the server reply right after it.
3. `220` means the server is ready: the next packets should be a TLS ClientHello from the client.
   A reset or silence after the ClientHello points to a middlebox or the server dropping the handshake.
4. `454` means the server refused: look at the server logs and certificate configuration.
5. Compare a capture taken at the client side with one at the server side. A reply that differs
   between the two means something in the path is rewriting or dropping traffic.
