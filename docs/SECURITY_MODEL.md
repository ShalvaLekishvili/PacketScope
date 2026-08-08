# Security Model

PacketScope analyzes potentially hostile binary files, so parsers are designed around strict length checks and bounded collections.

## Trust boundaries

**Untrusted:** capture bytes, filenames, HTTP request bodies, analyst notes/tags.

**Trusted local configuration:** environment variables and optional JSON analysis profile supplied by the operator.

## Controls

- packet/block size validation
- PCAPNG block length/trailer validation
- DNS pointer depth + loop protection
- DNS record/count bounds
- TLS record/handshake length bounds
- bounded HTTP header parsing and redaction of Authorization/Proxy-Authorization/Cookie/Set-Cookie values
- bounded analysis collections and TCP stream bytes
- web upload size limit
- random workspace IDs with strict validation
- no user-controlled workspace filesystem paths
- HTML escaping in report/UI rendering
- session TTL + explicit deletion
- Docker non-root execution, dropped capabilities and `no-new-privileges`

## Residual risks

A parser bug may still exist; use OS/container isolation for highly untrusted evidence. Packet slices intentionally contain original packet bytes and may contain sensitive material.
