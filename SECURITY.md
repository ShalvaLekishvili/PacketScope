# Security Policy

PacketScope is intended for defensive analysis of packet captures you are authorized to inspect.

## Reporting a vulnerability

Please open a private GitHub security advisory for issues that could cause code execution, path traversal, denial of service, sensitive data exposure, parser crashes on crafted inputs, or unsafe workspace behavior. Avoid attaching real sensitive packet captures to public issues.

## Evidence handling

Packet captures may contain credentials, session tokens, personal information and proprietary data. PacketScope redacts selected HTTP credential-bearing header values in analysis output, but exported PCAPNG slices contain original packet bytes.

Web investigation sessions are local and expire by TTL, but operators remain responsible for filesystem/container retention and backups.
