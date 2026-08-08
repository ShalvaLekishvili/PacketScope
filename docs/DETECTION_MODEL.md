# Detection Model

PacketScope detections are **investigative heuristics**, not signatures that automatically declare compromise.

Each active finding contains:

- stable `rule_id`
- generated finding `id`
- severity
- confidence percentage
- category
- plain-language summary
- evidence fields and bounded packet IDs
- recommendation
- contextual ATT&CK mappings where a network behavior reasonably overlaps a technique

## Current detection families

### Beaconing
Low coefficient-of-variation recurring communication to the same destination/port. ACK-only TCP packets are excluded from periodicity observations.

### DNS
- long/high-entropy labels
- aggregate unique encoded-looking subdomain sequences
- elevated NXDOMAIN ratio

The parent grouping is deliberately approximate (last two labels), so analysts should validate domains that use multi-label public suffixes.

### Reconnaissance
- vertical multi-port SYN/UDP probing
- horizontal same-port host sweeps

TCP scan heuristics use SYN packets without ACK to reduce response-noise false positives.

### HTTP
- Authorization header presence over cleartext HTTP (value redacted)
- direct IP-literal Host
- TRACE method

### TLS
- legacy protocol offer
- public/reserved TCP/443 ClientHello without SNI
- self-issued certificate name
- expired/not-yet-valid plaintext certificate metadata where visible

### Layer 2 / infrastructure
- multiple MAC addresses claiming the same IPv4 address through ARP
- multiple DHCP offer/ack/nak responders

### ICMP
High-volume echo-request activity between the same source/destination.

### Data transfer
Large private-to-external directional application payload volume.

## Suppression model

Suppressions are applied after candidate generation and retained in `suppressed_findings` with a `suppression_reason`. Supported controls are IP allowlists, domain suffix allowlists, category suppression and title suppression.

This is intentionally auditable: tuning should not make detection output silently disappear.

## Risk score

Severity weights are multiplied by a bounded confidence factor. A diminishing-return function maps accumulated weight to 0–100, reducing the chance that several weak low-confidence observations immediately saturate the score.
