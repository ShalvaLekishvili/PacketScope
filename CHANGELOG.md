# Changelog

All notable changes to PacketScope are documented here.

## 2.0.0 — 2026-08-09

### Added
- PCAP and PCAPNG readers with Ethernet, VLAN, Linux SLL/SLL2, BSD null/loopback, raw IPv4/IPv6 link-layer support.
- DNS record parsing and query/response correlation, HTTP request/response correlation, TLS ClientHello/ServerHello intelligence and plaintext X.509 metadata where available.
- Directional flows, bidirectional conversations, bounded sequence-aware TCP reconstruction, host profiles, IOC inventory and investigation graph.
- Evidence-backed behavior detections for periodic communication, DNS data-channel patterns, scanning, cleartext HTTP authentication, direct-IP HTTP, ARP conflicts, DHCP anomalies, ICMP bursts, TLS anomalies and large outbound transfers.
- Stable finding/rule IDs, confidence, recommendations, evidence packet IDs, suppression/allowlist profiles and contextual ATT&CK mapping.
- Ephemeral local investigation sessions with analyst status, verdict, tags and notes.
- Finding-level PCAPNG evidence slicing.
- Self-contained HTML/JSON reports, FastAPI service, CLI, responsive local web UI, Docker/Compose and CI.
- Deterministic 82-packet synthetic demo capture.
- 48 automated parser, detection, analysis, report and API workflow tests.

### Security
- Bounded readers and collections for untrusted capture input.
- Sensitive HTTP credential-bearing header values are redacted from normalized output.
- Local-only Compose binding by default, non-root container, dropped Linux capabilities and no-new-privileges.
- Capture SHA-256/evidence ID and local session TTL/deletion controls.

## 1.0.0

Initial functional MVP with PCAP/PCAPNG analysis, DNS/HTTP/TLS metadata, beaconing detection, IOC extraction, reporting, CLI/API and demo capture.
