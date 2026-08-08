# PacketScope 2.0

**Local-first network-forensics and packet-investigation workbench for PCAP/PCAPNG evidence.**

PacketScope turns raw captures into an analyst-oriented investigation model: evidence integrity, hosts, conversations, bounded TCP reconstruction, DNS/HTTP/TLS transactions, protocol metadata, IOCs, behavior detections, a network graph, analyst annotations, HTML/JSON reporting, and packet-level evidence slicing.

> PacketScope is a defensive analysis tool. Findings are heuristic leads that require environmental validation; they are not automatic malicious verdicts.

## Why this project exists

PacketScope is designed for SOC/DFIR workflows where an analyst needs more than a packet list but less operational overhead than a full network monitoring stack. The default workflow is offline/local: upload or open a capture, investigate metadata and evidence, annotate findings, and export only the packets related to a lead.

## Highlights

- **PCAP + PCAPNG** input with bounded custom readers
- Link layers: Ethernet, Linux cooked SLL/SLL2, BSD null/loopback, raw IP, DLT IPv4 and DLT IPv6
- IPv4/IPv6, VLAN metadata, TCP/UDP/ICMP, ARP
- **DNS** RR parsing + query/response transaction correlation and latency
- **HTTP** request/response metadata with sensitive header values redacted
- **TLS** ClientHello, ServerHello, JA3, SNI, ALPN, supported/selected versions; plaintext X.509 metadata where available
- DHCP and NTP metadata
- Directional flows + bidirectional conversations
- Bounded sequence-aware TCP stream reconstruction with overlap/gap accounting
- Host profiles with traffic, protocols, domains/SNI, services and attributed findings
- Investigation graph with host traffic, DNS pivots and TLS-SNI pivots
- IOC inventory: IP, domain, URL, JA3 and certificate SHA-256
- Behavior detections for beaconing, DNS data-channel patterns, NXDOMAIN anomalies, vertical/horizontal scanning, cleartext HTTP auth, direct-IP HTTP, ARP identity conflicts, multiple DHCP servers, ICMP bursts, legacy TLS, certificate anomalies and large outbound transfers
- Finding confidence, recommendation, evidence packet IDs and contextual MITRE ATT&CK mapping where appropriate
- Allowlist/suppression JSON configuration
- Ephemeral local web investigation sessions with status/verdict/note/tags
- **Export related packets** from a finding as a standalone PCAPNG slice
- JSON + self-contained HTML reporting
- FastAPI API, CLI, Docker/Compose and GitHub Actions CI
- 48 automated tests covering parsers, capture edge cases, detections, analysis, reporting and API workflows

## Quick start

### Python

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"

packetscope serve
# open http://127.0.0.1:8000
```

### Docker

```bash
docker compose up --build
# open http://127.0.0.1:8000
```

The Compose file binds only to localhost by default, drops Linux capabilities, enables `no-new-privileges`, runs the application as an unprivileged container user, and stores investigation sessions in a dedicated local volume.

## CLI

Analyze a capture:

```bash
packetscope analyze evidence.pcap
```

Generate JSON or HTML output:

```bash
packetscope analyze evidence.pcap --report evidence.html
packetscope analyze evidence.pcap --report evidence.json
packetscope analyze evidence.pcap --json > evidence.stdout.json
```

Use a detection/allowlist profile:

```bash
packetscope analyze evidence.pcap --config config.example.json
```

Export exact 1-based packet IDs as a PCAPNG evidence slice:

```bash
packetscope slice evidence.pcap finding-evidence.pcapng --packets 12,18,21,34
```

## Synthetic demo

The bundled demo is fully synthetic and intentionally contains several network behaviors for demonstration/testing.

```bash
python scripts/generate_demo_pcap.py
packetscope analyze sample-data/demo-beacon.pcap
```

Expected high-level demo shape:

- 82 packets
- DNS, HTTP, TLS, ARP, DHCP, ICMP and NTP metadata
- normal DNS and HTTP transactions
- periodic TLS communication
- encoded-looking DNS subdomain sequence
- vertical and horizontal SYN probing
- duplicate ARP IPv4 claim
- two DHCP responders
- ICMP echo burst
- cleartext HTTP Authorization presence (value redacted)

See [`docs/DEMO.md`](docs/DEMO.md).

## Web investigation workflow

1. Upload a capture or load the synthetic demo.
2. Verify the capture **SHA-256** and evidence ID.
3. Review risk-ranked hosts and priority findings.
4. Pivot through hosts, graph, conversations, protocol transactions, IOCs and timeline.
5. Open a finding to inspect confidence, recommendation, ATT&CK context and packet IDs.
6. Save analyst **status / verdict / note / tags**.
7. Export the exact related packets to `.pcapng` for deeper Wireshark/tcpdump review.
8. Export HTML/JSON results or explicitly close the investigation session.

Web-upload sessions expire after 4 hours by default. Configure with `PACKETSCOPE_SESSION_TTL`.

## Detection profile

Copy `config.example.json` and tune it for the environment. PacketScope keeps suppressed findings in a separate audit list rather than silently erasing them.

Supported suppression inputs:

- exact IP allowlist
- domain/suffix allowlist
- finding category suppression
- finding title suppression
- thresholds for beaconing, DNS channel heuristics, scanning, ICMP and large transfers

## Architecture

```text
PCAP / PCAPNG
      │
      ▼
Capture Reader ── integrity SHA-256 / evidence ID
      │
      ▼
Link + Network + Transport Parsers
      │
      ├── DNS / HTTP / TLS / ARP / DHCP / ICMP / NTP
      │
      ▼
Normalization + Flows + Conversations + Bounded TCP Reconstruction
      │
      ├── DNS / HTTP / TLS transaction correlation
      ├── Host profiler
      ├── IOC inventory
      └── Investigation graph
      │
      ▼
Detection Engine ── allowlist/suppression ── risk model
      │
      ▼
CLI / FastAPI / Web Workspace / Reports / Evidence Slices
```

More detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## API

When the server is running, FastAPI exposes interactive OpenAPI documentation at `/docs`.

Core endpoints:

```text
GET    /api/health
GET    /api/config
POST   /api/analyze?filename=evidence.pcap
GET    /api/demo
GET    /api/sessions/{session_id}
PATCH  /api/sessions/{session_id}/findings/{finding_id}
GET    /api/sessions/{session_id}/findings/{finding_id}/slice
GET    /api/sessions/{session_id}/report
DELETE /api/sessions/{session_id}
POST   /api/report
```

`POST /api/analyze` accepts raw capture bytes (`application/octet-stream`) so the service can stream the request to disk without first materializing the entire upload in memory.

## Security and privacy model

- no cloud upload or reputation enrichment by default
- no packet capture function and no active network scanning
- uploaded captures are stored only in the configured local workspace
- web sessions use random IDs and never accept user-provided filesystem paths
- session TTL cleanup + explicit deletion endpoint
- web upload limit: 100 MB by default (`PACKETSCOPE_MAX_UPLOAD_MB`)
- bounded packet/event/protocol/stream collections to reduce memory exhaustion risk
- HTTP Authorization/Cookie values are never placed in analysis output
- HTML report output escapes capture-derived strings
- packet slices contain the original packet bytes selected by evidence ID; treat them as sensitive evidence

See [`SECURITY.md`](SECURITY.md) and [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

## Important limitations

PacketScope intentionally does **not** pretend to replace Wireshark, Zeek, Suricata or a full NDR platform.

- IP fragments are identified but not reassembled.
- TCP reconstruction is bounded and stops at missing sequence gaps; it does not fabricate bytes.
- Encrypted application payloads are not decrypted.
- TLS 1.3 encrypts post-ServerHello handshake messages, so certificate metadata is normally unavailable without key material; plaintext certificate parsing mainly benefits TLS 1.2-style handshakes.
- DNS parent-domain aggregation uses an approximate last-two-label grouping and does not bundle a public-suffix database.
- Heuristics can produce false positives; the UI and reports explicitly preserve this analyst-validation model.
- PacketScope performs no automatic internet reputation lookup.

## Testing

```bash
pytest -q
# 48 tests
```

CI additionally runs fatal Ruff checks, Python/JavaScript syntax checks, CLI/report/slice smoke tests and a wheel build across supported Python versions. Release gates are documented in [`docs/RELEASE_VALIDATION.md`](docs/RELEASE_VALIDATION.md).

## Repository map

```text
packetscope/
  analysis.py      orchestration, correlations, host/graph model
  capture.py       PCAP/PCAPNG readers + PCAPNG writer
  protocols.py     bounded protocol decoders
  detectors.py     behavior detections and risk scoring
  config.py        detection/allowlist configuration
  slicing.py       packet-level evidence export
  workspace.py     local investigation sessions + annotations
  reporting.py     JSON/HTML reporting
  api.py           FastAPI service
  cli.py           CLI entrypoint
  web/             packaged frontend
  sample_data/     packaged synthetic demo

tests/             parser/detection/analysis/API tests
sample-data/       developer-visible synthetic capture
scripts/           demo generation helper
docs/              architecture, detection and investigation docs
```

## Responsible use

Use PacketScope only on captures you are authorized to inspect. Packet captures can contain credentials, tokens, personal information and proprietary data even when PacketScope's default analysis output redacts selected sensitive headers.

## License

MIT. See [`LICENSE`](LICENSE).
