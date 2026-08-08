# Synthetic Demo Capture

`sample-data/demo-beacon.pcap` is generated entirely by `packetscope.demo.generate_demo`. It contains no real organization traffic, credentials or third-party captures.

Current deterministic demo: **82 packets**.

Included behaviors:

- matched DNS A lookup/response
- matched HTTP GET/200 transaction
- 10 encoded-looking unique DNS subdomain queries
- cleartext HTTP request containing a synthetic Authorization header (the parser exposes only header presence)
- six periodic TLS ClientHello records with SNI
- 15-port vertical SYN probing sequence
- 20-host TCP/445 horizontal sweep
- conflicting ARP claims for one IPv4 address
- offers from two synthetic DHCP servers
- 20 ICMP echo requests
- NTP client metadata
- additional benign TLS context

Generate/re-generate:

```bash
python scripts/generate_demo_pcap.py
```

Analyze:

```bash
packetscope analyze sample-data/demo-beacon.pcap
```

The exact risk score is an implementation detail and may change when detection weighting changes; protocol/event counts and intended finding families are covered by automated tests.
