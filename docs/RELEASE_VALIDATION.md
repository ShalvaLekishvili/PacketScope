# Release validation

PacketScope 2.0 is validated at three levels before packaging.

## Automated suite

```bash
pytest -q
```

The current suite contains 48 tests covering capture corruption/truncation, PCAPNG round trips and slicing, supported link layers, VLAN/raw IP handling, DNS compression safety, HTTP secret redaction, TLS/DHCP/NTP parsing, behavior detections, suppression logic, report generation and the API investigation lifecycle.

## Source-tree smoke checks

```bash
python -m compileall -q packetscope tests scripts
node --check packetscope/web/app.js
python scripts/generate_demo_pcap.py
packetscope analyze sample-data/demo-beacon.pcap --report /tmp/packetscope-report.html
packetscope slice sample-data/demo-beacon.pcap /tmp/packetscope-slice.pcapng --packets 1,2,3
```

## Distribution smoke check

Build a wheel, install it, change out of the source tree, and verify that the CLI and bundled web/demo assets still work:

```bash
python -m pip wheel . --no-deps -w /tmp/wheelhouse
python -m venv /tmp/packetscope-release
/tmp/packetscope-release/bin/python -m pip install /tmp/wheelhouse/packetscope-*.whl
cd /tmp
/tmp/packetscope-release/bin/packetscope analyze /path/to/demo-beacon.pcap
```

The distribution must include `packetscope/web/*` and `packetscope/sample_data/demo-beacon.pcap`.

## Manual API lifecycle

Validate this order with FastAPI/TestClient or a local server:

1. health/config
2. create demo or upload capture
3. fetch session
4. annotate a finding
5. export its related packet slice
6. generate a session report
7. delete the session

This document describes release gates, not a claim that heuristic detections are infallible. Real captures should still be validated in environmental context and, when needed, in Wireshark/Zeek/Suricata.
