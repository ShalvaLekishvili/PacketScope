# Publishing PacketScope to GitHub

1. Create a **public** repository named `PacketScope` without auto-generating README/license files.
2. Upload the contents of this folder (not the outer ZIP folder).
3. Confirm `.github/workflows/ci.yml` appears in the repository.
4. Wait for CI to pass on all configured Python versions.
5. In repository **About**, use a concise description such as:
   `Local-first PCAP/PCAPNG network-forensics workbench with protocol correlation, behavioral detections, host profiling, analyst workflow and evidence slicing.`
6. Suggested topics: `network-forensics`, `pcap`, `dfir`, `soc`, `threat-hunting`, `packet-analysis`, `fastapi`, `cybersecurity`.
7. Pin PacketScope on the GitHub profile alongside the strongest defensive-security projects.

Before publishing, run:

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check packetscope tests scripts --select E9,F63,F7,F82
python -m compileall -q packetscope tests scripts
node --check packetscope/web/app.js
python scripts/generate_demo_pcap.py
packetscope analyze sample-data/demo-beacon.pcap --report demo-report.html
packetscope slice sample-data/demo-beacon.pcap demo-slice.pcapng --packets 1,2,3
```

Do not commit real customer/enterprise packet captures or exported slices.
