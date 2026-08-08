from __future__ import annotations

from pathlib import Path
import shutil

from packetscope.demo import generate_demo


if __name__ == "__main__":
    output = generate_demo(Path("sample-data/demo-beacon.pcap"))
    packaged = Path("packetscope/sample_data/demo-beacon.pcap")
    packaged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(output, packaged)
    print(output)
