from __future__ import annotations

from pathlib import Path
import pytest

from packetscope.analysis import analyze_capture
from packetscope.demo import generate_demo


@pytest.fixture
def demo_capture(tmp_path: Path) -> Path:
    return generate_demo(tmp_path / "demo.pcap")


@pytest.fixture
def demo_result(demo_capture: Path):
    return analyze_capture(demo_capture)
