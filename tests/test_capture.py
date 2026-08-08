from __future__ import annotations

from pathlib import Path
import struct

import pytest

from packetscope.capture import CaptureFormatError, PacketRecord, capture_kind, iter_capture, write_pcapng
from packetscope.slicing import slice_capture


def test_demo_capture_is_classic_pcap(demo_capture: Path):
    assert capture_kind(demo_capture) == "pcap"
    packets = list(iter_capture(demo_capture))
    assert len(packets) == 82
    assert all(row.linktype == 1 for row in packets)


def test_capture_rejects_unknown_magic(tmp_path: Path):
    path = tmp_path / "bad.cap"
    path.write_bytes(b"NOPE" + b"\x00" * 32)
    with pytest.raises(CaptureFormatError):
        list(iter_capture(path))


def test_capture_rejects_truncated_pcap_header(tmp_path: Path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 5)
    with pytest.raises(CaptureFormatError, match="Truncated PCAP global header"):
        list(iter_capture(path))


def test_capture_rejects_truncated_packet_data(tmp_path: Path):
    path = tmp_path / "bad.pcap"
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    data += struct.pack("<IIII", 1, 0, 20, 20) + b"short"
    path.write_bytes(data)
    with pytest.raises(CaptureFormatError, match="Truncated PCAP packet data"):
        list(iter_capture(path))


def test_write_and_read_pcapng_round_trip(tmp_path: Path):
    rows = [PacketRecord(1.25, b"abc", 3, 1), PacketRecord(2.5, b"defg", 4, 101)]
    path = write_pcapng(rows, tmp_path / "roundtrip.pcapng")
    parsed = list(iter_capture(path))
    assert capture_kind(path) == "pcapng"
    assert [p.data for p in parsed] == [b"abc", b"defg"]
    assert [p.linktype for p in parsed] == [1, 101]
    assert parsed[0].timestamp == pytest.approx(1.25, abs=1e-6)


def test_slice_capture_exports_requested_packets(demo_capture: Path, tmp_path: Path):
    output = slice_capture(demo_capture, tmp_path / "slice.pcapng", [1, 2, 10])
    rows = list(iter_capture(output))
    source = list(iter_capture(demo_capture))
    assert len(rows) == 3
    assert rows[0].data == source[0].data
    assert rows[2].data == source[9].data


def test_slice_capture_rejects_empty_selection(demo_capture: Path, tmp_path: Path):
    with pytest.raises(ValueError, match="No packet IDs"):
        slice_capture(demo_capture, tmp_path / "slice.pcapng", [])
