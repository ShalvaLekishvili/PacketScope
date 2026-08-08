from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Iterable, Iterator


class CaptureFormatError(ValueError):
    pass


@dataclass(slots=True)
class PacketRecord:
    timestamp: float
    data: bytes
    original_length: int
    linktype: int = 1


# Common libpcap DLT values supported by PacketScope.
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276
SUPPORTED_LINKTYPES = {
    DLT_NULL,
    DLT_EN10MB,
    DLT_RAW,
    DLT_LOOP,
    DLT_LINUX_SLL,
    DLT_IPV4,
    DLT_IPV6,
    DLT_LINUX_SLL2,
}

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def iter_capture(path: str | Path) -> Iterator[PacketRecord]:
    path = Path(path)
    with path.open("rb") as handle:
        magic = handle.read(4)
        handle.seek(0)
        if magic in PCAP_MAGIC:
            yield from _iter_pcap(handle)
        elif magic == PCAPNG_MAGIC:
            yield from _iter_pcapng(handle)
        else:
            raise CaptureFormatError("Unsupported capture format: expected PCAP or PCAPNG")


def capture_kind(path: str | Path) -> str:
    with Path(path).open("rb") as handle:
        magic = handle.read(4)
    if magic in PCAP_MAGIC:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return "unknown"


def _iter_pcap(handle) -> Iterator[PacketRecord]:
    header = handle.read(24)
    if len(header) != 24:
        raise CaptureFormatError("Truncated PCAP global header")
    magic = header[:4]
    endian, resolution = PCAP_MAGIC[magic]
    _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", header)
    if major != 2 or minor != 4:
        raise CaptureFormatError(f"Unsupported PCAP version {major}.{minor}")
    if snaplen == 0:
        raise CaptureFormatError("Invalid PCAP snap length")

    packet_header = struct.Struct(endian + "IIII")
    while True:
        raw = handle.read(packet_header.size)
        if not raw:
            break
        if len(raw) != packet_header.size:
            raise CaptureFormatError("Truncated PCAP packet header")
        ts_sec, ts_frac, included, original = packet_header.unpack(raw)
        if included > 64 * 1024 * 1024:
            raise CaptureFormatError("Unreasonable PCAP packet length")
        data = handle.read(included)
        if len(data) != included:
            raise CaptureFormatError("Truncated PCAP packet data")
        yield PacketRecord(ts_sec + ts_frac / resolution, data, original, linktype)


def _iter_pcapng(handle) -> Iterator[PacketRecord]:
    endian = "<"
    interfaces: dict[int, tuple[int, float]] = {}
    seen_section = False

    while True:
        prefix = handle.read(12)
        if not prefix:
            break
        if len(prefix) != 12:
            raise CaptureFormatError("Truncated PCAPNG block header")

        block_type_raw = prefix[:4]
        if block_type_raw == PCAPNG_MAGIC:
            bom = prefix[8:12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureFormatError("Invalid PCAPNG byte-order magic")
            block_type = 0x0A0D0D0A
            total_len = struct.unpack(endian + "I", prefix[4:8])[0]
            seen_section = True
            interfaces = {}
        else:
            if not seen_section:
                raise CaptureFormatError("PCAPNG data before section header")
            block_type, total_len = struct.unpack(endian + "II", prefix[:8])

        if total_len < 12 or total_len > 128 * 1024 * 1024 or total_len % 4:
            raise CaptureFormatError("Invalid PCAPNG block length")
        rest = handle.read(total_len - 12)
        if len(rest) != total_len - 12:
            raise CaptureFormatError("Truncated PCAPNG block")
        full = prefix + rest
        trailer = struct.unpack(endian + "I", full[-4:])[0]
        if trailer != total_len:
            raise CaptureFormatError("PCAPNG block length mismatch")
        body = full[8:-4]

        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                continue
            linktype = struct.unpack(endian + "H", body[:2])[0]
            ts_resolution = 1e-6
            options = body[8:]
            cursor = 0
            while cursor + 4 <= len(options):
                code, length = struct.unpack(endian + "HH", options[cursor:cursor + 4])
                cursor += 4
                if code == 0:
                    break
                if cursor + length > len(options):
                    break
                value = options[cursor:cursor + length]
                cursor += (length + 3) & ~3
                if code == 9 and value:
                    raw_res = value[0]
                    ts_resolution = 2 ** -(raw_res & 0x7F) if raw_res & 0x80 else 10 ** -raw_res
            interfaces[len(interfaces)] = (linktype, ts_resolution)

        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            interface_id, ts_high, ts_low, captured, original = struct.unpack(
                endian + "IIIII", body[:20]
            )
            if captured > len(body) - 20:
                continue
            linktype, resolution = interfaces.get(interface_id, (DLT_EN10MB, 1e-6))
            timestamp = ((ts_high << 32) | ts_low) * resolution
            data = body[20:20 + captured]
            yield PacketRecord(timestamp, data, original, linktype)

        elif block_type == 3:  # Simple Packet Block: no timestamp available.
            if len(body) < 4:
                continue
            original = struct.unpack(endian + "I", body[:4])[0]
            data = body[4:]
            # SPB carries packets for interface 0. Timestamp is unavailable; keep 0.0 explicit.
            linktype, _ = interfaces.get(0, (DLT_EN10MB, 1e-6))
            yield PacketRecord(0.0, data[:original], original, linktype)


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    padding = (4 - (len(body) % 4)) % 4
    padded = body + (b"\x00" * padding)
    total = 12 + len(padded)
    return struct.pack("<II", block_type, total) + padded + struct.pack("<I", total)


def write_pcapng(records: Iterable[PacketRecord], destination: str | Path) -> Path:
    """Write records to a standards-compatible little-endian PCAPNG file.

    PacketScope emits one interface block per observed link type and microsecond timestamps.
    This is intentionally small and deterministic for evidence slicing/export workflows.
    """
    path = Path(destination)
    rows = list(records)
    linktypes: list[int] = []
    for row in rows:
        if row.linktype not in linktypes:
            linktypes.append(row.linktype)
    if not linktypes:
        raise ValueError("No packets selected for export")
    interface_ids = {link: idx for idx, link in enumerate(linktypes)}

    with path.open("wb") as handle:
        shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        handle.write(_pcapng_block(0x0A0D0D0A, shb))
        for linktype in linktypes:
            # snaplen 262144; default PCAPNG timestamp resolution is 10^-6 seconds.
            handle.write(_pcapng_block(1, struct.pack("<HHI", linktype, 0, 262144)))
        for row in rows:
            ticks = max(0, int(round(row.timestamp * 1_000_000)))
            captured = len(row.data)
            body = struct.pack(
                "<IIIII",
                interface_ids[row.linktype],
                ticks >> 32,
                ticks & 0xFFFFFFFF,
                captured,
                row.original_length,
            ) + row.data
            handle.write(_pcapng_block(6, body))
    return path
