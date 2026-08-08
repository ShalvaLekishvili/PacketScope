from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .capture import PacketRecord, iter_capture, write_pcapng


def slice_capture(
    source: str | Path,
    destination: str | Path,
    packet_ids: Iterable[int],
) -> Path:
    """Export selected 1-based packet IDs to a PCAPNG evidence slice."""
    wanted = {int(x) for x in packet_ids if int(x) > 0}
    if not wanted:
        raise ValueError("No packet IDs were supplied for slicing")
    selected: list[PacketRecord] = []
    for packet_id, record in enumerate(iter_capture(source), start=1):
        if packet_id in wanted:
            selected.append(record)
            if len(selected) == len(wanted):
                break
    if not selected:
        raise ValueError("None of the requested packet IDs exist in the capture")
    return write_pcapng(selected, destination)
