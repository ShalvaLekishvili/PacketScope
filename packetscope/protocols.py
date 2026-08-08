from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timezone
import hashlib
import ipaddress
import socket
import struct
from typing import Any

from .capture import (
    DLT_EN10MB,
    DLT_IPV4,
    DLT_IPV6,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_LOOP,
    DLT_NULL,
    DLT_RAW,
)

try:  # Optional at import-time for graceful CLI failure if packaging is incomplete.
    from cryptography import x509
except Exception:  # pragma: no cover - dependency is declared in pyproject.
    x509 = None


@dataclass(slots=True)
class ParsedPacket:
    timestamp: float
    length: int
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    transport: str = "OTHER"
    application: str = "OTHER"
    payload_bytes: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    app_payload: bytes = field(default=b"", repr=False)

    def as_event(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src": self.src,
            "dst": self.dst,
            "sport": self.sport,
            "dport": self.dport,
            "transport": self.transport,
            "application": self.application,
            "length": self.length,
            "payload_bytes": self.payload_bytes,
            **self.metadata,
        }


def parse_packet(timestamp: float, raw: bytes, linktype: int = DLT_EN10MB) -> ParsedPacket | None:
    """Parse a packet frame using bounded protocol decoders.

    Supported link layers: Ethernet, Linux cooked v1/v2, BSD null/loopback,
    raw IP, and dedicated IPv4/IPv6 DLTs.
    """
    if linktype == DLT_EN10MB:
        return parse_ethernet(timestamp, raw)
    if linktype == DLT_LINUX_SLL:
        return _parse_linux_sll(timestamp, raw)
    if linktype == DLT_LINUX_SLL2:
        return _parse_linux_sll2(timestamp, raw)
    if linktype in {DLT_NULL, DLT_LOOP}:
        return _parse_loopback(timestamp, raw, network_order=(linktype == DLT_LOOP))
    if linktype in {DLT_RAW, DLT_IPV4, DLT_IPV6} and raw:
        if linktype == DLT_IPV4:
            return _parse_ipv4(timestamp, raw, 0)
        if linktype == DLT_IPV6:
            return _parse_ipv6(timestamp, raw, 0)
        version = raw[0] >> 4
        if version == 4:
            return _parse_ipv4(timestamp, raw, 0)
        if version == 6:
            return _parse_ipv6(timestamp, raw, 0)
    return None


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(timestamp: float, raw: bytes) -> ParsedPacket | None:
    if len(raw) < 14:
        return None
    dst_mac = _mac(raw[:6])
    src_mac = _mac(raw[6:12])
    offset = 14
    ethertype = struct.unpack("!H", raw[12:14])[0]
    vlan_ids: list[int] = []
    while ethertype in {0x8100, 0x88A8, 0x9100}:
        if len(raw) < offset + 4:
            return None
        tci, ethertype = struct.unpack("!HH", raw[offset:offset + 4])
        vlan_ids.append(tci & 0x0FFF)
        offset += 4
    l2 = {"src_mac": src_mac, "dst_mac": dst_mac}
    if vlan_ids:
        l2["vlan_ids"] = vlan_ids
    if ethertype == 0x0800:
        packet = _parse_ipv4(timestamp, raw, offset)
    elif ethertype == 0x86DD:
        packet = _parse_ipv6(timestamp, raw, offset)
    elif ethertype == 0x0806:
        packet = _parse_arp(timestamp, raw[offset:])
    else:
        packet = ParsedPacket(timestamp=timestamp, length=len(raw), transport="L2", application="OTHER")
        packet.metadata["ethertype"] = f"0x{ethertype:04x}"
    if packet:
        packet.metadata["l2"] = l2
    return packet


def _parse_linux_sll(timestamp: float, raw: bytes) -> ParsedPacket | None:
    if len(raw) < 16:
        return None
    packet_type, arphrd, addr_len = struct.unpack("!HHH", raw[:6])
    address = raw[6:14][: min(addr_len, 8)]
    protocol = struct.unpack("!H", raw[14:16])[0]
    packet = _parse_ethertype_payload(timestamp, raw, 16, protocol)
    if packet:
        packet.metadata["sll"] = {
            "version": 1,
            "packet_type": packet_type,
            "arphrd": arphrd,
            "address": _mac(address) if address else None,
        }
    return packet


def _parse_linux_sll2(timestamp: float, raw: bytes) -> ParsedPacket | None:
    if len(raw) < 20:
        return None
    protocol, _, if_index, arphrd, packet_type, addr_len = struct.unpack("!HHIHBB", raw[:12])
    address = raw[12:20][: min(addr_len, 8)]
    packet = _parse_ethertype_payload(timestamp, raw, 20, protocol)
    if packet:
        packet.metadata["sll"] = {
            "version": 2,
            "packet_type": packet_type,
            "arphrd": arphrd,
            "if_index": if_index,
            "address": _mac(address) if address else None,
        }
    return packet


def _parse_ethertype_payload(timestamp: float, raw: bytes, offset: int, protocol: int) -> ParsedPacket | None:
    if protocol == 0x0800:
        return _parse_ipv4(timestamp, raw, offset)
    if protocol == 0x86DD:
        return _parse_ipv6(timestamp, raw, offset)
    if protocol == 0x0806:
        return _parse_arp(timestamp, raw[offset:])
    packet = ParsedPacket(timestamp=timestamp, length=len(raw), transport="L2", application="OTHER")
    packet.metadata["ethertype"] = f"0x{protocol:04x}"
    return packet


def _parse_loopback(timestamp: float, raw: bytes, network_order: bool) -> ParsedPacket | None:
    if len(raw) < 4:
        return None
    family = struct.unpack("!I" if network_order else "=I", raw[:4])[0]
    # AF_INET is stable at 2. AF_INET6 differs across BSD families, hence the common set.
    if family == 2:
        return _parse_ipv4(timestamp, raw, 4)
    if family in {10, 24, 28, 30}:
        return _parse_ipv6(timestamp, raw, 4)
    return ParsedPacket(timestamp=timestamp, length=len(raw), transport="LOOP", application="OTHER", metadata={"address_family": family})


def _parse_arp(timestamp: float, payload: bytes) -> ParsedPacket | None:
    if len(payload) < 28:
        return None
    htype, ptype, hlen, plen, operation = struct.unpack("!HHBBH", payload[:8])
    required = 8 + 2 * hlen + 2 * plen
    if hlen > 32 or plen > 32 or len(payload) < required:
        return None
    cursor = 8
    sha = payload[cursor:cursor + hlen]
    cursor += hlen
    spa = payload[cursor:cursor + plen]
    cursor += plen
    tha = payload[cursor:cursor + hlen]
    cursor += hlen
    tpa = payload[cursor:cursor + plen]
    source_ip = target_ip = None
    if ptype == 0x0800 and plen == 4:
        source_ip = str(ipaddress.IPv4Address(spa))
        target_ip = str(ipaddress.IPv4Address(tpa))
    packet = ParsedPacket(
        timestamp=timestamp,
        length=len(payload),
        src=source_ip,
        dst=target_ip,
        transport="ARP",
        application="ARP",
    )
    packet.metadata["arp"] = {
        "operation": operation,
        "operation_name": {1: "request", 2: "reply"}.get(operation, str(operation)),
        "hardware_type": htype,
        "protocol_type": f"0x{ptype:04x}",
        "sender_mac": _mac(sha),
        "sender_ip": source_ip,
        "target_mac": _mac(tha),
        "target_ip": target_ip,
    }
    return packet


def _parse_ipv4(timestamp: float, raw: bytes, offset: int) -> ParsedPacket | None:
    if len(raw) < offset + 20:
        return None
    first = raw[offset]
    if first >> 4 != 4:
        return None
    ihl = (first & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl:
        return None
    total_len = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
    if total_len and total_len < ihl:
        return None
    ident, frag = struct.unpack("!HH", raw[offset + 4:offset + 8])
    proto = raw[offset + 9]
    src = str(ipaddress.IPv4Address(raw[offset + 12:offset + 16]))
    dst = str(ipaddress.IPv4Address(raw[offset + 16:offset + 20]))
    end = min(len(raw), offset + (total_len or len(raw) - offset))
    payload = raw[offset + ihl:end]
    fragment_offset = (frag & 0x1FFF) * 8
    more_fragments = bool(frag & 0x2000)
    if fragment_offset:
        packet = ParsedPacket(timestamp, len(raw), src, dst, transport=f"IP/{proto}", application="IP-FRAGMENT", payload_bytes=len(payload))
    else:
        packet = _parse_transport(timestamp, len(raw), src, dst, proto, payload)
    packet.metadata["ip"] = {
        "version": 4,
        "ttl": raw[offset + 8],
        "id": ident,
        "fragment_offset": fragment_offset,
        "more_fragments": more_fragments,
        "fragmented": more_fragments or fragment_offset > 0,
    }
    return packet


def _parse_ipv6(timestamp: float, raw: bytes, offset: int) -> ParsedPacket | None:
    if len(raw) < offset + 40 or raw[offset] >> 4 != 6:
        return None
    payload_len = struct.unpack("!H", raw[offset + 4:offset + 6])[0]
    next_header = raw[offset + 6]
    src = str(ipaddress.IPv6Address(raw[offset + 8:offset + 24]))
    dst = str(ipaddress.IPv6Address(raw[offset + 24:offset + 40]))
    cursor = offset + 40
    end = min(len(raw), cursor + payload_len) if payload_len else len(raw)
    extension_headers: list[int] = []
    fragment_info: dict[str, Any] | None = None

    while next_header in {0, 43, 44, 60, 51} and cursor < end:
        extension_headers.append(next_header)
        if next_header == 44:
            if cursor + 8 > end:
                return None
            nh = raw[cursor]
            fragment_field = struct.unpack("!H", raw[cursor + 2:cursor + 4])[0]
            fragment_info = {
                "offset": ((fragment_field >> 3) & 0x1FFF) * 8,
                "more_fragments": bool(fragment_field & 1),
                "id": struct.unpack("!I", raw[cursor + 4:cursor + 8])[0],
            }
            next_header = nh
            cursor += 8
            if fragment_info["offset"]:
                packet = ParsedPacket(timestamp, len(raw), src, dst, transport=f"IP/{next_header}", application="IP-FRAGMENT", payload_bytes=max(0, end - cursor))
                packet.metadata["ip"] = {
                    "version": 6,
                    "hop_limit": raw[offset + 7],
                    "extension_headers": extension_headers,
                    "fragment": fragment_info,
                    "fragmented": True,
                }
                return packet
        elif next_header == 51:  # Authentication Header length is in 32-bit words minus 2.
            if cursor + 2 > end:
                return None
            nh = raw[cursor]
            ext_len = (raw[cursor + 1] + 2) * 4
            if ext_len < 8 or cursor + ext_len > end:
                return None
            next_header = nh
            cursor += ext_len
        else:
            if cursor + 2 > end:
                return None
            nh = raw[cursor]
            ext_len = (raw[cursor + 1] + 1) * 8
            if ext_len < 8 or cursor + ext_len > end:
                return None
            next_header = nh
            cursor += ext_len
    packet = _parse_transport(timestamp, len(raw), src, dst, next_header, raw[cursor:end])
    packet.metadata["ip"] = {
        "version": 6,
        "hop_limit": raw[offset + 7],
        "extension_headers": extension_headers,
        "fragment": fragment_info,
        "fragmented": bool(fragment_info),
    }
    return packet


def _parse_transport(timestamp: float, frame_len: int, src: str, dst: str, proto: int, payload: bytes) -> ParsedPacket:
    if proto == 6 and len(payload) >= 20:
        sport, dport = struct.unpack("!HH", payload[:4])
        seq, ack = struct.unpack("!II", payload[4:12])
        data_offset = ((payload[12] >> 4) & 0xF) * 4
        if data_offset < 20 or data_offset > len(payload):
            data_offset = 20
        app_payload = payload[data_offset:]
        flags = struct.unpack("!H", payload[12:14])[0] & 0x01FF
        packet = ParsedPacket(timestamp, frame_len, src, dst, sport, dport, "TCP", payload_bytes=len(app_payload), app_payload=app_payload)
        packet.metadata["tcp"] = {
            "seq": seq,
            "ack": ack,
            "flags": flags,
            "syn": bool(flags & 0x002),
            "ack_flag": bool(flags & 0x010),
            "fin": bool(flags & 0x001),
            "rst": bool(flags & 0x004),
        }
        packet.metadata["tcp_seq"] = seq  # backwards compatibility for stream code.
        packet.metadata["tcp_flags"] = flags
        _classify_tcp(packet, app_payload)
        return packet
    if proto == 17 and len(payload) >= 8:
        sport, dport, udp_len = struct.unpack("!HHH", payload[:6])
        effective = len(payload) if udp_len == 0 else min(len(payload), max(8, udp_len))
        app_payload = payload[8:effective]
        packet = ParsedPacket(timestamp, frame_len, src, dst, sport, dport, "UDP", payload_bytes=len(app_payload), app_payload=app_payload)
        _classify_udp(packet, app_payload)
        return packet
    if proto in {1, 58}:
        return _parse_icmp(timestamp, frame_len, src, dst, proto, payload)
    return ParsedPacket(timestamp, frame_len, src, dst, transport=f"IP/{proto}", payload_bytes=len(payload))


def _parse_icmp(timestamp: float, frame_len: int, src: str, dst: str, proto: int, payload: bytes) -> ParsedPacket:
    packet = ParsedPacket(timestamp, frame_len, src, dst, transport="ICMPv6" if proto == 58 else "ICMP", application="ICMPv6" if proto == 58 else "ICMP", payload_bytes=max(0, len(payload) - 4))
    if len(payload) >= 4:
        icmp_type, code = payload[0], payload[1]
        names4 = {0: "echo-reply", 3: "destination-unreachable", 5: "redirect", 8: "echo-request", 11: "time-exceeded"}
        names6 = {1: "destination-unreachable", 2: "packet-too-big", 3: "time-exceeded", 128: "echo-request", 129: "echo-reply"}
        packet.metadata["icmp"] = {
            "type": icmp_type,
            "code": code,
            "name": (names6 if proto == 58 else names4).get(icmp_type, str(icmp_type)),
        }
        if (proto == 1 and icmp_type in {0, 8}) or (proto == 58 and icmp_type in {128, 129}):
            if len(payload) >= 8:
                ident, sequence = struct.unpack("!HH", payload[4:8])
                packet.metadata["icmp"].update({"id": ident, "sequence": sequence})
    return packet


def _classify_udp(packet: ParsedPacket, payload: bytes) -> None:
    ports = {packet.sport, packet.dport}
    if 53 in ports:
        dns = parse_dns(payload)
        if dns:
            packet.application = "DNS"
            packet.metadata["dns"] = dns
            return
    if ports & {67, 68}:
        dhcp = parse_dhcp(payload)
        if dhcp:
            packet.application = "DHCP"
            packet.metadata["dhcp"] = dhcp
            return
    if 123 in ports:
        ntp = parse_ntp(payload)
        if ntp:
            packet.application = "NTP"
            packet.metadata["ntp"] = ntp
            return
    packet.application = "UDP"


def _classify_tcp(packet: ParsedPacket, payload: bytes) -> None:
    if not payload:
        packet.application = "TCP"
        return
    if packet.sport == 53 or packet.dport == 53:
        dns_payload = payload
        if len(payload) >= 2:
            declared = struct.unpack("!H", payload[:2])[0]
            if 0 < declared <= len(payload) - 2:
                dns_payload = payload[2:2 + declared]
        dns = parse_dns(dns_payload)
        if dns:
            packet.application = "DNS"
            packet.metadata["dns"] = dns
            return
    http = parse_http(payload)
    if http:
        packet.application = "HTTP"
        packet.metadata["http"] = http
        return
    tls = parse_tls(payload)
    if tls:
        packet.application = "TLS"
        packet.metadata["tls"] = tls
        return
    packet.application = "TCP"


def _decode_dns_name(message: bytes, offset: int, depth: int = 0, visited: set[int] | None = None) -> tuple[str, int]:
    if depth > 16:
        raise ValueError("DNS compression depth exceeded")
    visited = set() if visited is None else visited
    labels: list[str] = []
    cursor = offset
    return_offset = None
    while cursor < len(message):
        if cursor in visited:
            raise ValueError("DNS compression loop")
        visited.add(cursor)
        length = message[cursor]
        if length == 0:
            cursor += 1
            return ".".join(labels), return_offset or cursor
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise ValueError("Truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message):
                raise ValueError("Invalid DNS pointer")
            pointed, _ = _decode_dns_name(message, pointer, depth + 1, visited)
            if pointed:
                labels.append(pointed)
            return_offset = return_offset or cursor + 2
            return ".".join(labels), return_offset
        if length > 63 or cursor + 1 + length > len(message):
            raise ValueError("Invalid DNS label")
        raw = message[cursor + 1:cursor + 1 + length]
        labels.append(raw.decode("utf-8", "replace"))
        cursor += 1 + length
    raise ValueError("Unterminated DNS name")


def _parse_dns_rr(payload: bytes, cursor: int) -> tuple[dict[str, Any], int]:
    name, cursor = _decode_dns_name(payload, cursor)
    if cursor + 10 > len(payload):
        raise ValueError("Truncated DNS resource record")
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", payload[cursor:cursor + 10])
    cursor += 10
    rdata_offset = cursor
    if cursor + rdlen > len(payload):
        raise ValueError("Truncated DNS RDATA")
    rdata = payload[cursor:cursor + rdlen]
    cursor += rdlen
    value: Any = None
    if rtype == 1 and rdlen == 4:
        value = str(ipaddress.IPv4Address(rdata))
    elif rtype == 28 and rdlen == 16:
        value = str(ipaddress.IPv6Address(rdata))
    elif rtype in {2, 5, 12}:
        value, _ = _decode_dns_name(payload, rdata_offset)
    elif rtype == 15 and rdlen >= 3:
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = _decode_dns_name(payload, rdata_offset + 2)
        value = {"preference": preference, "exchange": exchange}
    elif rtype == 16:
        chunks = []
        pos = 0
        while pos < len(rdata):
            size = rdata[pos]
            pos += 1
            if pos + size > len(rdata):
                break
            chunks.append(rdata[pos:pos + size].decode("utf-8", "replace"))
            pos += size
        value = "".join(chunks)[:4096]
    return {"name": name.lower().rstrip("."), "type": rtype, "class": rclass, "ttl": ttl, "value": value}, cursor


def parse_dns(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 12:
        return None
    try:
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
        if qd > 256 or an > 512 or ns > 512 or ar > 512:
            return None
        cursor = 12
        questions = []
        for _ in range(qd):
            name, cursor = _decode_dns_name(payload, cursor)
            if cursor + 4 > len(payload):
                raise ValueError
            qtype, qclass = struct.unpack("!HH", payload[cursor:cursor + 4])
            cursor += 4
            questions.append({"name": name.lower().rstrip("."), "type": qtype, "class": qclass})

        answers, authority, additional = [], [], []
        for target, count in ((answers, an), (authority, ns), (additional, ar)):
            for _ in range(count):
                row, cursor = _parse_dns_rr(payload, cursor)
                target.append(row)
        return {
            "id": txid,
            "response": bool(flags & 0x8000),
            "opcode": (flags >> 11) & 0xF,
            "authoritative": bool(flags & 0x0400),
            "truncated": bool(flags & 0x0200),
            "recursion_desired": bool(flags & 0x0100),
            "recursion_available": bool(flags & 0x0080),
            "rcode": flags & 0xF,
            "questions": questions,
            "answers": answers,
            "authority": authority,
            "additional": additional,
            "counts": {"questions": qd, "answers": an, "authority": ns, "additional": ar},
        }
    except (ValueError, struct.error):
        return None


HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}


def parse_http(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 8:
        return None
    head = payload[:32768]
    line_end = head.find(b"\r\n")
    if line_end < 0:
        return None
    first = head[:line_end].split(b" ")
    is_request = len(first) >= 3 and first[0] in HTTP_METHODS and first[-1].startswith(b"HTTP/")
    is_response = len(first) >= 2 and first[0].startswith(b"HTTP/")
    if not (is_request or is_response):
        return None
    header_end = head.find(b"\r\n\r\n")
    header_blob = head[line_end + 2: header_end if header_end >= 0 else len(head)]
    headers: dict[str, str] = {}
    for raw_line in header_blob.split(b"\r\n")[:200]:
        if b":" not in raw_line:
            continue
        key, value = raw_line.split(b":", 1)
        key_s = key.decode("latin1", "replace").strip().lower()
        value_s = value.decode("latin1", "replace").strip()
        if len(key_s) <= 128 and len(value_s) <= 4096:
            # Deliberately redact sensitive values; only presence is exposed below.
            if key_s not in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
                headers[key_s] = value_s
            else:
                headers[key_s] = "<redacted>"
    result: dict[str, Any] = {
        "kind": "request" if is_request else "response",
        "version": first[-1].decode("ascii", "replace") if is_request else first[0].decode("ascii", "replace"),
        "host": headers.get("host"),
        "user_agent": headers.get("user-agent"),
        "server": headers.get("server"),
        "content_type": headers.get("content-type"),
        "content_length": _safe_int(headers.get("content-length")),
        "authorization_present": "authorization" in headers or "proxy-authorization" in headers,
        "cookie_present": "cookie" in headers or "set-cookie" in headers,
    }
    if is_request:
        result.update({"method": first[0].decode("ascii", "replace"), "uri": first[1].decode("latin1", "replace")[:4096]})
    else:
        result["status"] = _safe_int(first[1].decode("ascii", "replace"))
        result["reason"] = b" ".join(first[2:]).decode("latin1", "replace")[:256] if len(first) > 2 else None
    return result


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_dhcp(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    op, htype, hlen, hops, xid = struct.unpack("!BBBBI", payload[:8])
    ciaddr = str(ipaddress.IPv4Address(payload[12:16]))
    yiaddr = str(ipaddress.IPv4Address(payload[16:20]))
    siaddr = str(ipaddress.IPv4Address(payload[20:24]))
    giaddr = str(ipaddress.IPv4Address(payload[24:28]))
    chaddr = _mac(payload[28:28 + min(hlen, 16)])
    options: dict[int, bytes] = {}
    cursor = 240
    while cursor < len(payload):
        code = payload[cursor]
        cursor += 1
        if code == 255:
            break
        if code == 0:
            continue
        if cursor >= len(payload):
            break
        length = payload[cursor]
        cursor += 1
        if cursor + length > len(payload):
            break
        options[code] = payload[cursor:cursor + length]
        cursor += length
    msg_type = options.get(53, b"\x00")[0] if options.get(53) else 0
    names = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}
    host = options.get(12, b"").decode("utf-8", "replace")[:255] or None
    requested = str(ipaddress.IPv4Address(options[50])) if len(options.get(50, b"")) == 4 else None
    server_id = str(ipaddress.IPv4Address(options[54])) if len(options.get(54, b"")) == 4 else None
    return {
        "op": op,
        "hardware_type": htype,
        "hops": hops,
        "xid": xid,
        "message_type": msg_type,
        "message_name": names.get(msg_type, str(msg_type)),
        "client_mac": chaddr,
        "client_ip": ciaddr,
        "your_ip": yiaddr,
        "server_ip": siaddr,
        "relay_ip": giaddr,
        "requested_ip": requested,
        "server_identifier": server_id,
        "host_name": host,
    }


def parse_ntp(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 48:
        return None
    first = payload[0]
    li = (first >> 6) & 0x3
    version = (first >> 3) & 0x7
    mode = first & 0x7
    if version == 0 or mode == 0:
        return None
    return {"leap": li, "version": version, "mode": mode, "stratum": payload[1], "poll": struct.unpack("!b", payload[2:3])[0]}


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _parse_extensions(blob: bytes) -> list[tuple[int, bytes]]:
    out = []
    cursor = 0
    while cursor + 4 <= len(blob):
        ext_type, ext_len = struct.unpack("!HH", blob[cursor:cursor + 4])
        cursor += 4
        if cursor + ext_len > len(blob):
            break
        out.append((ext_type, blob[cursor:cursor + ext_len]))
        cursor += ext_len
    return out


def parse_tls_client_hello(payload: bytes) -> dict[str, Any] | None:
    tls = parse_tls(payload)
    if tls and tls.get("kind") == "client_hello":
        return tls
    return None


def parse_tls(payload: bytes) -> dict[str, Any] | None:
    """Parse the first useful plaintext TLS handshake message in a byte stream.

    ClientHello and ServerHello work for TLS 1.2/1.3 handshakes. Certificate
    metadata is extractable for plaintext certificate messages (typically TLS 1.2);
    TLS 1.3 encrypts post-ServerHello handshake messages without key material.
    """
    if len(payload) < 5:
        return None
    cursor = 0
    while cursor + 5 <= len(payload):
        content_type = payload[cursor]
        record_version = struct.unpack("!H", payload[cursor + 1:cursor + 3])[0]
        record_len = struct.unpack("!H", payload[cursor + 3:cursor + 5])[0]
        if record_len > 18432 or cursor + 5 + record_len > len(payload):
            return None
        record = payload[cursor + 5:cursor + 5 + record_len]
        cursor += 5 + record_len
        if content_type != 22:
            continue
        hcur = 0
        while hcur + 4 <= len(record):
            htype = record[hcur]
            hlen = int.from_bytes(record[hcur + 1:hcur + 4], "big")
            hcur += 4
            if hcur + hlen > len(record):
                break
            body = record[hcur:hcur + hlen]
            hcur += hlen
            if htype == 1:
                parsed = _parse_client_hello_body(body)
                if parsed:
                    return {"kind": "client_hello", "record_version": f"0x{record_version:04x}", **parsed}
            elif htype == 2:
                parsed = _parse_server_hello_body(body)
                if parsed:
                    return {"kind": "server_hello", "record_version": f"0x{record_version:04x}", **parsed}
            elif htype == 11:
                parsed = _parse_certificate_body(body)
                if parsed:
                    return {"kind": "certificate", "record_version": f"0x{record_version:04x}", **parsed}
    return None


def _parse_client_hello_body(body: bytes) -> dict[str, Any] | None:
    if len(body) < 38:
        return None
    version = struct.unpack("!H", body[:2])[0]
    cursor = 34
    sid_len = body[cursor]
    cursor += 1 + sid_len
    if cursor + 2 > len(body):
        return None
    cipher_len = struct.unpack("!H", body[cursor:cursor + 2])[0]
    cursor += 2
    if cursor + cipher_len > len(body) or cipher_len % 2:
        return None
    ciphers = list(struct.unpack("!" + "H" * (cipher_len // 2), body[cursor:cursor + cipher_len]))
    cursor += cipher_len
    if cursor >= len(body):
        return None
    comp_len = body[cursor]
    cursor += 1 + comp_len
    if cursor + 2 > len(body):
        extensions_blob = b""
    else:
        extensions_len = struct.unpack("!H", body[cursor:cursor + 2])[0]
        cursor += 2
        extensions_blob = body[cursor:min(len(body), cursor + extensions_len)]

    extensions = _parse_extensions(extensions_blob)
    ext_types: list[int] = []
    curves: list[int] = []
    point_formats: list[int] = []
    sni = None
    alpn: list[str] = []
    supported_versions: list[str] = []

    for ext_type, value in extensions:
        ext_types.append(ext_type)
        try:
            if ext_type == 0 and len(value) >= 5:
                list_len = struct.unpack("!H", value[:2])[0]
                pos = 2
                while pos + 3 <= min(len(value), 2 + list_len):
                    name_type = value[pos]
                    name_len = struct.unpack("!H", value[pos + 1:pos + 3])[0]
                    pos += 3
                    if pos + name_len > len(value):
                        break
                    if name_type == 0:
                        sni = value[pos:pos + name_len].decode("idna").lower()
                        break
                    pos += name_len
            elif ext_type == 16 and len(value) >= 2:
                total = struct.unpack("!H", value[:2])[0]
                pos = 2
                while pos < min(len(value), total + 2):
                    plen = value[pos]
                    pos += 1
                    if pos + plen > len(value):
                        break
                    alpn.append(value[pos:pos + plen].decode("ascii", "replace"))
                    pos += plen
            elif ext_type == 10 and len(value) >= 2:
                total = struct.unpack("!H", value[:2])[0]
                raw_curves = value[2:2 + total]
                if len(raw_curves) % 2 == 0:
                    curves = list(struct.unpack("!" + "H" * (len(raw_curves) // 2), raw_curves))
            elif ext_type == 11 and value:
                total = value[0]
                point_formats = list(value[1:1 + total])
            elif ext_type == 43 and value:
                total = value[0]
                raw_versions = value[1:1 + total]
                for i in range(0, len(raw_versions) - 1, 2):
                    v = struct.unpack("!H", raw_versions[i:i + 2])[0]
                    supported_versions.append(f"0x{v:04x}")
        except (UnicodeError, struct.error):
            continue

    clean_ciphers = [v for v in ciphers if not _is_grease(v)]
    clean_ext = [v for v in ext_types if not _is_grease(v)]
    clean_curves = [v for v in curves if not _is_grease(v)]
    ja3 = ",".join([
        str(version),
        "-".join(map(str, clean_ciphers)),
        "-".join(map(str, clean_ext)),
        "-".join(map(str, clean_curves)),
        "-".join(map(str, point_formats)),
    ])
    return {
        "sni": sni,
        "alpn": alpn,
        "version": f"0x{version:04x}",
        "supported_versions": supported_versions,
        "ja3": ja3,
        "ja3_hash": hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest(),
        "cipher_count": len(clean_ciphers),
        "extension_count": len(clean_ext),
    }


def _parse_server_hello_body(body: bytes) -> dict[str, Any] | None:
    if len(body) < 38:
        return None
    version = struct.unpack("!H", body[:2])[0]
    cursor = 34
    sid_len = body[cursor]
    cursor += 1 + sid_len
    if cursor + 3 > len(body):
        return None
    cipher = struct.unpack("!H", body[cursor:cursor + 2])[0]
    compression = body[cursor + 2]
    cursor += 3
    selected_version = None
    alpn = None
    if cursor + 2 <= len(body):
        ext_len = struct.unpack("!H", body[cursor:cursor + 2])[0]
        cursor += 2
        for ext_type, value in _parse_extensions(body[cursor:cursor + ext_len]):
            if ext_type == 43 and len(value) == 2:
                selected_version = f"0x{struct.unpack('!H', value)[0]:04x}"
            elif ext_type == 16 and len(value) >= 3:
                # ServerHello ALPN extension contains a 2-byte list length + one protocol.
                plen = value[2] if len(value) > 2 else 0
                if 3 + plen <= len(value):
                    alpn = value[3:3 + plen].decode("ascii", "replace")
    return {
        "version": f"0x{version:04x}",
        "selected_version": selected_version,
        "cipher": f"0x{cipher:04x}",
        "compression": compression,
        "alpn": alpn,
    }


def _parse_certificate_body(body: bytes) -> dict[str, Any] | None:
    if len(body) < 6:
        return None
    chain_len = int.from_bytes(body[:3], "big")
    if chain_len + 3 > len(body):
        return None
    cursor = 3
    certificates = []
    while cursor + 3 <= min(len(body), 3 + chain_len) and len(certificates) < 20:
        cert_len = int.from_bytes(body[cursor:cursor + 3], "big")
        cursor += 3
        if cert_len <= 0 or cursor + cert_len > len(body):
            break
        der = body[cursor:cursor + cert_len]
        cursor += cert_len
        certificates.append(_decode_certificate(der))
    if not certificates:
        return None
    return {"chain_length": len(certificates), "certificates": certificates}


def _decode_certificate(der: bytes) -> dict[str, Any]:
    sha256 = hashlib.sha256(der).hexdigest()
    row: dict[str, Any] = {"sha256": sha256, "size": len(der)}
    if x509 is None:
        return row
    try:
        cert = x509.load_der_x509_certificate(der)
        row.update({
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": format(cert.serial_number, "x"),
            "not_before": cert.not_valid_before_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "not_after": cert.not_valid_after_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "self_signed_name": cert.subject == cert.issuer,
        })
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            row["dns_names"] = san.get_values_for_type(x509.DNSName)[:100]
            row["ip_addresses"] = [str(x) for x in san.get_values_for_type(x509.IPAddress)[:100]]
        except x509.ExtensionNotFound:
            row["dns_names"] = []
            row["ip_addresses"] = []
    except Exception:
        row["parse_error"] = True
    return row
