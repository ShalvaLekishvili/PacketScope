from __future__ import annotations

from pathlib import Path
import ipaddress
import socket
import struct


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ethernet(payload: bytes, ethertype: int = 0x0800, src: str = "66:77:88:99:aa:bb", dst: str = "00:11:22:33:44:55") -> bytes:
    mac = lambda value: bytes.fromhex(value.replace(":", ""))
    return mac(dst) + mac(src) + struct.pack("!H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 1, flags_frag: int = 0x4000) -> bytes:
    version_ihl = 0x45
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s", version_ihl, 0, total, ident & 0xFFFF, flags_frag, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst)
    )
    csum = _checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport: int, dport: int, payload: bytes = b"", seq: int = 1, flags: int = 0x18) -> bytes:
    offset_flags = (5 << 12) | flags
    return struct.pack("!HHIIHHHH", sport, dport, seq, 1, offset_flags, 64240, 0, 0) + payload


def _icmp_echo(ident: int, sequence: int, payload: bytes = b"PacketScope") -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, ident, sequence)
    checksum = _checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, checksum, ident, sequence) + payload


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def dns_query(name: str, txid: int = 0x1337) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(name: str, address: str, txid: int) -> bytes:
    question = _dns_name(name) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(address)
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer


def tls_client_hello(sni: str) -> bytes:
    version = 0x0303
    random = bytes(range(32))
    ciphers = [0x1301, 0x1302, 0xC02F, 0xC030]
    cipher_blob = b"".join(struct.pack("!H", x) for x in ciphers)
    sni_name = sni.encode()
    sni_list = b"\x00" + struct.pack("!H", len(sni_name)) + sni_name
    ext_sni = struct.pack("!HHH", 0, len(sni_list) + 2, len(sni_list)) + sni_list
    alpn_value = b"\x00\x03\x02h2"
    ext_alpn = struct.pack("!HH", 16, len(alpn_value)) + alpn_value
    vers_value = b"\x04\x03\x04\x03\x03"
    ext_versions = struct.pack("!HH", 43, len(vers_value)) + vers_value
    curves_value = struct.pack("!H", 4) + struct.pack("!HH", 29, 23)
    ext_curves = struct.pack("!HH", 10, len(curves_value)) + curves_value
    points_value = b"\x01\x00"
    ext_points = struct.pack("!HH", 11, len(points_value)) + points_value
    extensions = ext_sni + ext_curves + ext_points + ext_alpn + ext_versions
    body = (
        struct.pack("!H", version) + random + b"\x00"
        + struct.pack("!H", len(cipher_blob)) + cipher_blob
        + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _arp_reply(sender_ip: str, sender_mac: str, target_ip: str, target_mac: str) -> bytes:
    mac = lambda value: bytes.fromhex(value.replace(":", ""))
    payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    payload += mac(sender_mac) + socket.inet_aton(sender_ip) + mac(target_mac) + socket.inet_aton(target_ip)
    return _ethernet(payload, 0x0806, src=sender_mac, dst=target_mac)


def _dhcp_offer(server_ip: str, offered_ip: str, xid: int, client_mac: str = "02:00:00:00:00:25") -> bytes:
    chaddr = bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2, 1, 6, 0, xid, 0, 0,
        b"\x00" * 4,
        socket.inet_aton(offered_ip),
        socket.inet_aton(server_ip),
        b"\x00" * 4,
        chaddr,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = b"\x63\x82\x53\x63" + b"\x35\x01\x02" + b"\x36\x04" + socket.inet_aton(server_ip) + b"\xff"
    return fixed + options


def _ntp_request() -> bytes:
    # LI=0, version=4, client mode=3.
    return bytes([0x23, 0, 6, 0xEC]) + b"\x00" * 44


def generate_demo(path: str | Path) -> Path:
    """Generate a deterministic, fully synthetic capture for safe demonstrations/tests."""
    path = Path(path)
    frames: list[tuple[float, bytes]] = []
    ident = 100

    def add(ts: float, src: str, dst: str, proto: int, transport: bytes):
        nonlocal ident
        frames.append((ts, _ethernet(_ipv4(src, dst, proto, transport, ident))))
        ident += 1

    # Normal DNS transaction.
    add(1.0, "10.0.0.25", "1.1.1.1", 17, _udp(53001, 53, dns_query("updates.example.org", 0x1001)))
    add(1.04, "1.1.1.1", "10.0.0.25", 17, _udp(53, 53001, dns_response("updates.example.org", "192.0.2.20", 0x1001)))

    # Normal HTTP transaction.
    http = b"GET /release-notes HTTP/1.1\r\nHost: intranet.example.org\r\nUser-Agent: PacketScope-Demo/2.0\r\nAccept: */*\r\n\r\n"
    add(2.0, "10.0.0.25", "192.0.2.20", 6, _tcp(50001, 80, http, 10))
    response = b"HTTP/1.1 200 OK\r\nServer: demo-web\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
    add(2.08, "192.0.2.20", "10.0.0.25", 6, _tcp(80, 50001, response, 50))

    # Encoded-looking subdomain sequence to demonstrate aggregate DNS channel detection.
    labels = [
        "k7x9q2m4v8n1p6r3", "m4z8c1q7v2x9n5k3", "p8v2m7q1x4n9c6k5", "r3n8x1v6m2q9k4c7",
        "v6q1n9m3x8k2c7p4", "x2m8v4q9n1k6c3r7", "c9v3x7m1q6n2k8p4", "n1q7v4m9x3k8c2r6",
        "q8m2x6v1n7k4c9p3", "z4v9m1q8x2n6k3c7",
    ]
    for idx, label in enumerate(labels):
        add(3.0 + idx * 0.15, "10.0.0.44", "1.1.1.1", 17, _udp(54000 + idx, 53, dns_query(f"{label}.telemetry.example", 0x2000 + idx)))

    # Cleartext authorization to an IP-literal host. Value is synthetic and never exposed by parser output.
    risky_http = (
        b"POST /api/sync HTTP/1.1\r\nHost: 198.51.100.77\r\nUser-Agent: sync-client/0.9\r\n"
        b"Authorization: Basic ZGVtbzpkZW1v\r\nContent-Length: 0\r\n\r\n"
    )
    add(6.0, "10.0.0.40", "198.51.100.77", 6, _tcp(51000, 80, risky_http, 20))

    # Synthetic periodic TLS ClientHello traffic: every 10 seconds with zero jitter.
    hello = tls_client_hello("edge-poll.example.net")
    for idx, ts in enumerate([10, 20, 30, 40, 50, 60], start=1):
        add(float(ts), "10.0.0.25", "203.0.113.50", 6, _tcp(51515, 443, hello, 1000 + idx * 300))

    # Vertical SYN scan against one destination.
    for idx, port in enumerate(range(20, 35)):
        add(12.0 + idx * 0.02, "10.0.0.60", "10.0.0.70", 6, _tcp(40000 + idx, port, b"", 2000 + idx, flags=0x02))

    # Horizontal SMB service sweep.
    for idx in range(20):
        add(14.0 + idx * 0.02, "10.0.0.61", f"10.0.1.{10 + idx}", 6, _tcp(42000 + idx, 445, b"", 3000 + idx, flags=0x02))

    # ARP duplicate-address signal (can also represent HA/virtualization; analyzer says so).
    frames.append((16.0, _arp_reply("10.0.0.1", "00:aa:00:aa:00:aa", "10.0.0.25", "02:00:00:00:00:25")))
    frames.append((16.1, _arp_reply("10.0.0.1", "00:bb:00:bb:00:bb", "10.0.0.25", "02:00:00:00:00:25")))

    # Multiple DHCP responders.
    add(17.0, "10.0.0.2", "255.255.255.255", 17, _udp(67, 68, _dhcp_offer("10.0.0.2", "10.0.0.120", 0xAABBCCDD)))
    add(17.1, "10.0.0.3", "255.255.255.255", 17, _udp(67, 68, _dhcp_offer("10.0.0.3", "10.0.0.121", 0xAABBCCDD)))

    # ICMP burst from a synthetic monitoring/scanning host.
    for idx in range(20):
        add(18.0 + idx * 0.05, "10.0.0.80", "10.0.0.90", 1, _icmp_echo(0x4242, idx + 1))

    # NTP metadata and a benign TLS flow for richer protocol composition.
    add(22.0, "10.0.0.31", "192.0.2.123", 17, _udp(55000, 123, _ntp_request()))
    add(23.0, "10.0.0.31", "192.0.2.44", 6, _tcp(52000, 443, tls_client_hello("docs.example.org"), 5000))

    frames.sort(key=lambda item: item[0])
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
    return path
