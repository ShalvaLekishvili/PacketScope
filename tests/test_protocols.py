from __future__ import annotations

import socket
import struct

from packetscope.capture import DLT_IPV4, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_LOOP, DLT_NULL, DLT_RAW
from packetscope.demo import _dhcp_offer, _ethernet, _ipv4, _ntp_request, _tcp, _udp, dns_query, tls_client_hello
from packetscope.protocols import parse_dhcp, parse_dns, parse_http, parse_ntp, parse_packet, parse_tls


def test_dns_query_parser():
    result = parse_dns(dns_query("example.org", 42))
    assert result["id"] == 42
    assert result["questions"][0]["name"] == "example.org"
    assert result["response"] is False


def test_dns_compression_loop_is_rejected():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    assert parse_dns(header + b"\xc0\x0c" + struct.pack("!HH", 1, 1)) is None


def test_http_redacts_sensitive_header_values():
    payload = b"GET / HTTP/1.1\r\nHost: example.org\r\nAuthorization: Basic secret\r\nCookie: a=b\r\n\r\n"
    result = parse_http(payload)
    assert result["authorization_present"] is True
    assert result["cookie_present"] is True
    assert "secret" not in repr(result)
    assert "a=b" not in repr(result)


def test_http_response_parser():
    result = parse_http(b"HTTP/1.1 404 Not Found\r\nServer: unit\r\nContent-Length: 0\r\n\r\n")
    assert result["kind"] == "response"
    assert result["status"] == 404
    assert result["server"] == "unit"


def test_tls_client_hello_extracts_sni_and_ja3():
    result = parse_tls(tls_client_hello("edge.example.org"))
    assert result["kind"] == "client_hello"
    assert result["sni"] == "edge.example.org"
    assert len(result["ja3_hash"]) == 32
    assert "0x0304" in result["supported_versions"]


def test_tls_truncated_record_returns_none():
    hello = tls_client_hello("example.org")
    assert parse_tls(hello[:-5]) is None


def test_dhcp_offer_parser():
    result = parse_dhcp(_dhcp_offer("10.0.0.2", "10.0.0.120", 1234))
    assert result["message_name"] == "offer"
    assert result["server_identifier"] == "10.0.0.2"
    assert result["your_ip"] == "10.0.0.120"


def test_ntp_parser():
    result = parse_ntp(_ntp_request())
    assert result["version"] == 4
    assert result["mode"] == 3


def test_raw_ipv4_linktype():
    raw = _ipv4("10.0.0.1", "10.0.0.2", 17, _udp(1000, 53, dns_query("raw.example")))
    packet = parse_packet(1.0, raw, DLT_RAW)
    assert packet.src == "10.0.0.1"
    assert packet.application == "DNS"


def test_dedicated_ipv4_linktype():
    raw = _ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1000, 80, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert parse_packet(1.0, raw, DLT_IPV4).application == "HTTP"


def test_linux_sll_v1_linktype():
    ip = _ipv4("10.0.0.1", "10.0.0.2", 17, _udp(1, 2, b"x"))
    header = struct.pack("!HHH8sH", 0, 1, 6, bytes.fromhex("0011223344550000"), 0x0800)
    packet = parse_packet(1.0, header + ip, DLT_LINUX_SLL)
    assert packet.src == "10.0.0.1"
    assert packet.metadata["sll"]["version"] == 1


def test_linux_sll_v2_linktype():
    ip = _ipv4("10.0.0.3", "10.0.0.4", 17, _udp(1, 2, b"x"))
    header = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, 0, 6, bytes.fromhex("0011223344550000"))
    packet = parse_packet(1.0, header + ip, DLT_LINUX_SLL2)
    assert packet.dst == "10.0.0.4"
    assert packet.metadata["sll"]["if_index"] == 2


def test_null_loopback_linktype():
    ip = _ipv4("127.0.0.1", "127.0.0.1", 17, _udp(1, 2, b"x"))
    packet = parse_packet(1.0, struct.pack("=I", 2) + ip, DLT_NULL)
    assert packet.src == "127.0.0.1"


def test_network_order_loopback_linktype():
    ip = _ipv4("127.0.0.1", "127.0.0.1", 17, _udp(1, 2, b"x"))
    packet = parse_packet(1.0, struct.pack("!I", 2) + ip, DLT_LOOP)
    assert packet.dst == "127.0.0.1"


def test_vlan_metadata_is_preserved():
    inner = _ipv4("10.0.0.1", "10.0.0.2", 17, _udp(1, 2, b"x"))
    frame = bytes.fromhex("00112233445566778899aabb") + struct.pack("!HHH", 0x8100, 42, 0x0800) + inner
    packet = parse_packet(1.0, frame, 1)
    assert packet.metadata["l2"]["vlan_ids"] == [42]
