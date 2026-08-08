from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from .capture import SUPPORTED_LINKTYPES, capture_kind, iter_capture
from .config import AnalysisConfig
from .detectors import (
    apply_suppressions,
    assign_finding_ids,
    detect_arp,
    detect_beacons,
    detect_dhcp,
    detect_dns,
    detect_http,
    detect_icmp,
    detect_large_transfers,
    detect_scanning,
    detect_tls,
    ip_scope,
    risk_score,
)
from .protocols import parse_http, parse_packet, parse_tls


@dataclass(slots=True)
class AnalysisLimits:
    max_packets: int = 500_000
    max_events: int = 100_000
    max_protocol_records: int = 5_000
    max_flows: int = 50_000
    max_streams: int = 500
    max_stream_bytes: int = 1024 * 1024
    max_evidence_packet_ids: int = 500


def iso_utc(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _append_packet_id(target: dict[str, Any], packet_id: int, limit: int) -> None:
    ids = target.setdefault("packet_ids", [])
    if len(ids) < limit:
        ids.append(packet_id)


def _canonical_conversation(src: str | None, sport: int | None, dst: str | None, dport: int | None, transport: str) -> tuple:
    left = (src or "", sport if sport is not None else -1)
    right = (dst or "", dport if dport is not None else -1)
    return (left, right, transport) if left <= right else (right, left, transport)


def _reassemble_segments(segments: list[tuple[int, bytes, int]], max_bytes: int) -> dict[str, Any]:
    if not segments:
        return {"data": b"", "gaps": 0, "overlap_bytes": 0, "packet_ids": []}
    ordered = sorted(segments, key=lambda item: (item[0], item[2]))
    assembled = bytearray()
    packet_ids: list[int] = []
    expected: int | None = None
    gaps = 0
    overlap_bytes = 0
    for seq, chunk, packet_id in ordered:
        if not chunk:
            continue
        if packet_id not in packet_ids and len(packet_ids) < 500:
            packet_ids.append(packet_id)
        if expected is None:
            take = chunk[:max_bytes]
            assembled.extend(take)
            expected = seq + len(chunk)
            if len(assembled) >= max_bytes:
                break
            continue
        if seq > expected:
            gaps += 1
            # Do not invent missing TCP bytes. Keep only the first contiguous fragment.
            break
        overlap = max(0, expected - seq)
        overlap_bytes += min(overlap, len(chunk))
        if overlap < len(chunk):
            remaining = max_bytes - len(assembled)
            if remaining <= 0:
                break
            assembled.extend(chunk[overlap:overlap + remaining])
            expected = max(expected, seq + len(chunk))
        if len(assembled) >= max_bytes:
            break
    return {"data": bytes(assembled), "gaps": gaps, "overlap_bytes": overlap_bytes, "packet_ids": packet_ids}


def _dns_transactions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pending: dict[tuple, deque[dict[str, Any]]] = defaultdict(deque)
    transactions: list[dict[str, Any]] = []
    for event in sorted(events, key=lambda row: row["timestamp"]):
        questions = event.get("questions") or []
        qname = questions[0].get("name") if questions else None
        qtype = questions[0].get("type") if questions else None
        if not event.get("response"):
            key = (event.get("src"), event.get("dst"), event.get("id"), qname, qtype)
            pending[key].append(event)
            continue
        key = (event.get("dst"), event.get("src"), event.get("id"), qname, qtype)
        query = pending[key].popleft() if pending.get(key) else None
        latency = None if not query else max(0.0, float(event["timestamp"]) - float(query["timestamp"])) * 1000
        transactions.append({
            "id": event.get("id"),
            "client": event.get("dst"),
            "server": event.get("src"),
            "query": qname,
            "qtype": qtype,
            "rcode": event.get("rcode"),
            "answers": event.get("answers", []),
            "latency_ms": None if latency is None else round(latency, 3),
            "query_packet_id": query.get("packet_id") if query else None,
            "response_packet_id": event.get("packet_id"),
            "matched": bool(query),
        })
    for queue in pending.values():
        for query in queue:
            questions = query.get("questions") or []
            transactions.append({
                "id": query.get("id"),
                "client": query.get("src"),
                "server": query.get("dst"),
                "query": questions[0].get("name") if questions else None,
                "qtype": questions[0].get("type") if questions else None,
                "rcode": None,
                "answers": [],
                "latency_ms": None,
                "query_packet_id": query.get("packet_id"),
                "response_packet_id": None,
                "matched": False,
            })
    transactions.sort(key=lambda row: (row["query_packet_id"] or 10**12, row["response_packet_id"] or 10**12))
    return transactions


def _http_transactions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pending: dict[tuple, deque[dict[str, Any]]] = defaultdict(deque)
    transactions: list[dict[str, Any]] = []
    for event in sorted(events, key=lambda row: row["timestamp"]):
        http = event.get("http") or {}
        if http.get("kind") == "request":
            key = (event.get("src"), event.get("sport"), event.get("dst"), event.get("dport"))
            pending[key].append(event)
        elif http.get("kind") == "response":
            key = (event.get("dst"), event.get("dport"), event.get("src"), event.get("sport"))
            request = pending[key].popleft() if pending.get(key) else None
            latency = None if not request else (float(event["timestamp"]) - float(request["timestamp"])) * 1000
            request_http = (request or {}).get("http", {})
            transactions.append({
                "client": event.get("dst"),
                "server": event.get("src"),
                "host": request_http.get("host"),
                "method": request_http.get("method"),
                "uri": request_http.get("uri"),
                "status": http.get("status"),
                "latency_ms": None if latency is None else round(max(0.0, latency), 3),
                "request_packet_id": request.get("packet_id") if request else None,
                "response_packet_id": event.get("packet_id"),
                "matched": bool(request),
            })
    return transactions


def _tls_sessions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sessions: dict[tuple, dict[str, Any]] = {}
    for event in sorted(events, key=lambda row: row["timestamp"]):
        tls = event.get("tls") or {}
        kind = tls.get("kind")
        if kind == "client_hello":
            key = (event.get("src"), event.get("sport"), event.get("dst"), event.get("dport"))
            sessions.setdefault(key, {
                "client": event.get("src"), "client_port": event.get("sport"),
                "server": event.get("dst"), "server_port": event.get("dport"),
                "client_hello": None, "server_hello": None, "certificate": None,
                "packet_ids": [],
            })
            sessions[key]["client_hello"] = tls
            sessions[key]["packet_ids"].append(event.get("packet_id"))
        elif kind in {"server_hello", "certificate"}:
            key = (event.get("dst"), event.get("dport"), event.get("src"), event.get("sport"))
            session = sessions.setdefault(key, {
                "client": event.get("dst"), "client_port": event.get("dport"),
                "server": event.get("src"), "server_port": event.get("sport"),
                "client_hello": None, "server_hello": None, "certificate": None,
                "packet_ids": [],
            })
            session[kind] = tls
            session["packet_ids"].append(event.get("packet_id"))
    rows = list(sessions.values())
    for row in rows:
        row["packet_ids"] = [x for x in row["packet_ids"] if isinstance(x, int)]
        row["sni"] = (row.get("client_hello") or {}).get("sni")
        row["ja3_hash"] = (row.get("client_hello") or {}).get("ja3_hash")
        row["selected_version"] = (row.get("server_hello") or {}).get("selected_version") or (row.get("server_hello") or {}).get("version")
        row["cipher"] = (row.get("server_hello") or {}).get("cipher")
    return rows


def _host_profiles(events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}

    def host(ip: str) -> dict[str, Any]:
        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "scope": ip_scope(ip),
                "first_seen": None,
                "last_seen": None,
                "packets_in": 0,
                "packets_out": 0,
                "bytes_in": 0,
                "bytes_out": 0,
                "payload_bytes_out": 0,
                "destinations": set(),
                "source_ports": set(),
                "destination_ports": set(),
                "protocols": Counter(),
                "domains": set(),
                "http_hosts": set(),
                "tls_sni": set(),
                "finding_ids": [],
                "service_hits": Counter(),
            }
        return hosts[ip]

    for event in events:
        src, dst = event.get("src"), event.get("dst")
        ts = event.get("timestamp")
        length = int(event.get("length") or 0)
        app = event.get("application") or event.get("transport") or "OTHER"
        if src:
            row = host(src)
            row["packets_out"] += 1
            row["bytes_out"] += length
            row["payload_bytes_out"] += int(event.get("payload_bytes") or 0)
            row["protocols"][app] += 1
            if dst:
                row["destinations"].add(dst)
            if event.get("sport") is not None:
                row["source_ports"].add(event["sport"])
            if event.get("dport") is not None:
                row["destination_ports"].add(event["dport"])
            row["first_seen"] = ts if row["first_seen"] is None else min(row["first_seen"], ts)
            row["last_seen"] = ts if row["last_seen"] is None else max(row["last_seen"], ts)
            if event.get("dport") in {22, 53, 67, 80, 443, 445, 3389}:
                row["service_hits"][str(event.get("dport"))] += 1
            dns = event.get("dns") or {}
            for q in dns.get("questions", []):
                if q.get("name"):
                    row["domains"].add(q["name"])
            http = event.get("http") or {}
            if http.get("host"):
                row["http_hosts"].add(http["host"].split(":")[0].lower())
            tls = event.get("tls") or {}
            if tls.get("sni"):
                row["tls_sni"].add(tls["sni"])
        if dst:
            row = host(dst)
            row["packets_in"] += 1
            row["bytes_in"] += length
            row["protocols"][app] += 1
            row["first_seen"] = ts if row["first_seen"] is None else min(row["first_seen"], ts)
            row["last_seen"] = ts if row["last_seen"] is None else max(row["last_seen"], ts)

    for finding in findings:
        evidence = finding.get("evidence") or {}
        candidates = {evidence.get(k) for k in ("src", "dst", "ip", "client") if evidence.get(k)}
        for value in candidates:
            if value in hosts:
                hosts[value]["finding_ids"].append(finding["id"])

    output = []
    for row in hosts.values():
        related = [f for f in findings if f["id"] in row["finding_ids"]]
        services = []
        service_map = {"22": "SSH", "53": "DNS", "67": "DHCP", "80": "HTTP", "443": "HTTPS", "445": "SMB", "3389": "RDP"}
        for port, count in row["service_hits"].most_common():
            if count >= 2:
                services.append(service_map.get(port, port))
        output.append({
            "ip": row["ip"],
            "scope": row["scope"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "packets_in": row["packets_in"],
            "packets_out": row["packets_out"],
            "bytes_in": row["bytes_in"],
            "bytes_out": row["bytes_out"],
            "payload_bytes_out": row["payload_bytes_out"],
            "unique_destinations": len(row["destinations"]),
            "source_ports": sorted(row["source_ports"])[:100],
            "destination_ports": sorted(row["destination_ports"])[:100],
            "protocols": dict(row["protocols"].most_common()),
            "domains": sorted(row["domains"])[:100],
            "http_hosts": sorted(row["http_hosts"])[:100],
            "tls_sni": sorted(row["tls_sni"])[:100],
            "services": services,
            "finding_ids": row["finding_ids"],
            "risk_score": risk_score(related),
        })
    output.sort(key=lambda row: (-row["risk_score"], -(row["bytes_in"] + row["bytes_out"]), row["ip"]))
    return output


def _network_graph(conversations: list[dict[str, Any]], dns_events: list[dict[str, Any]], tls_events: list[dict[str, Any]], hosts: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    host_map = {row["ip"]: row for row in hosts}
    for ip, row in list(host_map.items())[:150]:
        nodes[f"host:{ip}"] = {"id": f"host:{ip}", "label": ip, "type": "host", "scope": row["scope"], "risk_score": row["risk_score"]}
    for conv in conversations[:300]:
        a, b = conv.get("endpoint_a"), conv.get("endpoint_b")
        if a in host_map and b in host_map and f"host:{a}" in nodes and f"host:{b}" in nodes:
            edges.append({"source": f"host:{a}", "target": f"host:{b}", "type": "traffic", "packets": conv["packets"], "bytes": conv["bytes"], "applications": conv.get("applications", [])})
    seen_domain_edges: set[tuple[str, str, str]] = set()
    for event in dns_events:
        if event.get("response") or not event.get("src") or f"host:{event['src']}" not in nodes:
            continue
        for q in event.get("questions", [])[:3]:
            domain = q.get("name")
            if not domain or len(nodes) >= 250:
                continue
            did = f"domain:{domain}"
            nodes.setdefault(did, {"id": did, "label": domain, "type": "domain", "scope": "dns"})
            key = (f"host:{event['src']}", did, "dns")
            if key not in seen_domain_edges:
                edges.append({"source": key[0], "target": did, "type": "dns", "packets": 1, "bytes": 0, "applications": ["DNS"]})
                seen_domain_edges.add(key)
    for event in tls_events:
        tls = event.get("tls") or {}
        sni = tls.get("sni")
        if not sni or not event.get("src") or f"host:{event['src']}" not in nodes or len(nodes) >= 250:
            continue
        did = f"domain:{sni}"
        nodes.setdefault(did, {"id": did, "label": sni, "type": "domain", "scope": "tls"})
        key = (f"host:{event['src']}", did, "tls-sni")
        if key not in seen_domain_edges:
            edges.append({"source": key[0], "target": did, "type": "tls-sni", "packets": 1, "bytes": 0, "applications": ["TLS"]})
            seen_domain_edges.add(key)
    return {"nodes": list(nodes.values()), "edges": edges[:500]}


def analyze_capture(
    path: str | Path,
    limits: AnalysisLimits | None = None,
    config: AnalysisConfig | None = None,
) -> dict[str, Any]:
    path = Path(path)
    limits = limits or AnalysisLimits()
    config = config or AnalysisConfig()
    config.validate()

    events: list[dict[str, Any]] = []
    protocol_events: dict[str, list[dict[str, Any]]] = {name: [] for name in ("dns", "http", "tls", "arp", "dhcp", "icmp", "ntp")}
    applications: Counter[str] = Counter()
    transports: Counter[str] = Counter()
    talker_bytes: Counter[str] = Counter()
    talker_packets: Counter[str] = Counter()
    flows: dict[tuple, dict[str, Any]] = {}
    conversations: dict[tuple, dict[str, Any]] = {}
    all_ips: set[str] = set()
    all_domains: set[str] = set()
    all_urls: set[str] = set()
    ja3_hashes: set[str] = set()
    cert_hashes: set[str] = set()
    warnings: list[str] = []
    stream_segments: dict[tuple, list[tuple[int, bytes, int]]] = defaultdict(list)
    stream_sizes: Counter[tuple] = Counter()
    linktypes: Counter[int] = Counter()

    packet_count = parsed_count = total_bytes = fragment_count = 0
    start_ts: float | None = None
    end_ts: float | None = None
    truncated = False

    for packet_id, record in enumerate(iter_capture(path), start=1):
        packet_count += 1
        if packet_count > limits.max_packets:
            truncated = True
            packet_count -= 1
            warnings.append(f"Analysis stopped at the configured {limits.max_packets:,}-packet safety limit.")
            break
        total_bytes += record.original_length
        linktypes[record.linktype] += 1
        start_ts = record.timestamp if start_ts is None else min(start_ts, record.timestamp)
        end_ts = record.timestamp if end_ts is None else max(end_ts, record.timestamp)

        parsed = parse_packet(record.timestamp, record.data, record.linktype)
        if parsed is None:
            continue
        parsed_count += 1
        event = parsed.as_event()
        event["packet_id"] = packet_id
        event["linktype"] = record.linktype
        if (event.get("ip") or {}).get("fragmented"):
            fragment_count += 1
        if len(events) < limits.max_events:
            events.append(event)

        applications[parsed.application] += 1
        transports[parsed.transport] += 1
        for endpoint in (parsed.src, parsed.dst):
            if endpoint:
                all_ips.add(endpoint)
                talker_packets[endpoint] += 1
                talker_bytes[endpoint] += parsed.length

        if parsed.src and parsed.dst and len(flows) < limits.max_flows:
            flow_key = (parsed.src, parsed.sport, parsed.dst, parsed.dport, parsed.transport)
            flow = flows.setdefault(flow_key, {
                "src": parsed.src, "sport": parsed.sport, "dst": parsed.dst, "dport": parsed.dport,
                "transport": parsed.transport, "application": parsed.application,
                "packets": 0, "bytes": 0, "payload_bytes": 0,
                "first_seen": parsed.timestamp, "last_seen": parsed.timestamp, "packet_ids": [],
            })
            flow["packets"] += 1
            flow["bytes"] += parsed.length
            flow["payload_bytes"] += parsed.payload_bytes
            flow["last_seen"] = max(flow["last_seen"], parsed.timestamp)
            _append_packet_id(flow, packet_id, limits.max_evidence_packet_ids)
            if flow["application"] in {"TCP", "UDP", "OTHER"} and parsed.application not in {"TCP", "UDP", "OTHER"}:
                flow["application"] = parsed.application

            conv_key = _canonical_conversation(parsed.src, parsed.sport, parsed.dst, parsed.dport, parsed.transport)
            conv = conversations.setdefault(conv_key, {
                "endpoint_a": conv_key[0][0], "port_a": None if conv_key[0][1] == -1 else conv_key[0][1],
                "endpoint_b": conv_key[1][0], "port_b": None if conv_key[1][1] == -1 else conv_key[1][1],
                "transport": parsed.transport, "packets": 0, "bytes": 0, "payload_bytes": 0,
                "first_seen": parsed.timestamp, "last_seen": parsed.timestamp, "applications": set(), "packet_ids": [],
            })
            conv["packets"] += 1
            conv["bytes"] += parsed.length
            conv["payload_bytes"] += parsed.payload_bytes
            conv["last_seen"] = max(conv["last_seen"], parsed.timestamp)
            conv["applications"].add(parsed.application)
            _append_packet_id(conv, packet_id, limits.max_evidence_packet_ids)

            if parsed.transport == "TCP" and parsed.app_payload and len(stream_segments) < limits.max_streams:
                seq = int((event.get("tcp") or {}).get("seq", event.get("tcp_seq", 0)))
                if stream_sizes[flow_key] < limits.max_stream_bytes * 2:
                    remaining = limits.max_stream_bytes * 2 - stream_sizes[flow_key]
                    chunk = parsed.app_payload[:remaining]
                    stream_segments[flow_key].append((seq, chunk, packet_id))
                    stream_sizes[flow_key] += len(chunk)

        for name in protocol_events:
            if name in event and len(protocol_events[name]) < limits.max_protocol_records:
                row = {
                    "packet_id": packet_id,
                    "timestamp": parsed.timestamp,
                    "src": parsed.src,
                    "dst": parsed.dst,
                    "sport": parsed.sport,
                    "dport": parsed.dport,
                    **event[name],
                    name: event[name],
                }
                # Flatten protocol metadata while retaining the nested form for detector/API consistency.
                if isinstance(event[name], dict):
                    row.update(event[name])
                protocol_events[name].append(row)

        dns = event.get("dns") or {}
        for question in dns.get("questions", []):
            if question.get("name"):
                all_domains.add(question["name"].lower().rstrip("."))
        for rr_group in (dns.get("answers", []), dns.get("authority", []), dns.get("additional", [])):
            for answer in rr_group:
                value = answer.get("value")
                if isinstance(value, str):
                    try:
                        ipaddress.ip_address(value)
                        all_ips.add(value)
                    except ValueError:
                        if "." in value:
                            all_domains.add(value.lower().rstrip("."))

        http = event.get("http") or {}
        host = http.get("host")
        if host:
            clean_host = host.split(":")[0].strip("[]").lower()
            try:
                ipaddress.ip_address(clean_host)
                all_ips.add(clean_host)
            except ValueError:
                all_domains.add(clean_host)
            uri = http.get("uri")
            if uri:
                all_urls.add(urljoin(f"http://{host}", uri))

        tls = event.get("tls") or {}
        if tls.get("sni"):
            all_domains.add(tls["sni"].lower())
        if tls.get("ja3_hash"):
            ja3_hashes.add(tls["ja3_hash"])
        for cert in tls.get("certificates", []):
            if cert.get("sha256"):
                cert_hashes.add(cert["sha256"])
            for name in cert.get("dns_names", []):
                all_domains.add(name.lower().rstrip("."))

    unsupported = [str(link) for link in linktypes if link not in SUPPORTED_LINKTYPES]
    if unsupported:
        warnings.append("Unsupported link-layer types were skipped: " + ", ".join(unsupported))
    if fragment_count:
        warnings.append(f"Observed {fragment_count:,} fragmented IP packet(s). PacketScope records fragmentation metadata but does not perform IP fragment reassembly in v2.0.")

    # TCP stream reconstruction catches HTTP/TLS records split across TCP segments.
    streams = []
    tls_signatures = {(e.get("packet_id"), (e.get("tls") or {}).get("kind")) for e in protocol_events["tls"]}
    for key, segments in stream_segments.items():
        reconstructed = _reassemble_segments(segments, limits.max_stream_bytes)
        data = reconstructed.pop("data")
        http_stream = parse_http(data) if data else None
        tls_stream = parse_tls(data) if data else None
        src, sport, dst, dport, transport = key
        application = "HTTP" if http_stream else "TLS" if tls_stream else "TCP"
        stream_row = {
            "src": src, "sport": sport, "dst": dst, "dport": dport, "transport": transport,
            "segments": len(segments), "reassembled_bytes": len(data), **reconstructed,
            "application": application, "http": http_stream, "tls": tls_stream,
        }
        streams.append(stream_row)
        if tls_stream and (segments[0][2], tls_stream.get("kind")) not in tls_signatures and len(protocol_events["tls"]) < limits.max_protocol_records:
            row = {
                "packet_id": segments[0][2], "timestamp": next((e["timestamp"] for e in events if e.get("packet_id") == segments[0][2]), 0.0),
                "src": src, "dst": dst, "sport": sport, "dport": dport,
                **tls_stream, "tls": tls_stream, "source": "reassembled_stream", "packet_ids": reconstructed["packet_ids"],
            }
            protocol_events["tls"].append(row)
            if tls_stream.get("sni"):
                all_domains.add(tls_stream["sni"].lower())
            if tls_stream.get("ja3_hash"):
                ja3_hashes.add(tls_stream["ja3_hash"])
            for cert in tls_stream.get("certificates", []):
                if cert.get("sha256"):
                    cert_hashes.add(cert["sha256"])
    streams.sort(key=lambda item: (-item["reassembled_bytes"], -item["segments"]))

    flow_rows = []
    for flow in flows.values():
        row = dict(flow)
        row["duration"] = round(row["last_seen"] - row["first_seen"], 6)
        flow_rows.append(row)
    flow_rows.sort(key=lambda x: (-x["bytes"], -x["packets"]))

    conversation_rows = []
    for conv in conversations.values():
        row = dict(conv)
        row["duration"] = round(row["last_seen"] - row["first_seen"], 6)
        row["applications"] = sorted(row["applications"])
        conversation_rows.append(row)
    conversation_rows.sort(key=lambda x: (-x["bytes"], -x["packets"]))

    beacons, beacon_findings = detect_beacons(events, config)
    candidate_findings = (
        beacon_findings
        + detect_dns(protocol_events["dns"], config)
        + detect_http(protocol_events["http"], config)
        + detect_scanning(events, config)
        + detect_tls(protocol_events["tls"], config)
        + detect_arp(protocol_events["arp"])
        + detect_dhcp(protocol_events["dhcp"])
        + detect_icmp(protocol_events["icmp"], config)
        + detect_large_transfers(flow_rows, config)
    )
    active_findings, suppressed_findings = apply_suppressions(candidate_findings, config)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    active_findings.sort(key=lambda x: (severity_order.get(x["severity"], 9), -x.get("confidence", 0), x["rule_id"]))
    suppressed_findings.sort(key=lambda x: (severity_order.get(x["severity"], 9), x["rule_id"]))
    assign_finding_ids(active_findings)
    assign_finding_ids(suppressed_findings)

    top_talkers = [{"ip": ip, "scope": ip_scope(ip), "packets": talker_packets[ip], "bytes": size} for ip, size in talker_bytes.most_common(25)]
    hosts = _host_profiles(events, active_findings)
    graph = _network_graph(conversation_rows, protocol_events["dns"], protocol_events["tls"], hosts)

    timeline = sorted(events, key=lambda x: (x["timestamp"], x["packet_id"]))
    if len(timeline) > 3000:
        step = max(1, len(timeline) // 3000)
        timeline = timeline[::step][:3000]

    capture_sha256 = _sha256_file(path)
    duration = 0.0 if start_ts is None or end_ts is None else max(0.0, end_ts - start_ts)
    finding_score = risk_score(active_findings)
    result = {
        "schema_version": "2.0",
        "engine": {"name": "PacketScope", "version": "2.0.0", "local_first": True},
        "capture": {
            "name": path.name,
            "format": capture_kind(path),
            "sha256": capture_sha256,
            "evidence_id": capture_sha256[:16],
            "size_bytes": path.stat().st_size,
            "packets": packet_count,
            "parsed_packets": parsed_count,
            "parse_coverage_percent": round((parsed_count / packet_count * 100) if packet_count else 0, 2),
            "wire_bytes": total_bytes,
            "duration_seconds": round(duration, 6),
            "start_time": iso_utc(start_ts),
            "end_time": iso_utc(end_ts),
            "linktypes": {str(k): v for k, v in linktypes.items()},
            "fragmented_packets": fragment_count,
            "truncated": truncated,
        },
        "posture": {
            "risk_score": finding_score,
            "findings": len(active_findings),
            "suppressed_findings": len(suppressed_findings),
            "critical": sum(f["severity"] == "critical" for f in active_findings),
            "high": sum(f["severity"] == "high" for f in active_findings),
            "medium": sum(f["severity"] == "medium" for f in active_findings),
            "low": sum(f["severity"] == "low" for f in active_findings),
        },
        "protocols": {"application": dict(applications.most_common()), "transport": dict(transports.most_common())},
        "top_talkers": top_talkers,
        "hosts": hosts[:500],
        "flows": flow_rows[:2000],
        "conversations": conversation_rows[:2000],
        "streams": streams[:limits.max_streams],
        "dns": protocol_events["dns"],
        "dns_transactions": _dns_transactions(protocol_events["dns"])[:5000],
        "http": protocol_events["http"],
        "http_transactions": _http_transactions(protocol_events["http"])[:5000],
        "tls": protocol_events["tls"],
        "tls_sessions": _tls_sessions(protocol_events["tls"])[:5000],
        "arp": protocol_events["arp"],
        "dhcp": protocol_events["dhcp"],
        "icmp": protocol_events["icmp"],
        "ntp": protocol_events["ntp"],
        "beacons": beacons,
        "findings": active_findings,
        "suppressed_findings": suppressed_findings,
        "iocs": {
            "domains": [{"value": value, "type": "domain"} for value in sorted(all_domains)][:5000],
            "ips": [{"value": value, "type": "ip", "scope": ip_scope(value)} for value in sorted(all_ips)][:5000],
            "urls": [{"value": value, "type": "url"} for value in sorted(all_urls)][:5000],
            "ja3": [{"value": value, "type": "ja3"} for value in sorted(ja3_hashes)][:5000],
            "certificate_sha256": [{"value": value, "type": "certificate_sha256"} for value in sorted(cert_hashes)][:5000],
        },
        "graph": graph,
        "timeline": timeline,
        "analysis_config": config.as_dict(),
        "warnings": warnings,
    }
    return result


def dumps_result(result: dict[str, Any], pretty: bool = True) -> str:
    return json.dumps(result, indent=2 if pretty else None, ensure_ascii=False)
