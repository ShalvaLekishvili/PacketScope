from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from math import exp, log2, sqrt
import ipaddress
from typing import Any, Iterable

from .config import AnalysisConfig


SEVERITY_WEIGHT = {"critical": 45, "high": 28, "medium": 14, "low": 6, "info": 0}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in value:
        counts[ch] += 1
    n = len(value)
    return -sum((count / n) * log2(count / n) for count in counts.values())


def coefficient_of_variation(values: list[float]) -> float:
    if not values:
        return 999.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 999.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return sqrt(variance) / mean


def is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def ip_scope(value: str | None) -> str:
    if not value:
        return "unknown"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    return "public"


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    summary: str,
    evidence: dict[str, Any],
    category: str,
    *,
    confidence: int,
    recommendation: str,
    mitre: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "summary": summary,
        "category": category,
        "confidence": max(0, min(100, int(confidence))),
        "recommendation": recommendation,
        "mitre": mitre or [],
        "evidence": evidence,
    }


def _packet_ids(rows: Iterable[dict[str, Any]], limit: int = 200) -> list[int]:
    ids = []
    for row in rows:
        value = row.get("packet_id")
        if isinstance(value, int) and value not in ids:
            ids.append(value)
            if len(ids) >= limit:
                break
    return ids


def detect_beacons(events: list[dict[str, Any]], config: AnalysisConfig) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    d = config.detections
    buckets: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("transport") not in {"TCP", "UDP"}:
            continue
        if not event.get("src") or not event.get("dst"):
            continue
        # ACK-only packets create false periodicity; only use payload or SYN/UDP observations.
        tcp = event.get("tcp") or {}
        if event.get("transport") == "TCP" and not event.get("payload_bytes") and not tcp.get("syn"):
            continue
        key = (event["src"], event["dst"], event.get("dport"), event["transport"])
        buckets[key].append(event)

    beacons: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for key, rows in buckets.items():
        timestamps = sorted({float(row["timestamp"]) for row in rows})
        if len(timestamps) < d.beacon_min_observations:
            continue
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
        if len(intervals) < d.beacon_min_observations - 1:
            continue
        mean = sum(intervals) / len(intervals)
        cv = coefficient_of_variation(intervals)
        if not (d.beacon_min_interval_seconds <= mean <= d.beacon_max_interval_seconds):
            continue
        if cv > d.beacon_max_jitter_cv:
            continue
        src, dst, dport, transport = key
        confidence = round(max(0.0, min(1.0, 1.0 - cv / max(d.beacon_max_jitter_cv, 0.01))) * 30 + 70)
        beacon = {
            "src": src,
            "dst": dst,
            "dport": dport,
            "transport": transport,
            "count": len(timestamps),
            "mean_interval": round(mean, 3),
            "min_interval": round(min(intervals), 3),
            "max_interval": round(max(intervals), 3),
            "jitter_cv": round(cv, 4),
            "confidence": confidence,
            "first_seen": timestamps[0],
            "last_seen": timestamps[-1],
            "packet_ids": _packet_ids(rows),
        }
        beacons.append(beacon)
        findings.append(_finding(
            "NET.BEACON.PERIODIC",
            "high" if confidence >= 90 else "medium",
            "Periodic communication pattern",
            "A source contacted the same destination at highly regular intervals. This can indicate polling, monitoring, or command-and-control beaconing and requires context validation.",
            beacon,
            "Beaconing",
            confidence=confidence,
            recommendation="Validate the destination, owning process/asset, and whether the interval matches an approved polling or keepalive mechanism.",
            mitre=[{"id": "T1071", "name": "Application Layer Protocol"}],
        ))
    beacons.sort(key=lambda x: (-x["confidence"], -x["count"]))
    return beacons, findings


def _base_domain(domain: str) -> str:
    labels = [x for x in domain.lower().rstrip(".").split(".") if x]
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower().rstrip(".")


def detect_dns(dns_events: list[dict[str, Any]], config: AnalysisConfig) -> list[dict[str, Any]]:
    d = config.detections
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    query_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    response_by_client: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in dns_events:
        if event.get("response"):
            if event.get("dst"):
                response_by_client[event["dst"]].append(event)
            continue
        for question in event.get("questions", []):
            domain = question.get("name", "").lower().rstrip(".")
            if not domain:
                continue
            query_groups[(event.get("src") or "", _base_domain(domain))].append({**event, "domain": domain})
            if domain in seen:
                continue
            seen.add(domain)
            first_label = domain.split(".")[0]
            entropy = shannon_entropy(first_label)
            evidence = {
                "domain": domain,
                "src": event.get("src"),
                "label_length": len(first_label),
                "entropy": round(entropy, 2),
                "packet_ids": _packet_ids([event]),
            }
            if len(first_label) >= d.dns_entropy_min_label_length and entropy >= d.dns_entropy_threshold:
                findings.append(_finding(
                    "DNS.HIGH_ENTROPY_LABEL",
                    "medium",
                    "High-entropy DNS label",
                    "A long high-entropy DNS label was observed. Generated labels are common in telemetry and CDNs, but they can also carry encoded data or identify malware infrastructure.",
                    evidence,
                    "DNS",
                    confidence=72,
                    recommendation="Review the parent domain, query volume, endpoint role, and whether similarly encoded subdomains recur over time.",
                    mitre=[{"id": "T1071.004", "name": "DNS"}],
                ))
            elif len(domain) >= 80:
                findings.append(_finding(
                    "DNS.UNUSUALLY_LONG_NAME",
                    "low",
                    "Unusually long DNS query",
                    "An unusually long DNS name was observed. Long names can be legitimate but are common in encoded-data channels.",
                    {**evidence, "length": len(domain)},
                    "DNS",
                    confidence=55,
                    recommendation="Compare against baseline DNS behavior for the source and inspect sibling queries to the same parent domain.",
                    mitre=[{"id": "T1071.004", "name": "DNS"}],
                ))

    for (src, base), rows in query_groups.items():
        if len(rows) < d.dns_tunnel_min_queries:
            continue
        names = [row["domain"] for row in rows]
        unique_ratio = len(set(names)) / len(names)
        labels = [name[: -(len(base) + 1)] if name.endswith("." + base) else name.split(".")[0] for name in names]
        entropies = [shannon_entropy(label.replace(".", "")) for label in labels if label]
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0
        avg_label_length = sum(len(label) for label in labels) / len(labels) if labels else 0
        if unique_ratio >= d.dns_tunnel_unique_ratio and avg_entropy >= 3.2 and avg_label_length >= 12:
            findings.append(_finding(
                "DNS.POSSIBLE_TUNNEL",
                "high" if avg_entropy >= 3.6 and avg_label_length >= 20 else "medium",
                "Possible DNS data channel",
                "Repeated unique, encoded-looking subdomains were queried beneath the same approximate parent domain. This pattern is consistent with some DNS tunneling and data-transfer behaviors.",
                {
                    "src": src,
                    "base_domain": base,
                    "queries": len(rows),
                    "unique_ratio": round(unique_ratio, 3),
                    "average_label_entropy": round(avg_entropy, 2),
                    "average_label_length": round(avg_label_length, 1),
                    "sample_domains": sorted(set(names))[:10],
                    "packet_ids": _packet_ids(rows),
                },
                "DNS",
                confidence=82,
                recommendation="Validate the parent domain and endpoint process, inspect query/response sizes, and compare with known application telemetry before escalating.",
                mitre=[{"id": "T1071.004", "name": "DNS"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}],
            ))

    for client, rows in response_by_client.items():
        if len(rows) < d.dns_nxdomain_min_responses:
            continue
        nxdomain = [row for row in rows if row.get("rcode") == 3]
        ratio = len(nxdomain) / len(rows)
        if ratio >= d.dns_nxdomain_ratio:
            findings.append(_finding(
                "DNS.HIGH_NXDOMAIN_RATIO",
                "medium",
                "High NXDOMAIN response ratio",
                "A client received an unusually high proportion of name-error responses. This can occur with DGA activity, stale software, misconfiguration, or reconnaissance.",
                {
                    "client": client,
                    "responses": len(rows),
                    "nxdomain": len(nxdomain),
                    "ratio": round(ratio, 3),
                    "packet_ids": _packet_ids(nxdomain),
                },
                "DNS",
                confidence=70,
                recommendation="Review the failed query names and identify the generating process or application on the client.",
                mitre=[{"id": "T1568.002", "name": "Dynamic Resolution: Domain Generation Algorithms"}],
            ))
    return findings


def detect_http(http_events: list[dict[str, Any]], config: AnalysisConfig) -> list[dict[str, Any]]:
    findings = []
    for event in http_events:
        http = event.get("http", {})
        if http.get("kind") != "request":
            continue
        host = (http.get("host") or "").split(":")[0].strip("[]")
        common = {
            "src": event.get("src"),
            "dst": event.get("dst"),
            "host": host,
            "method": http.get("method"),
            "uri": http.get("uri"),
            "packet_ids": _packet_ids([event]),
        }
        if http.get("authorization_present"):
            findings.append(_finding(
                "HTTP.CLEARTEXT_AUTH",
                "high",
                "Authorization header over cleartext HTTP",
                "An HTTP request carried an Authorization header without TLS. PacketScope records only presence and deliberately redacts the credential value.",
                common,
                "HTTP",
                confidence=96,
                recommendation="Move the service to HTTPS, rotate exposed credentials if this capture came from a real environment, and review the endpoint for additional cleartext secrets.",
            ))
        if is_ip(host):
            findings.append(_finding(
                "HTTP.IP_LITERAL_HOST",
                "medium",
                "HTTP request addressed directly to an IP",
                "Direct-IP HTTP bypasses normal hostname context. It can be legitimate for appliances and internal APIs, but also appears in ad-hoc or malicious infrastructure.",
                common,
                "HTTP",
                confidence=65,
                recommendation="Validate ownership and business purpose of the destination and compare the request path/User-Agent with expected application behavior.",
            ))
        if http.get("method") == "TRACE":
            findings.append(_finding(
                "HTTP.TRACE_METHOD",
                "low",
                "HTTP TRACE request observed",
                "The TRACE method was observed. It is uncommon in normal user traffic and may be used during web-service testing or reconnaissance.",
                common,
                "HTTP",
                confidence=58,
                recommendation="Confirm whether the request came from an approved scanner or diagnostic workflow and disable TRACE on services where it is unnecessary.",
            ))
    return findings


def detect_scanning(events: list[dict[str, Any]], config: AnalysisConfig) -> list[dict[str, Any]]:
    d = config.detections
    pair_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    pair_rows: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    src_port_hosts: dict[tuple[str, int], set[str]] = defaultdict(set)
    src_port_rows: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        src, dst, port = event.get("src"), event.get("dst"), event.get("dport")
        if not src or not dst or not isinstance(port, int):
            continue
        if event.get("transport") == "TCP":
            tcp = event.get("tcp") or {}
            if not (tcp.get("syn") and not tcp.get("ack_flag")):
                continue
        elif event.get("transport") != "UDP":
            continue
        pair_ports[(src, dst)].add(port)
        pair_rows[(src, dst)].append(event)
        src_port_hosts[(src, port)].add(dst)
        src_port_rows[(src, port)].append(event)
    findings = []
    for (src, dst), ports in pair_ports.items():
        if len(ports) >= d.vertical_scan_port_threshold:
            findings.append(_finding(
                "NET.VERTICAL_SCAN",
                "medium",
                "Multi-port probing pattern",
                "A source attempted connections to many destination ports on the same host.",
                {"src": src, "dst": dst, "unique_ports": len(ports), "ports": sorted(ports)[:100], "packet_ids": _packet_ids(pair_rows[(src, dst)])},
                "Reconnaissance",
                confidence=min(95, 60 + len(ports)),
                recommendation="Confirm whether the source is an approved scanner or management platform; otherwise inspect the source endpoint for reconnaissance activity.",
                mitre=[{"id": "T1046", "name": "Network Service Discovery"}],
            ))
    for (src, port), hosts in src_port_hosts.items():
        if len(hosts) >= d.horizontal_scan_host_threshold:
            findings.append(_finding(
                "NET.HORIZONTAL_SCAN",
                "medium",
                "Horizontal service sweep",
                "A source probed the same destination port across many hosts.",
                {"src": src, "dport": port, "unique_hosts": len(hosts), "sample_hosts": sorted(hosts)[:100], "packet_ids": _packet_ids(src_port_rows[(src, port)])},
                "Reconnaissance",
                confidence=min(95, 60 + len(hosts) // 2),
                recommendation="Validate whether the source is authorized to enumerate this service across the network and review its process/network telemetry.",
                mitre=[{"id": "T1046", "name": "Network Service Discovery"}],
            ))
    return findings


def _tls_version_number(value: str | None) -> int | None:
    try:
        return int(value, 16) if value else None
    except ValueError:
        return None


def detect_tls(tls_events: list[dict[str, Any]], config: AnalysisConfig) -> list[dict[str, Any]]:
    findings = []
    for event in tls_events:
        tls = event.get("tls") or {}
        kind = tls.get("kind")
        if kind == "client_hello":
            versions = [_tls_version_number(x) for x in tls.get("supported_versions", [])]
            versions = [x for x in versions if x is not None and not ((x & 0x0F0F) == 0x0A0A)]
            legacy = _tls_version_number(tls.get("version"))
            highest = max(versions) if versions else legacy
            if highest is not None and highest <= 0x0302:
                findings.append(_finding(
                    "TLS.LEGACY_VERSION",
                    "medium",
                    "Legacy TLS version offered",
                    "A TLS ClientHello appears limited to TLS 1.1 or older, which lacks modern protocol protections.",
                    {"src": event.get("src"), "dst": event.get("dst"), "dport": event.get("dport"), "version": tls.get("version"), "supported_versions": tls.get("supported_versions", []), "packet_ids": _packet_ids([event])},
                    "TLS",
                    confidence=90,
                    recommendation="Identify the client/application and upgrade or disable legacy TLS support where operationally possible.",
                ))
            if event.get("dport") == 443 and not tls.get("sni") and ip_scope(event.get("dst")) in {"public", "reserved"}:
                findings.append(_finding(
                    "TLS.NO_SNI_PUBLIC_443",
                    "low",
                    "TLS connection without SNI",
                    "A ClientHello to TCP/443 did not include a Server Name Indication. This can be normal for IP-based services but reduces hostname context for investigation.",
                    {"src": event.get("src"), "dst": event.get("dst"), "dport": event.get("dport"), "ja3_hash": tls.get("ja3_hash"), "packet_ids": _packet_ids([event])},
                    "TLS",
                    confidence=45,
                    recommendation="Correlate the destination IP with DNS, process telemetry, certificates, and known service ownership before assigning significance.",
                ))
        elif kind == "certificate":
            for cert in tls.get("certificates", [])[:3]:
                if cert.get("parse_error"):
                    continue
                evidence = {"src": event.get("src"), "dst": event.get("dst"), "subject": cert.get("subject"), "issuer": cert.get("issuer"), "sha256": cert.get("sha256"), "not_before": cert.get("not_before"), "not_after": cert.get("not_after"), "packet_ids": _packet_ids([event])}
                if cert.get("self_signed_name"):
                    findings.append(_finding(
                        "TLS.SELF_SIGNED_CERT",
                        "low",
                        "Self-issued TLS certificate observed",
                        "A certificate has identical subject and issuer names. Self-issued certificates are common internally but can also appear on unmanaged or ad-hoc infrastructure.",
                        evidence,
                        "TLS",
                        confidence=55,
                        recommendation="Validate the service owner, certificate deployment policy, and whether the fingerprint is expected for this destination.",
                    ))
                try:
                    when = datetime.fromtimestamp(float(event.get("timestamp", 0)), tz=timezone.utc)
                    not_after = datetime.fromisoformat(str(cert.get("not_after", "")).replace("Z", "+00:00"))
                    not_before = datetime.fromisoformat(str(cert.get("not_before", "")).replace("Z", "+00:00"))
                    if when > not_after:
                        findings.append(_finding(
                            "TLS.EXPIRED_CERT",
                            "medium",
                            "Expired TLS certificate observed",
                            "The certificate was already expired at the capture timestamp.",
                            evidence,
                            "TLS",
                            confidence=95,
                            recommendation="Replace the expired certificate and investigate whether clients were bypassing certificate validation.",
                        ))
                    elif when < not_before:
                        findings.append(_finding(
                            "TLS.NOT_YET_VALID_CERT",
                            "medium",
                            "TLS certificate not yet valid",
                            "The certificate validity period had not started at the capture timestamp.",
                            evidence,
                            "TLS",
                            confidence=90,
                            recommendation="Check system clocks, certificate deployment timing, and whether the service is presenting an unexpected certificate.",
                        ))
                except (TypeError, ValueError):
                    pass
    return findings


def detect_arp(arp_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    claims: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for event in arp_events:
        arp = event.get("arp") or {}
        ip = arp.get("sender_ip")
        mac = arp.get("sender_mac")
        if ip and mac and ip != "0.0.0.0":
            claims[ip][mac].append(event)
    findings = []
    for ip, macs in claims.items():
        if len(macs) <= 1:
            continue
        rows = [row for group in macs.values() for row in group]
        findings.append(_finding(
            "ARP.MULTIPLE_MAC_CLAIMS",
            "high",
            "Multiple MAC addresses claimed the same IPv4 address",
            "ARP traffic shows more than one hardware address claiming the same IPv4 address. This can reflect failover/virtualization, duplicate addressing, or ARP spoofing.",
            {"ip": ip, "mac_addresses": sorted(macs), "claim_counts": {mac: len(group) for mac, group in macs.items()}, "packet_ids": _packet_ids(rows)},
            "ARP",
            confidence=80,
            recommendation="Check legitimate HA/VRRP behavior and switch/endpoint ARP tables; if unexplained, investigate for duplicate IP assignment or ARP poisoning.",
            mitre=[{"id": "T1557.002", "name": "ARP Cache Poisoning"}],
        ))
    return findings


def detect_dhcp(dhcp_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    servers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in dhcp_events:
        dhcp = event.get("dhcp") or {}
        if dhcp.get("message_type") in {2, 5, 6}:
            server = dhcp.get("server_identifier") or event.get("src")
            if server:
                servers[server].append(event)
    if len(servers) <= 1:
        return []
    rows = [row for group in servers.values() for row in group]
    return [_finding(
        "DHCP.MULTIPLE_SERVERS",
        "medium",
        "Multiple DHCP servers observed",
        "More than one server issued DHCP offer/ack/nak traffic in the capture. Multiple servers can be intentional, but unexpected responders may indicate a rogue or misconfigured DHCP service.",
        {"servers": sorted(servers), "message_counts": {server: len(group) for server, group in servers.items()}, "packet_ids": _packet_ids(rows)},
        "DHCP",
        confidence=65,
        recommendation="Compare the observed server identifiers with the authorized DHCP inventory and investigate any unrecognized responder.",
    )]


def detect_icmp(icmp_events: list[dict[str, Any]], config: AnalysisConfig) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in icmp_events:
        icmp = event.get("icmp") or {}
        if icmp.get("name") == "echo-request" and event.get("src") and event.get("dst"):
            buckets[(event["src"], event["dst"])].append(event)
    findings = []
    for (src, dst), rows in buckets.items():
        if len(rows) >= config.detections.icmp_echo_threshold:
            duration = max(float(r["timestamp"]) for r in rows) - min(float(r["timestamp"]) for r in rows)
            findings.append(_finding(
                "ICMP.HIGH_ECHO_VOLUME",
                "low" if len(rows) < config.detections.icmp_echo_threshold * 5 else "medium",
                "High-volume ICMP echo activity",
                "A source sent many ICMP echo requests to the same destination. This may be monitoring, diagnostics, scanning, or an ICMP-based channel depending on payload and context.",
                {"src": src, "dst": dst, "requests": len(rows), "duration_seconds": round(duration, 3), "packet_ids": _packet_ids(rows)},
                "ICMP",
                confidence=60,
                recommendation="Verify whether the source is an approved monitoring/scanning system and inspect ICMP payload characteristics if the traffic is unexpected.",
                mitre=[{"id": "T1095", "name": "Non-Application Layer Protocol"}],
            ))
    return findings


def detect_large_transfers(flows: list[dict[str, Any]], config: AnalysisConfig) -> list[dict[str, Any]]:
    threshold = config.detections.outbound_payload_threshold_bytes
    findings = []
    for flow in flows:
        if flow.get("payload_bytes", 0) < threshold:
            continue
        if ip_scope(flow.get("src")) != "private" or ip_scope(flow.get("dst")) not in {"public", "reserved"}:
            continue
        findings.append(_finding(
            "NET.LARGE_OUTBOUND_TRANSFER",
            "medium",
            "Large outbound application payload",
            "A private source sent a large amount of application payload to an external destination in one directional flow. Large transfers are common in normal business traffic but merit review when unexpected.",
            {"src": flow.get("src"), "dst": flow.get("dst"), "dport": flow.get("dport"), "transport": flow.get("transport"), "application": flow.get("application"), "payload_bytes": flow.get("payload_bytes"), "packets": flow.get("packets"), "packet_ids": flow.get("packet_ids", [])[:200]},
            "Data Transfer",
            confidence=55,
            recommendation="Validate the destination, application, user/business context, and whether the transfer size is normal for this endpoint.",
            mitre=[{"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}],
        ))
    return findings


def apply_suppressions(findings: list[dict[str, Any]], config: AnalysisConfig) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active, suppressed = [], []
    for finding in findings:
        reason = None
        if finding.get("category", "").lower() in config.suppressed_categories:
            reason = "category suppression"
        elif finding.get("title", "").lower() in config.suppressed_titles:
            reason = "title suppression"
        else:
            evidence = finding.get("evidence") or {}
            endpoints = [evidence.get("src"), evidence.get("dst"), evidence.get("ip"), evidence.get("client")]
            domains = [evidence.get("domain"), evidence.get("base_domain"), evidence.get("host")]
            if any(config.ip_allowed(value) for value in endpoints if value):
                reason = "IP allowlist"
            elif any(config.domain_allowed(value) for value in domains if value):
                reason = "domain allowlist"
        if reason:
            suppressed.append({**finding, "suppression_reason": reason})
        else:
            active.append(finding)
    return active, suppressed


def assign_finding_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counters: dict[str, int] = defaultdict(int)
    for finding in findings:
        prefix = finding.get("rule_id", "FINDING").replace(".", "-")
        counters[prefix] += 1
        finding["id"] = f"{prefix}-{counters[prefix]:03d}"
    return findings


def risk_score(findings: list[dict[str, Any]]) -> int:
    raw = 0.0
    for item in findings:
        weight = SEVERITY_WEIGHT.get(item.get("severity", "info"), 0)
        confidence = max(0.25, min(1.0, float(item.get("confidence", 100)) / 100.0))
        raw += weight * confidence
    # Diminishing returns keep multiple low-confidence heuristics from instantly saturating 100.
    return min(100, round(100 * (1 - exp(-raw / 85.0))))
