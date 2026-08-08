from __future__ import annotations

from pathlib import Path

from packetscope.analysis import AnalysisLimits, analyze_capture
from packetscope.config import AnalysisConfig
from packetscope.reporting import render_html_report, write_report


def test_demo_analysis_extracts_expected_protocols(demo_result):
    apps=demo_result["protocols"]["application"]
    for name in ["DNS","HTTP","TLS","ARP","DHCP","ICMP","NTP"]:
        assert apps[name] > 0


def test_demo_analysis_finds_expected_leads(demo_result):
    titles={f["title"] for f in demo_result["findings"]}
    expected={"Periodic communication pattern","Possible DNS data channel","Multi-port probing pattern","Horizontal service sweep","Multiple MAC addresses claimed the same IPv4 address","Multiple DHCP servers observed"}
    assert expected <= titles


def test_demo_analysis_has_integrity_hash(demo_result):
    assert len(demo_result["capture"]["sha256"]) == 64
    assert demo_result["capture"]["evidence_id"] == demo_result["capture"]["sha256"][:16]


def test_dns_transaction_is_correlated(demo_result):
    tx=next(x for x in demo_result["dns_transactions"] if x["query"]=="updates.example.org")
    assert tx["matched"] is True
    assert tx["latency_ms"] == 40.0
    assert tx["answers"][0]["value"] == "192.0.2.20"


def test_http_transaction_is_correlated(demo_result):
    tx=demo_result["http_transactions"][0]
    assert tx["method"] == "GET"
    assert tx["status"] == 200
    assert tx["latency_ms"] == 80.0


def test_host_profiles_attribute_findings(demo_result):
    host=next(x for x in demo_result["hosts"] if x["ip"]=="10.0.0.25")
    assert host["risk_score"] > 0
    assert host["tls_sni"]


def test_graph_contains_host_and_domain_nodes(demo_result):
    types={n["type"] for n in demo_result["graph"]["nodes"]}
    assert {"host","domain"} <= types
    assert demo_result["graph"]["edges"]


def test_analysis_packet_limit_marks_truncation(demo_capture: Path):
    result=analyze_capture(demo_capture,AnalysisLimits(max_packets=10))
    assert result["capture"]["packets"] == 10
    assert result["capture"]["truncated"] is True


def test_config_allowlist_moves_findings_to_suppressed(demo_capture: Path):
    config=AnalysisConfig.from_mapping({"allowlisted_ips":["10.0.0.25"]})
    result=analyze_capture(demo_capture,config=config)
    assert result["posture"]["suppressed_findings"] >= 1
    assert any(x["suppression_reason"]=="IP allowlist" for x in result["suppressed_findings"])


def test_html_report_contains_hash_and_finding(demo_result):
    html=render_html_report(demo_result)
    assert demo_result["capture"]["sha256"] in html
    assert "Periodic communication pattern" in html
    assert "PACKETSCOPE 2.0" in html


def test_json_report_write(demo_result,tmp_path:Path):
    path=write_report(demo_result,tmp_path/"report.json")
    assert path.exists()
    assert '"schema_version": "2.0"' in path.read_text()
