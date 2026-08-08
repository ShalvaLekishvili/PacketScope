from __future__ import annotations

from packetscope.config import AnalysisConfig
from packetscope.detectors import (
    apply_suppressions,
    coefficient_of_variation,
    detect_beacons,
    detect_dns,
    risk_score,
    shannon_entropy,
)


def test_entropy_zero_for_empty_string():
    assert shannon_entropy("") == 0


def test_coefficient_of_variation_zero_for_constant_intervals():
    assert coefficient_of_variation([10, 10, 10]) == 0


def test_beacon_detection_requires_repetition():
    events = [{"packet_id":i+1,"timestamp":i*10.0,"src":"10.0.0.1","dst":"203.0.113.1","dport":443,"transport":"TCP","payload_bytes":100,"tcp":{"syn":False}} for i in range(6)]
    beacons, findings = detect_beacons(events, AnalysisConfig())
    assert beacons[0]["mean_interval"] == 10.0
    assert findings[0]["rule_id"] == "NET.BEACON.PERIODIC"


def test_jittered_traffic_is_not_strong_beacon():
    times = [0, 10, 35, 42, 80, 90]
    events = [{"packet_id":i+1,"timestamp":t,"src":"a","dst":"b","dport":443,"transport":"TCP","payload_bytes":1,"tcp":{"syn":False}} for i,t in enumerate(times)]
    assert detect_beacons(events, AnalysisConfig())[0] == []


def test_dns_tunnel_aggregate_detection():
    rows=[]
    for i,label in enumerate(["k7x9q2m4v8n1p6r3","m4z8c1q7v2x9n5k3","p8v2m7q1x4n9c6k5","r3n8x1v6m2q9k4c7","v6q1n9m3x8k2c7p4","x2m8v4q9n1k6c3r7","c9v3x7m1q6n2k8p4","n1q7v4m9x3k8c2r6","q8m2x6v1n7k4c9p3","z4v9m1q8x2n6k3c7"]):
        rows.append({"packet_id":i+1,"timestamp":i,"src":"10.0.0.1","dst":"1.1.1.1","response":False,"questions":[{"name":f"{label}.telemetry.example","type":1}]})
    titles={f["title"] for f in detect_dns(rows,AnalysisConfig())}
    assert "Possible DNS data channel" in titles


def test_ip_allowlist_suppresses_finding():
    config=AnalysisConfig.from_mapping({"allowlisted_ips":["10.0.0.1"]})
    finding={"title":"x","category":"Beaconing","evidence":{"src":"10.0.0.1"}}
    active,suppressed=apply_suppressions([finding],config)
    assert not active and suppressed[0]["suppression_reason"]=="IP allowlist"


def test_domain_allowlist_matches_subdomain():
    config=AnalysisConfig.from_mapping({"allowlisted_domains":["example.org"]})
    finding={"title":"x","category":"DNS","evidence":{"domain":"a.b.example.org"}}
    assert apply_suppressions([finding],config)[0]==[]


def test_category_suppression_is_case_insensitive():
    config=AnalysisConfig.from_mapping({"suppressed_categories":["dns"]})
    finding={"title":"x","category":"DNS","evidence":{}}
    assert apply_suppressions([finding],config)[1]


def test_risk_score_increases_with_severity():
    low=risk_score([{"severity":"low","confidence":100}])
    high=risk_score([{"severity":"high","confidence":100}])
    assert 0 < low < high < 100
