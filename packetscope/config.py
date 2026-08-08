from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class DetectionConfig:
    beacon_min_observations: int = 5
    beacon_max_jitter_cv: float = 0.20
    beacon_min_interval_seconds: float = 1.0
    beacon_max_interval_seconds: float = 3600.0
    dns_entropy_min_label_length: int = 24
    dns_entropy_threshold: float = 3.5
    dns_tunnel_min_queries: int = 10
    dns_tunnel_unique_ratio: float = 0.80
    dns_nxdomain_min_responses: int = 10
    dns_nxdomain_ratio: float = 0.60
    vertical_scan_port_threshold: int = 15
    horizontal_scan_host_threshold: int = 20
    icmp_echo_threshold: int = 20
    outbound_payload_threshold_bytes: int = 5 * 1024 * 1024


@dataclass(slots=True)
class AnalysisConfig:
    detections: DetectionConfig = field(default_factory=DetectionConfig)
    allowlisted_ips: set[str] = field(default_factory=set)
    allowlisted_domains: set[str] = field(default_factory=set)
    suppressed_categories: set[str] = field(default_factory=set)
    suppressed_titles: set[str] = field(default_factory=set)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "AnalysisConfig":
        detection_data = data.get("detections") or {}
        defaults = DetectionConfig()
        allowed_detection_keys = {name for name in defaults.__dataclass_fields__}
        normalized_detection = {
            key: value for key, value in detection_data.items() if key in allowed_detection_keys
        }
        config = cls(
            detections=DetectionConfig(**normalized_detection),
            allowlisted_ips={str(x).strip() for x in data.get("allowlisted_ips", []) if str(x).strip()},
            allowlisted_domains={
                str(x).strip().lower().rstrip(".")
                for x in data.get("allowlisted_domains", [])
                if str(x).strip()
            },
            suppressed_categories={str(x).strip().lower() for x in data.get("suppressed_categories", [])},
            suppressed_titles={str(x).strip().lower() for x in data.get("suppressed_titles", [])},
        )
        config.validate()
        return config

    @classmethod
    def from_json(cls, path: str | Path) -> "AnalysisConfig":
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("PacketScope config must be a JSON object")
        return cls.from_mapping(data)

    def validate(self) -> None:
        d = self.detections
        if d.beacon_min_observations < 3:
            raise ValueError("beacon_min_observations must be at least 3")
        if not 0 <= d.beacon_max_jitter_cv <= 2:
            raise ValueError("beacon_max_jitter_cv must be between 0 and 2")
        if d.beacon_min_interval_seconds <= 0 or d.beacon_max_interval_seconds <= 0:
            raise ValueError("beacon interval bounds must be positive")
        if d.beacon_min_interval_seconds > d.beacon_max_interval_seconds:
            raise ValueError("beacon minimum interval exceeds maximum interval")
        if not 0 <= d.dns_tunnel_unique_ratio <= 1:
            raise ValueError("dns_tunnel_unique_ratio must be between 0 and 1")
        if not 0 <= d.dns_nxdomain_ratio <= 1:
            raise ValueError("dns_nxdomain_ratio must be between 0 and 1")
        for value in self.allowlisted_ips:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"Invalid allowlisted IP: {value}") from exc

    def domain_allowed(self, value: str | None) -> bool:
        if not value:
            return False
        domain = value.lower().rstrip(".")
        return any(domain == allowed or domain.endswith("." + allowed) for allowed in self.allowlisted_domains)

    def ip_allowed(self, value: str | None) -> bool:
        return bool(value and value in self.allowlisted_ips)

    def as_dict(self) -> dict[str, Any]:
        return {
            "detections": {
                name: getattr(self.detections, name)
                for name in self.detections.__dataclass_fields__
            },
            "allowlisted_ips": sorted(self.allowlisted_ips),
            "allowlisted_domains": sorted(self.allowlisted_domains),
            "suppressed_categories": sorted(self.suppressed_categories),
            "suppressed_titles": sorted(self.suppressed_titles),
        }
