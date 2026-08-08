from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .analysis import AnalysisLimits, analyze_capture
from .capture import CaptureFormatError
from .config import AnalysisConfig
from .reporting import write_report
from .slicing import slice_capture


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="packetscope", description="Defensive PCAP/PCAPNG network-forensics workbench")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a packet capture")
    analyze.add_argument("capture", type=Path)
    analyze.add_argument("--report", type=Path, help="Write .html or .json report")
    analyze.add_argument("--config", type=Path, help="JSON detection/allowlist configuration")
    analyze.add_argument("--max-packets", type=int, default=500_000)
    analyze.add_argument("--json", action="store_true", help="Print full JSON to stdout")

    slice_cmd = sub.add_parser("slice", help="Export selected 1-based packet IDs to PCAPNG")
    slice_cmd.add_argument("capture", type=Path)
    slice_cmd.add_argument("output", type=Path)
    slice_cmd.add_argument("--packets", required=True, help="Comma-separated packet IDs, e.g. 12,18,21")

    serve = sub.add_parser("serve", help="Run the local PacketScope web workbench")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def _load_config(path: Path | None) -> AnalysisConfig:
    return AnalysisConfig.from_json(path) if path else AnalysisConfig()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        try:
            import uvicorn
            uvicorn.run("packetscope.api:app", host=args.host, port=args.port)
            return 0
        except KeyboardInterrupt:
            return 130

    if args.command == "slice":
        try:
            ids = [int(item.strip()) for item in args.packets.split(",") if item.strip()]
            output = slice_capture(args.capture, args.output, ids)
            print(f"Evidence slice: {output}")
            return 0
        except (OSError, ValueError, CaptureFormatError) as exc:
            print(f"PacketScope error: {exc}", file=sys.stderr)
            return 2

    try:
        config = _load_config(args.config)
        result = analyze_capture(args.capture, AnalysisLimits(max_packets=max(1, args.max_packets)), config=config)
    except (OSError, ValueError, json.JSONDecodeError, CaptureFormatError) as exc:
        print(f"PacketScope error: {exc}", file=sys.stderr)
        return 2
    if args.report:
        output = write_report(result, args.report)
        print(f"Report: {output}")
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        cap, posture = result["capture"], result["posture"]
        print(f"PacketScope · {cap['name']} · evidence {cap['evidence_id']}")
        print(f"Packets: {cap['packets']:,} · Coverage: {cap['parse_coverage_percent']:.1f}% · Duration: {cap['duration_seconds']:.3f}s · Risk: {posture['risk_score']}/100")
        print(f"Findings: {posture['findings']} (critical={posture['critical']}, high={posture['high']}, medium={posture['medium']}, low={posture['low']}) · Suppressed: {posture['suppressed_findings']}")
        print(f"Hosts: {len(result['hosts'])} · Conversations: {len(result['conversations'])} · DNS tx: {len(result['dns_transactions'])} · HTTP tx: {len(result['http_transactions'])} · TLS sessions: {len(result['tls_sessions'])}")
        print(f"SHA256: {cap['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
