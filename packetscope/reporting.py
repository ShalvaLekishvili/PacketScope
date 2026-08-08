from __future__ import annotations

from html import escape
import json
from pathlib import Path
from typing import Any


def _fmt_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{value} B"


def _json(value: Any) -> str:
    return escape(json.dumps(value, ensure_ascii=False, separators=(",", ": ")))


def render_html_report(result: dict[str, Any]) -> str:
    cap = result["capture"]
    posture = result["posture"]
    findings = result.get("findings", [])
    rows = []
    for finding in findings:
        analyst = finding.get("analyst") or {}
        mitre = ", ".join(f"{x.get('id')} {x.get('name')}" for x in finding.get("mitre", [])) or "—"
        packet_ids = (finding.get("evidence") or {}).get("packet_ids", [])
        rows.append(
            "<tr>"
            f"<td><span class='sev {escape(finding['severity'])}'>{escape(finding['severity'].upper())}</span><br><small>{finding.get('confidence', 0)}% confidence</small></td>"
            f"<td><strong>{escape(finding['title'])}</strong><br><small>{escape(finding.get('summary', ''))}</small><div class='rule'>{escape(finding.get('rule_id',''))}</div></td>"
            f"<td>{escape(finding.get('category',''))}<br><small>{escape(mitre)}</small></td>"
            f"<td>{escape(finding.get('recommendation',''))}</td>"
            f"<td><code>{_json(finding.get('evidence', {}))}</code><div class='rule'>{len(packet_ids)} packet reference(s)</div></td>"
            f"<td>{escape(analyst.get('status','new'))}<br><small>{escape(analyst.get('verdict','unknown'))}</small></td>"
            "</tr>"
        )
    finding_html = "".join(rows) or "<tr><td colspan='6'>No active heuristic findings.</td></tr>"
    protocols = "".join(
        f"<li><span>{escape(name)}</span><strong>{count:,}</strong></li>"
        for name, count in result.get("protocols", {}).get("application", {}).items()
    ) or "<li><span>No parsed protocols</span><strong>0</strong></li>"
    hosts = "".join(
        f"<tr><td><code>{escape(h['ip'])}</code></td><td>{escape(h['scope'])}</td><td>{h['risk_score']}/100</td><td>{h['packets_in']:,} / {h['packets_out']:,}</td><td>{_fmt_bytes(h['bytes_in'] + h['bytes_out'])}</td><td>{escape(', '.join(h.get('services', [])) or '—')}</td></tr>"
        for h in result.get("hosts", [])[:25]
    ) or "<tr><td colspan='6'>No IP hosts profiled.</td></tr>"
    beacons = "".join(
        f"<tr><td><code>{escape(str(b['src']))}</code></td><td><code>{escape(str(b['dst']))}:{escape(str(b['dport']))}</code></td><td>{b['mean_interval']}s</td><td>{b['jitter_cv']}</td><td>{b['confidence']}%</td></tr>"
        for b in result.get("beacons", [])
    ) or "<tr><td colspan='5'>No strongly periodic flows detected.</td></tr>"
    sha = cap.get("sha256", "—")
    return f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>PacketScope Report — {escape(cap['name'])}</title>
<style>
:root{{--bg:#0b1016;--panel:#111923;--line:#25313e;--text:#e8edf2;--muted:#8fa1b3;--accent:#7dd3fc;--high:#fb7185;--med:#fbbf24;--low:#60a5fa}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:13px/1.55 Inter,ui-sans-serif,system-ui,sans-serif}} main{{max-width:1280px;margin:auto;padding:46px 28px}}
.eyebrow{{letter-spacing:.14em;color:var(--accent);font-size:10px;font-weight:800}} h1{{font-size:36px;margin:7px 0}} h2{{margin-top:34px}} .muted,small{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:26px 0}} .card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}} .metric{{font-size:25px;font-weight:750;margin-top:5px}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}} th,td{{text-align:left;vertical-align:top;padding:11px;border-bottom:1px solid var(--line)}} th{{color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.08em}} code{{white-space:pre-wrap;overflow-wrap:anywhere;color:#c7d2fe;font-size:10px}} .sev{{font-size:9px;font-weight:800;padding:4px 7px;border:1px solid var(--line);border-radius:999px}} .sev.high,.sev.critical{{color:var(--high)}} .sev.medium{{color:var(--med)}} .sev.low{{color:var(--low)}}
ul{{padding:0;list-style:none}} li{{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding:7px 0}} .rule{{color:#6f8598;font:9px ui-monospace,monospace;margin-top:5px}} .hash{{word-break:break-all;font-family:ui-monospace,monospace;font-size:10px}}
@media(max-width:900px){{.grid{{grid-template-columns:1fr 1fr}}}} @media(max-width:520px){{.grid{{grid-template-columns:1fr}}}}
@media print{{body{{background:white;color:#111}} .card,table{{background:white;border-color:#ddd}} th,td{{border-color:#ddd}} .muted,small,.rule{{color:#555}}}}
</style></head><body><main>
<div class='eyebrow'>PACKETSCOPE 2.0 · NETWORK FORENSICS REPORT</div><h1>{escape(cap['name'])}</h1>
<p class='muted'>Local metadata analysis. Findings are evidence-backed heuristic leads for analyst validation, not standalone proof of malicious activity.</p>
<div class='grid'>
<div class='card'><div class='muted'>Risk score</div><div class='metric'>{posture['risk_score']}/100</div></div>
<div class='card'><div class='muted'>Packets</div><div class='metric'>{cap['packets']:,}</div></div>
<div class='card'><div class='muted'>Parse coverage</div><div class='metric'>{cap.get('parse_coverage_percent',0):.1f}%</div></div>
<div class='card'><div class='muted'>Wire volume</div><div class='metric'>{_fmt_bytes(cap['wire_bytes'])}</div></div>
<div class='card'><div class='muted'>Findings</div><div class='metric'>{posture['findings']}</div></div></div>
<section><h2>Evidence integrity</h2><div class='card'><strong>Evidence ID:</strong> {escape(cap.get('evidence_id','—'))}<br><strong>SHA-256:</strong> <span class='hash'>{escape(sha)}</span><br><strong>Format:</strong> {escape(cap['format'].upper())} · <strong>Duration:</strong> {cap['duration_seconds']:.3f}s · <strong>Window:</strong> {escape(str(cap['start_time']))} → {escape(str(cap['end_time']))}</div></section>
<section><h2>Application protocols</h2><div class='card'><ul>{protocols}</ul></div></section>
<section><h2>Priority hosts</h2><table><thead><tr><th>Host</th><th>Scope</th><th>Risk</th><th>Packets in/out</th><th>Traffic</th><th>Observed services</th></tr></thead><tbody>{hosts}</tbody></table></section>
<section><h2>Beacon candidates</h2><table><thead><tr><th>Source</th><th>Destination</th><th>Interval</th><th>Jitter CV</th><th>Confidence</th></tr></thead><tbody>{beacons}</tbody></table></section>
<section><h2>Analyst findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Category / ATT&CK</th><th>Recommendation</th><th>Evidence</th><th>Analyst state</th></tr></thead><tbody>{finding_html}</tbody></table></section>
<section><p class='muted'>PacketScope 2.0 · Local-first defensive analysis · No third-party reputation lookup or cloud upload is performed by default.</p></section>
</main></body></html>"""


def write_report(result: dict[str, Any], destination: str | Path) -> Path:
    path = Path(destination)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        path.write_text(render_html_report(result), encoding="utf-8")
    return path
