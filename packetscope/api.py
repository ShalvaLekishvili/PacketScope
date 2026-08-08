from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from . import __version__
from .analysis import analyze_capture
from .capture import CaptureFormatError
from .config import AnalysisConfig
from .reporting import render_html_report
from .workspace import EvidenceStore, WorkspaceError

PACKAGE_DIR = Path(__file__).resolve().parent
WEB_DIR = PACKAGE_DIR / "web"
SAMPLE_DIR = PACKAGE_DIR / "sample_data"
MAX_UPLOAD_BYTES = int(os.environ.get("PACKETSCOPE_MAX_UPLOAD_MB", "100")) * 1024 * 1024
store = EvidenceStore()

app = FastAPI(
    title="PacketScope API",
    version=__version__,
    description="Local-first defensive PCAP/PCAPNG network-forensics API with ephemeral investigation workspaces.",
)


def _analysis_config() -> AnalysisConfig:
    path = os.environ.get("PACKETSCOPE_CONFIG")
    if not path:
        return AnalysisConfig()
    try:
        return AnalysisConfig.from_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(500, f"Invalid PACKETSCOPE_CONFIG: {exc}") from exc


def _workspace_error(exc: WorkspaceError) -> HTTPException:
    message = str(exc)
    return HTTPException(404 if "not found" in message.lower() else 400, message)


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "workspace_ttl_seconds": store.ttl_seconds,
        "max_upload_bytes": MAX_UPLOAD_BYTES,
    }


@app.get("/api/config")
def config() -> dict:
    return _analysis_config().as_dict()


@app.post("/api/analyze")
async def analyze(request: Request, filename: str = "capture.pcap"):
    suffix = Path(filename).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(415, "Expected a .pcap, .pcapng, or .cap file")

    total = 0
    temp_path: Path | None = None
    moved = False
    try:
        with tempfile.NamedTemporaryFile(prefix="packetscope-upload-", suffix=suffix, delete=False) as tmp:
            temp_path = Path(tmp.name)
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB web-upload limit. Use the CLI or raise PACKETSCOPE_MAX_UPLOAD_MB for larger evidence sets.")
                tmp.write(chunk)
        if total == 0:
            raise HTTPException(400, "Empty capture")
        result = analyze_capture(temp_path, config=_analysis_config())
        stored = store.create(temp_path, result, Path(filename).name)
        moved = True
        return JSONResponse(stored)
    except CaptureFormatError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        if temp_path and temp_path.exists() and not moved:
            temp_path.unlink(missing_ok=True)


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str):
    try:
        return JSONResponse(store.get(session_id))
    except WorkspaceError as exc:
        raise _workspace_error(exc) from exc


@app.patch("/api/sessions/{session_id}/findings/{finding_id}")
async def annotate_finding(session_id: str, finding_id: str, request: Request):
    try:
        update = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(400, "Invalid JSON body") from exc
    if not isinstance(update, dict):
        raise HTTPException(400, "Expected a JSON object")
    allowed = {key: value for key, value in update.items() if key in {"status", "verdict", "note", "tags"}}
    if not allowed:
        raise HTTPException(400, "No supported annotation fields supplied")
    try:
        return JSONResponse(store.annotate(session_id, finding_id, allowed))
    except WorkspaceError as exc:
        raise _workspace_error(exc) from exc


@app.get("/api/sessions/{session_id}/findings/{finding_id}/slice")
def finding_slice(session_id: str, finding_id: str):
    fd, raw_path = tempfile.mkstemp(prefix="packetscope-slice-", suffix=".pcapng")
    os.close(fd)
    path = Path(raw_path)
    try:
        store.slice_finding(session_id, finding_id, path)
    except WorkspaceError as exc:
        path.unlink(missing_ok=True)
        raise _workspace_error(exc) from exc
    except ValueError as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(400, str(exc)) from exc
    return FileResponse(
        path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"PacketScope-{finding_id}.pcapng",
        background=BackgroundTask(path.unlink, missing_ok=True),
    )


@app.get("/api/sessions/{session_id}/report", response_class=HTMLResponse)
def session_report(session_id: str):
    try:
        result = store.get(session_id)
    except WorkspaceError as exc:
        raise _workspace_error(exc) from exc
    return HTMLResponse(render_html_report(result))


@app.delete("/api/sessions/{session_id}", status_code=204)
def delete_session(session_id: str):
    try:
        store.delete(session_id)
    except WorkspaceError as exc:
        raise _workspace_error(exc) from exc
    return None


@app.post("/api/report", response_class=HTMLResponse)
async def report(request: Request):
    try:
        result = await request.json()
        if not isinstance(result, dict) or "capture" not in result or "posture" not in result:
            raise ValueError
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(400, "Invalid PacketScope result JSON")
    return HTMLResponse(render_html_report(result))


@app.get("/api/demo")
def demo():
    demo_path = SAMPLE_DIR / "demo-beacon.pcap"
    if not demo_path.exists():
        raise HTTPException(404, "Demo capture is not bundled")
    temp = Path(tempfile.mktemp(prefix="packetscope-demo-", suffix=".pcap"))
    shutil.copy2(demo_path, temp)
    try:
        result = analyze_capture(temp, config=_analysis_config())
        return JSONResponse(store.create(temp, result, demo_path.name))
    finally:
        temp.unlink(missing_ok=True)


if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
