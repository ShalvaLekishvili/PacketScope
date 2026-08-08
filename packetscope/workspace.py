from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any
from uuid import uuid4

from .slicing import slice_capture


SESSION_RE = re.compile(r"^[a-f0-9]{32}$")
VALID_STATUSES = {"new", "triage", "investigating", "contained", "resolved", "dismissed"}
VALID_VERDICTS = {"unknown", "benign", "suspicious", "malicious", "false_positive"}


class WorkspaceError(ValueError):
    pass


class EvidenceStore:
    """Small local evidence workspace for web investigations.

    Sessions live on the PacketScope host only. They expire by TTL and can be
    explicitly deleted. The API never accepts user-provided filesystem paths.
    """

    def __init__(self, root: str | Path | None = None, ttl_seconds: int | None = None):
        base = root or os.environ.get("PACKETSCOPE_WORKDIR") or (Path(tempfile.gettempdir()) / "packetscope-sessions")
        self.root = Path(base)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        self.ttl_seconds = int(ttl_seconds or os.environ.get("PACKETSCOPE_SESSION_TTL", 4 * 3600))

    def _dir(self, session_id: str) -> Path:
        if not SESSION_RE.fullmatch(session_id):
            raise WorkspaceError("Invalid session identifier")
        return self.root / session_id

    def cleanup(self) -> int:
        now = time.time()
        removed = 0
        for child in self.root.iterdir():
            if not child.is_dir() or not SESSION_RE.fullmatch(child.name):
                continue
            try:
                age = now - child.stat().st_mtime
                if age > self.ttl_seconds:
                    shutil.rmtree(child, ignore_errors=True)
                    removed += 1
            except OSError:
                continue
        return removed

    def create(self, capture_path: str | Path, result: dict[str, Any], source_name: str) -> dict[str, Any]:
        self.cleanup()
        session_id = uuid4().hex
        folder = self._dir(session_id)
        folder.mkdir(mode=0o700)
        capture = folder / "evidence.capture"
        shutil.move(str(capture_path), capture)
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        stored = {**result, "session_id": session_id, "source_name": Path(source_name).name, "workspace": {"created_at": now, "expires_in_seconds": self.ttl_seconds}}
        (folder / "result.json").write_text(json.dumps(stored, ensure_ascii=False), encoding="utf-8")
        (folder / "annotations.json").write_text("{}", encoding="utf-8")
        self.touch(session_id)
        return stored

    def touch(self, session_id: str) -> None:
        folder = self._dir(session_id)
        if not folder.exists():
            raise WorkspaceError("Investigation session not found")
        now = time.time()
        os.utime(folder, (now, now))

    def get(self, session_id: str) -> dict[str, Any]:
        folder = self._dir(session_id)
        result_path = folder / "result.json"
        if not result_path.exists():
            raise WorkspaceError("Investigation session not found")
        self.touch(session_id)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        annotations = self._read_annotations(folder)
        for finding in result.get("findings", []):
            finding["analyst"] = annotations.get(finding.get("id"), {
                "status": "new", "verdict": "unknown", "note": "", "tags": []
            })
        return result

    def annotate(self, session_id: str, finding_id: str, update: dict[str, Any]) -> dict[str, Any]:
        folder = self._dir(session_id)
        result = self.get(session_id)
        finding_ids = {item.get("id") for item in result.get("findings", [])}
        if finding_id not in finding_ids:
            raise WorkspaceError("Finding not found in this investigation")
        current = self._read_annotations(folder).get(finding_id, {
            "status": "new", "verdict": "unknown", "note": "", "tags": []
        })
        if "status" in update:
            if update["status"] not in VALID_STATUSES:
                raise WorkspaceError("Invalid finding status")
            current["status"] = update["status"]
        if "verdict" in update:
            if update["verdict"] not in VALID_VERDICTS:
                raise WorkspaceError("Invalid analyst verdict")
            current["verdict"] = update["verdict"]
        if "note" in update:
            current["note"] = str(update["note"])[:5000]
        if "tags" in update:
            if not isinstance(update["tags"], list):
                raise WorkspaceError("tags must be a list")
            current["tags"] = sorted({str(x).strip()[:64] for x in update["tags"] if str(x).strip()})[:20]
        current["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        annotations = self._read_annotations(folder)
        annotations[finding_id] = current
        (folder / "annotations.json").write_text(json.dumps(annotations, ensure_ascii=False, indent=2), encoding="utf-8")
        self.touch(session_id)
        return current

    def slice_finding(self, session_id: str, finding_id: str, destination: str | Path) -> Path:
        folder = self._dir(session_id)
        result = self.get(session_id)
        finding = next((item for item in result.get("findings", []) if item.get("id") == finding_id), None)
        if not finding:
            raise WorkspaceError("Finding not found in this investigation")
        packet_ids = (finding.get("evidence") or {}).get("packet_ids") or []
        if not packet_ids:
            raise WorkspaceError("This finding has no packet-level evidence IDs")
        return slice_capture(folder / "evidence.capture", destination, packet_ids)

    def delete(self, session_id: str) -> None:
        folder = self._dir(session_id)
        if not folder.exists():
            raise WorkspaceError("Investigation session not found")
        shutil.rmtree(folder)

    @staticmethod
    def _read_annotations(folder: Path) -> dict[str, Any]:
        path = folder / "annotations.json"
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}
