from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..plugins.dkom import detect_dkom
from ..plugins.etw_ti import detect_etw_ti
from ..plugins.hidden_processes import detect_hidden_processes
from ..plugins.ssdt_hooks import detect_ssdt_hooks
from .data_models import SnapshotValidationError, Timeline, load_snapshot


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _optional_string(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SnapshotValidationError(f"{key} must be a string")
    return value


def _severity_counts(findings: Timeline) -> dict[str, int]:
    return {
        "high": len([f for f in findings if f.severity == "high"]),
        "medium": len([f for f in findings if f.severity == "medium"]),
        "low": len([f for f in findings if f.severity == "low"]),
    }


def scan_snapshot(path: str | Path, ti_rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    snapshot_path = Path(path)
    data = json.loads(snapshot_path.read_text(encoding="utf-8"))
    processes, ssdt, etw_events = load_snapshot(data)
    generated_at = datetime.now(UTC).isoformat()
    os_version = _optional_string(data, "os_version")
    snapshot_timestamp = _optional_string(data, "timestamp")
    finding_timestamp = snapshot_timestamp or generated_at

    findings: Timeline = []
    findings += detect_hidden_processes(processes, finding_timestamp)
    findings += detect_dkom(processes, finding_timestamp)
    findings += detect_ssdt_hooks(ssdt, finding_timestamp)
    if ti_rules:
        findings += detect_etw_ti(etw_events, ti_rules, finding_timestamp)
    findings.sort(key=lambda f: f.ts)
    summary = {
        "metadata": {
            "schema_version": "volguard.snapshot.v1",
            "source_path": str(snapshot_path),
            "source_sha256": _file_sha256(snapshot_path),
            "generated_at": generated_at,
        },
        "os_version": os_version,
        "timestamp": snapshot_timestamp,
        "counts": {
            "hidden_processes": len([f for f in findings if f.detector == "hidden_processes"]),
            "dkom": len([f for f in findings if f.detector == "dkom"]),
            "ssdt_hooks": len([f for f in findings if f.detector == "ssdt_hooks"]),
            "etw_ti": len([f for f in findings if f.detector == "etw_ti"]),
            "total": len(findings),
        },
        "severity_counts": _severity_counts(findings),
        "findings": [f.__dict__ for f in findings],
    }
    return summary
