from __future__ import annotations
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
from .data_models import Timeline, load_snapshot, EtwEvent
from ..plugins.hidden_processes import detect_hidden_processes
from ..plugins.dkom import detect_dkom
from ..plugins.ssdt_hooks import detect_ssdt_hooks
from ..plugins.etw_ti import detect_etw_ti

def scan_snapshot(path: str, ti_rules: Optional[List[dict]] = None) -> Dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    processes, ssdt, etw_events = load_snapshot(data)
    findings: Timeline = []
    findings += detect_hidden_processes(processes)
    findings += detect_dkom(processes)
    findings += detect_ssdt_hooks(ssdt)
    if ti_rules:
        findings += detect_etw_ti(etw_events, ti_rules)
    findings.sort(key=lambda f: f.ts)
    summary = {
        "os_version": data.get("os_version"),
        "timestamp": data.get("timestamp"),
        "counts": {
            "hidden_processes": len([f for f in findings if f.detector == "hidden_processes"]),
            "dkom": len([f for f in findings if f.detector == "dkom"]),
            "ssdt_hooks": len([f for f in findings if f.detector == "ssdt_hooks"]),
            "etw_ti": len([f for f in findings if f.detector == "etw_ti"]),
            "total": len(findings),
        },
        "findings": [f.__dict__ for f in findings],
    }
    return summary
