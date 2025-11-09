from __future__ import annotations
from typing import List, Dict, Any
from datetime import datetime, timezone
import re
from ..core.data_models import EtwEvent, Finding

def detect_etw_ti(events: List[EtwEvent], rules: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    now = datetime.now(timezone.utc).isoformat()
    patterns = []
    for r in rules:
        pat = r.get("pattern")
        if not pat:
            continue
        try:
            patterns.append((re.compile(pat, re.I), r.get("id", "TI"), r.get("description", "match")))
        except re.error:
            # skip invalid user rules
            continue
    for ev in events:
        cmd = ev.cmdline or ev.message or ""
        for rex, tid, desc in patterns:
            if rex.search(cmd):
                findings.append(Finding(
                    ts=now, detector="etw_ti", severity="low", pid=ev.pid,
                    description=f"ETW TI match: {desc} (pid={ev.pid})",
                    tags=[tid]
                ))
    return findings
