from __future__ import annotations
from typing import List
from datetime import datetime, timezone
from ..core.data_models import Process, Finding

def detect_dkom(processes: List[Process]) -> List[Finding]:
    findings: List[Finding] = []
    now = datetime.now(timezone.utc).isoformat()
    for p in processes:
        # Simple heuristics: zero threads or parent mismatch can indicate unlinking / tampering
        if p.present_in_pool and p.in_active_list and p.threads == 0:
            findings.append(Finding(
                ts=now, detector="dkom", severity="medium", pid=p.pid,
                description=f"Suspicious EPROCESS: zero threads for {p.name} (pid={p.pid})",
                tags=["dkom", "threads"]
            ))
        if p.ppid is not None and p.ppid == p.pid:
            findings.append(Finding(
                ts=now, detector="dkom", severity="low", pid=p.pid,
                description=f"Suspicious PPID loop for {p.name} (pid={p.pid})",
                tags=["dkom", "ppid"]
            ))
    return findings
