from __future__ import annotations
from typing import List
from datetime import datetime, timezone
from ..core.data_models import Process, Finding

def detect_hidden_processes(processes: List[Process]) -> List[Finding]:
    findings: List[Finding] = []
    now = datetime.now(timezone.utc).isoformat()
    for p in processes:
        # Present in pool (pool scan) but not linked in ActiveProcessLinks => likely hidden via DKOM
        if p.present_in_pool and not p.in_active_list:
            findings.append(Finding(
                ts=now,
                detector="hidden_processes",
                severity="high",
                pid=p.pid,
                description=f"Process hidden from ActiveProcessLinks: {p.name} (pid={p.pid})",
                tags=["hide", "dkom"],
            ))
    return findings
