from __future__ import annotations

from datetime import UTC, datetime

from ..core.data_models import Finding, Process


def detect_hidden_processes(processes: list[Process]) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(UTC).isoformat()
    for p in processes:
        if p.present_in_pool and not p.in_active_list:
            findings.append(
                Finding(
                    ts=now,
                    detector="hidden_processes",
                    severity="high",
                    pid=p.pid,
                    description=f"Process hidden from ActiveProcessLinks: {p.name} (pid={p.pid})",
                    tags=["hide", "dkom"],
                )
            )
    return findings
