from __future__ import annotations

from datetime import UTC, datetime

from ..core.data_models import Finding, Process


def detect_dkom(
    processes: list[Process],
    timestamp: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    ts = timestamp or datetime.now(UTC).isoformat()
    for p in processes:
        if p.present_in_pool and p.in_active_list and p.threads == 0:
            findings.append(
                Finding(
                    ts=ts,
                    detector="dkom",
                    severity="medium",
                    pid=p.pid,
                    description=f"Suspicious EPROCESS: zero threads for {p.name} (pid={p.pid})",
                    tags=["dkom", "threads"],
                )
            )
        if p.ppid is not None and p.ppid == p.pid:
            findings.append(
                Finding(
                    ts=ts,
                    detector="dkom",
                    severity="low",
                    pid=p.pid,
                    description=f"Suspicious PPID loop for {p.name} (pid={p.pid})",
                    tags=["dkom", "ppid"],
                )
            )
    return findings
