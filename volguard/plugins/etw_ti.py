from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from ..core.data_models import EtwEvent, Finding


def detect_etw_ti(
    events: list[EtwEvent],
    rules: list[dict[str, Any]],
    timestamp: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    ts = timestamp or datetime.now(UTC).isoformat()
    patterns = []
    for r in rules:
        pat = r.get("pattern")
        if not isinstance(pat, str) or not pat:
            continue
        rule_id = r.get("id", "TI")
        description = r.get("description", "match")
        if not isinstance(rule_id, str) or not isinstance(description, str):
            continue
        try:
            patterns.append((re.compile(pat, re.I), rule_id, description))
        except re.error:
            continue
    for ev in events:
        cmd = ev.cmdline or ev.message or ""
        for rex, tid, desc in patterns:
            if rex.search(cmd):
                findings.append(
                    Finding(
                        ts=ts,
                        detector="etw_ti",
                        severity="low",
                        pid=ev.pid,
                        description=f"ETW TI match: {desc} (pid={ev.pid})",
                        tags=[tid],
                    )
                )
    return findings
