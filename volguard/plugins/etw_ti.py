from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from ..core.data_models import EtwEvent, Finding


def detect_etw_ti(events: list[EtwEvent], rules: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(UTC).isoformat()
    patterns = []
    for r in rules:
        pat = r.get("pattern")
        if not pat:
            continue
        try:
            patterns.append(
                (re.compile(pat, re.I), r.get("id", "TI"), r.get("description", "match"))
            )
        except re.error:
            continue
    for ev in events:
        cmd = ev.cmdline or ev.message or ""
        for rex, tid, desc in patterns:
            if rex.search(cmd):
                findings.append(
                    Finding(
                        ts=now,
                        detector="etw_ti",
                        severity="low",
                        pid=ev.pid,
                        description=f"ETW TI match: {desc} (pid={ev.pid})",
                        tags=[tid],
                    )
                )
    return findings
