from __future__ import annotations
from typing import List
from datetime import datetime, timezone
from ..core.data_models import SsdtEntry, Finding

def detect_ssdt_hooks(entries: List[SsdtEntry]) -> List[Finding]:
    findings: List[Finding] = []
    now = datetime.now(timezone.utc).isoformat()
    for e in entries:
        if e.expected_module_base is None:
            # If we don't know the module base, we can't assert a hook; skip.
            continue
        # Heuristic: if function pointer address is not within kernel module base..base+0x400000 => suspect
        module_base = e.expected_module_base
        module_end = module_base + 0x400000
        if not (module_base <= e.addr < module_end):
            findings.append(Finding(
                ts=now, detector="ssdt_hooks", severity="high", pid=None,
                description=f"SSDT index {e.index} points outside kernel text: 0x{e.addr:x}",
                tags=["ssdt", "hook"]
            ))
    return findings
