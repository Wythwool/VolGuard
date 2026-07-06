from __future__ import annotations

from datetime import UTC, datetime

from ..core.data_models import Finding, SsdtEntry


def detect_ssdt_hooks(entries: list[SsdtEntry]) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(UTC).isoformat()
    for e in entries:
        if e.expected_module_base is None:
            continue
        module_base = e.expected_module_base
        module_end = module_base + 0x400000
        if not (module_base <= e.addr < module_end):
            findings.append(
                Finding(
                    ts=now,
                    detector="ssdt_hooks",
                    severity="high",
                    pid=None,
                    description=f"SSDT index {e.index} points outside kernel text: 0x{e.addr:x}",
                    tags=["ssdt", "hook"],
                )
            )
    return findings
