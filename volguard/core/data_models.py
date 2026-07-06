from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Process:
    pid: int
    ppid: int | None
    name: str
    cmd: str | None
    in_active_list: bool
    present_in_pool: bool
    threads: int


@dataclass
class SsdtEntry:
    index: int
    addr: int
    expected_module_base: int | None


@dataclass
class EtwEvent:
    pid: int
    provider: str
    event_id: int
    message: str
    cmdline: str | None = None


@dataclass
class Finding:
    ts: str
    detector: str
    severity: str
    pid: int | None
    description: str
    tags: list[str]


Timeline = list[Finding]


def load_snapshot(obj: dict[str, Any]) -> tuple[list[Process], list[SsdtEntry], list[EtwEvent]]:
    processes = [Process(**p) for p in obj.get("processes", [])]
    ssdt = [SsdtEntry(**e) for e in obj.get("ssdt", [])]
    etw = [EtwEvent(**e) for e in obj.get("etw_events", [])]
    return processes, ssdt, etw
