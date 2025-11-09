from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

@dataclass
class Process:
    pid: int
    ppid: Optional[int]
    name: str
    cmd: Optional[str]
    in_active_list: bool
    present_in_pool: bool
    threads: int

@dataclass
class SsdtEntry:
    index: int
    addr: int
    expected_module_base: Optional[int]  # if known

@dataclass
class EtwEvent:
    pid: int
    provider: str
    event_id: int
    message: str
    cmdline: Optional[str] = None

@dataclass
class Finding:
    ts: str
    detector: str
    severity: str
    pid: Optional[int]
    description: str
    tags: List[str]

Timeline = List[Finding]

def load_snapshot(obj: Dict[str, Any]) -> tuple[list[Process], list[SsdtEntry], list[EtwEvent]]:
    processes = [Process(**p) for p in obj.get("processes", [])]
    ssdt = [SsdtEntry(**e) for e in obj.get("ssdt", [])]
    etw = [EtwEvent(**e) for e in obj.get("etw_events", [])]
    return processes, ssdt, etw
