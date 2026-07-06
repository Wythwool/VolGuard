from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

T = TypeVar("T")


class SnapshotValidationError(ValueError):
    """Raised when a snapshot does not match the input contract."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_int(name: str, value: object, minimum: int = 0) -> int:
    if not _is_int(value) or value < minimum:
        raise SnapshotValidationError(f"{name} must be an integer >= {minimum}")
    return value


def _require_optional_int(name: str, value: object, minimum: int = 0) -> int | None:
    if value is None:
        return None
    return _require_int(name, value, minimum)


def _require_str(name: str, value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SnapshotValidationError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise SnapshotValidationError(f"{name} must not be empty")
    return value


def _require_optional_str(name: str, value: object) -> str | None:
    if value is None:
        return None
    return _require_str(name, value, allow_empty=True)


def _require_bool(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise SnapshotValidationError(f"{name} must be true or false")
    return value


def _require_tags(name: str, value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(tag, str) for tag in value):
        raise SnapshotValidationError(f"{name} must be a list of strings")
    return value


@dataclass
class Process:
    pid: int
    ppid: int | None
    name: str
    cmd: str | None
    in_active_list: bool
    present_in_pool: bool
    threads: int

    def __post_init__(self) -> None:
        self.pid = _require_int("pid", self.pid)
        self.ppid = _require_optional_int("ppid", self.ppid)
        self.name = _require_str("name", self.name)
        self.cmd = _require_optional_str("cmd", self.cmd)
        self.in_active_list = _require_bool("in_active_list", self.in_active_list)
        self.present_in_pool = _require_bool("present_in_pool", self.present_in_pool)
        self.threads = _require_int("threads", self.threads)


@dataclass
class SsdtEntry:
    index: int
    addr: int
    expected_module_base: int | None

    def __post_init__(self) -> None:
        self.index = _require_int("index", self.index)
        self.addr = _require_int("addr", self.addr)
        self.expected_module_base = _require_optional_int(
            "expected_module_base",
            self.expected_module_base,
        )


@dataclass
class EtwEvent:
    pid: int
    provider: str
    event_id: int
    message: str
    cmdline: str | None = None

    def __post_init__(self) -> None:
        self.pid = _require_int("pid", self.pid)
        self.provider = _require_str("provider", self.provider)
        self.event_id = _require_int("event_id", self.event_id)
        self.message = _require_str("message", self.message, allow_empty=True)
        self.cmdline = _require_optional_str("cmdline", self.cmdline)


@dataclass
class Finding:
    ts: str
    detector: str
    severity: str
    pid: int | None
    description: str
    tags: list[str]

    def __post_init__(self) -> None:
        self.ts = _require_str("ts", self.ts)
        self.detector = _require_str("detector", self.detector)
        self.severity = _require_str("severity", self.severity)
        if self.severity not in {"low", "medium", "high"}:
            raise SnapshotValidationError("severity must be low, medium, or high")
        self.pid = _require_optional_int("pid", self.pid)
        self.description = _require_str("description", self.description)
        self.tags = _require_tags("tags", self.tags)


Timeline = list[Finding]


def _load_section(
    obj: dict[str, Any],
    key: str,
    model: Callable[..., T],
) -> list[T]:
    section = obj.get(key, [])
    if not isinstance(section, list):
        raise SnapshotValidationError(f"{key} must be a list")

    parsed = []
    for index, item in enumerate(section):
        if not isinstance(item, dict):
            raise SnapshotValidationError(f"{key}[{index}] must be an object")
        try:
            parsed.append(model(**item))
        except SnapshotValidationError as exc:
            raise SnapshotValidationError(f"{key}[{index}]: {exc}") from exc
        except TypeError as exc:
            raise SnapshotValidationError(f"{key}[{index}]: {exc}") from exc
    return parsed


def load_snapshot(obj: Any) -> tuple[list[Process], list[SsdtEntry], list[EtwEvent]]:
    if not isinstance(obj, dict):
        raise SnapshotValidationError("snapshot root must be an object")

    processes = _load_section(obj, "processes", Process)
    ssdt = _load_section(obj, "ssdt", SsdtEntry)
    etw = _load_section(obj, "etw_events", EtwEvent)
    return processes, ssdt, etw
