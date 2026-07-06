from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from . import __version__
from .core.data_models import SnapshotValidationError
from .core.scan import scan_snapshot
from .report import write_report


def _load_ti_rules(path: Path | None) -> list[dict[str, Any]] | None:
    if path is None:
        return None

    rules = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rules, list):
        raise SnapshotValidationError("TI rules file must contain a JSON list")

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise SnapshotValidationError(f"TI rules[{index}] must be an object")
        pattern = rule.get("pattern")
        if pattern is not None and not isinstance(pattern, str):
            raise SnapshotValidationError(f"TI rules[{index}].pattern must be a string")
        rule_id = rule.get("id")
        if rule_id is not None and not isinstance(rule_id, str):
            raise SnapshotValidationError(f"TI rules[{index}].id must be a string")
        description = rule.get("description")
        if description is not None and not isinstance(description, str):
            raise SnapshotValidationError(f"TI rules[{index}].description must be a string")
    return rules


def _json_error(exc: JSONDecodeError) -> str:
    return f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}"


def _rules_path(parser: argparse.ArgumentParser, value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if not path.exists():
        parser.error(f"TI rules file not found: {path}")
    return path


def _scan_one(
    image: Path,
    out_dir: Path,
    rules: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    summary = scan_snapshot(image, rules)
    write_report(summary, out_dir)
    return summary


def _case_dir_name(index: int, snapshot: Path) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
    stem = "".join(char if char in allowed else "_" for char in snapshot.stem).strip("._")
    if not stem:
        stem = "snapshot"
    return f"{index:04d}_{stem}"


def _scan_dir(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    source_dir = Path(args.directory)
    if not source_dir.exists():
        parser.error(f"directory not found: {source_dir}")
    if not source_dir.is_dir():
        parser.error(f"not a directory: {source_dir}")

    snapshots = sorted(path for path in source_dir.glob(args.pattern) if path.is_file())
    if not snapshots:
        parser.error(f"no files matched {args.pattern!r} in {source_dir}")

    rules = _load_ti_rules(_rules_path(parser, args.ti_rules))
    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = []

    for index, snapshot in enumerate(snapshots, start=1):
        case_out = out_root / _case_dir_name(index, snapshot)
        try:
            summary = _scan_one(snapshot, case_out, rules)
            cases.append(
                {
                    "input": str(snapshot),
                    "report_dir": str(case_out),
                    "status": "ok",
                    "source_sha256": summary["metadata"]["source_sha256"],
                    "counts": summary["counts"],
                    "severity_counts": summary["severity_counts"],
                }
            )
        except JSONDecodeError as exc:
            cases.append({"input": str(snapshot), "status": "error", "error": _json_error(exc)})
        except (SnapshotValidationError, OSError) as exc:
            cases.append({"input": str(snapshot), "status": "error", "error": str(exc)})

    ok_count = len([case for case in cases if case["status"] == "ok"])
    index_doc = {
        "metadata": {
            "source_dir": str(source_dir),
            "pattern": args.pattern,
            "generated_at": datetime.now(UTC).isoformat(),
        },
        "summary": {
            "total_files": len(cases),
            "ok": ok_count,
            "error": len(cases) - ok_count,
            "findings": sum(case.get("counts", {}).get("total", 0) for case in cases),
        },
        "cases": cases,
    }
    (out_root / "index.json").write_text(json.dumps(index_doc, indent=2), encoding="utf-8")
    return 0 if ok_count == len(cases) else 1


def _scan_file(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    image = Path(args.image)
    if not image.exists():
        parser.error(f"file not found: {image}")

    try:
        rules = _load_ti_rules(_rules_path(parser, args.ti_rules))
        _scan_one(image, Path(args.out), rules)
    except JSONDecodeError as exc:
        parser.error(_json_error(exc))
    except SnapshotValidationError as exc:
        parser.error(str(exc))
    except OSError as exc:
        parser.error(str(exc))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="volguard", description=f"VolGuard CLI v{__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="Scan a JSON snapshot and write report")
    ps.add_argument("--image", required=True, help="Path to JSON snapshot")
    ps.add_argument("--out", default="artifacts", help="Output directory (default: artifacts)")
    ps.add_argument(
        "--ti-rules",
        default=None,
        help="Optional TI rules JSON",
    )

    psd = sub.add_parser("scan-dir", help="Scan JSON snapshots in a directory")
    psd.add_argument("directory", help="Directory containing snapshot JSON files")
    psd.add_argument("--pattern", default="*.json", help="Glob pattern inside the directory")
    psd.add_argument("--out", default="artifacts", help="Output directory (default: artifacts)")
    psd.add_argument(
        "--ti-rules",
        default=None,
        help="Optional TI rules JSON",
    )

    args = p.parse_args()
    if args.cmd == "scan":
        return _scan_file(p, args)
    if args.cmd == "scan-dir":
        return _scan_dir(p, args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
