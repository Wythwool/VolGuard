from __future__ import annotations

import argparse
import json
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

    args = p.parse_args()
    if args.cmd == "scan":
        image = Path(args.image)
        if not image.exists():
            p.error(f"file not found: {image}")
        rules_path = Path(args.ti_rules) if args.ti_rules else None
        if rules_path and not rules_path.exists():
            p.error(f"TI rules file not found: {rules_path}")
        try:
            rules = _load_ti_rules(rules_path)
            summary = scan_snapshot(image, rules)
            write_report(summary, args.out)
        except JSONDecodeError as exc:
            p.error(f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}")
        except SnapshotValidationError as exc:
            p.error(str(exc))
        except OSError as exc:
            p.error(str(exc))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
