from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .core.scan import scan_snapshot
from .report import write_report


def main() -> int:
    p = argparse.ArgumentParser(prog="volguard", description=f"VolGuard CLI v{__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="Scan a JSON snapshot and write report")
    ps.add_argument("--image", required=True, help="Path to JSON snapshot")
    ps.add_argument("--out", default="artifacts", help="Output directory (default: artifacts)")
    ps.add_argument(
        "--ti-rules",
        default="tests/fixtures/ti_rules.json",
        help="Optional TI rules JSON",
    )

    args = p.parse_args()
    if args.cmd == "scan":
        image = Path(args.image)
        if not image.exists():
            p.error(f"file not found: {image}")
        rules = None
        rules_path = Path(args.ti_rules) if args.ti_rules else None
        if rules_path and rules_path.exists():
            rules = json.loads(rules_path.read_text(encoding="utf-8"))
        summary = scan_snapshot(str(image), rules)
        write_report(summary, args.out)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
