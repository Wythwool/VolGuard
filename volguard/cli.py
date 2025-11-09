from __future__ import annotations
import argparse, json, os
from .core.scan import scan_snapshot
from .report import write_report
from . import __version__

def main() -> int:
    p = argparse.ArgumentParser(prog="volguard", description=f"VolGuard CLI v{__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="Scan a JSON snapshot and write report")
    ps.add_argument("--image", required=True, help="Path to JSON snapshot")
    ps.add_argument("--out", default="artifacts", help="Output directory (default: artifacts)")
    ps.add_argument("--ti-rules", default="tests/fixtures/ti_rules.json", help="Optional TI rules JSON")

    args = p.parse_args()
    if args.cmd == "scan":
        image = args.image
        if not os.path.exists(image):
            p.error(f"file not found: {image}")
        rules = None
        if args.ti_rules and os.path.exists(args.ti_rules):
            rules = json.loads(open(args.ti_rules, "r", encoding="utf-8").read())
        summary = scan_snapshot(image, rules)
        write_report(summary, args.out)
        return 0
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
