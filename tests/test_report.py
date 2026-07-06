import csv
import json
from pathlib import Path

from volguard.core.scan import scan_snapshot
from volguard.report import write_report


def test_write_report_outputs_json_html_and_csv(tmp_path):
    snapshot_path = Path("tests/fixtures/snapshot_win11_24h2_case1.json")
    with open("tests/fixtures/ti_rules.json", encoding="utf-8") as rules_file:
        rules = json.load(rules_file)

    summary = scan_snapshot(snapshot_path, rules)
    write_report(summary, tmp_path)

    assert (tmp_path / "summary.json").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "findings.csv").exists()

    with (tmp_path / "findings.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == summary["counts"]["total"]
    assert {"ts", "detector", "severity", "pid", "description", "tags"} <= set(rows[0])
