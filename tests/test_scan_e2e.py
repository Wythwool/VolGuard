import hashlib
import json
from pathlib import Path

from volguard.core.scan import scan_snapshot


def test_e2e_scan_fixture():
    snapshot_path = Path("tests/fixtures/snapshot_win11_24h2_case1.json")
    with open("tests/fixtures/ti_rules.json", encoding="utf-8") as rules_file:
        rules = json.load(rules_file)

    summary = scan_snapshot(snapshot_path, rules)

    assert summary["counts"]["total"] >= 3
    assert summary["counts"]["hidden_processes"] >= 1
    assert summary["counts"]["ssdt_hooks"] >= 1
    assert summary["counts"]["etw_ti"] >= 1
    assert summary["severity_counts"] == {"high": 2, "medium": 1, "low": 2}
    assert (
        summary["metadata"]["source_sha256"]
        == hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    )
    assert {finding["ts"] for finding in summary["findings"]} == {summary["timestamp"]}
