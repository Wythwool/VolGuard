import json
from volguard.core.scan import scan_snapshot

def test_e2e_scan_fixture(tmp_path):
    summary = scan_snapshot("tests/fixtures/snapshot_win11_24h2_case1.json", json.load(open("tests/fixtures/ti_rules.json")))
    assert summary["counts"]["total"] >= 3
    assert summary["counts"]["hidden_processes"] >= 1
    assert summary["counts"]["ssdt_hooks"] >= 1
