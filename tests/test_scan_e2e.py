import json

from volguard.core.scan import scan_snapshot


def test_e2e_scan_fixture():
    with open("tests/fixtures/ti_rules.json", encoding="utf-8") as rules_file:
        rules = json.load(rules_file)

    summary = scan_snapshot("tests/fixtures/snapshot_win11_24h2_case1.json", rules)

    assert summary["counts"]["total"] >= 3
    assert summary["counts"]["hidden_processes"] >= 1
    assert summary["counts"]["ssdt_hooks"] >= 1
    assert summary["counts"]["etw_ti"] >= 1
