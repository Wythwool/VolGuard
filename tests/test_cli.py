import json
import shutil
import sys
from pathlib import Path

from volguard.cli import main


def test_scan_dir_writes_batch_index(monkeypatch, tmp_path):
    source_dir = tmp_path / "snapshots"
    source_dir.mkdir()
    shutil.copyfile(
        Path("tests/fixtures/snapshot_win11_24h2_case1.json"),
        source_dir / "good.json",
    )
    (source_dir / "bad.json").write_text('{"processes": "not a list"}', encoding="utf-8")
    out_dir = tmp_path / "out"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "volguard",
            "scan-dir",
            str(source_dir),
            "--pattern",
            "*.json",
            "--ti-rules",
            "tests/fixtures/ti_rules.json",
            "--out",
            str(out_dir),
        ],
    )

    exit_code = main()

    assert exit_code == 1
    index = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
    assert index["summary"]["total_files"] == 2
    assert index["summary"]["ok"] == 1
    assert index["summary"]["error"] == 1
    assert index["summary"]["findings"] == 5
    assert (out_dir / "0002_good" / "summary.json").exists()
    assert (out_dir / "0002_good" / "findings.csv").exists()
