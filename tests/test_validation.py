import json
import sys

import pytest

from volguard.cli import _load_ti_rules, main
from volguard.core.data_models import (
    Finding,
    Process,
    SnapshotValidationError,
    load_snapshot,
)


def test_load_snapshot_rejects_non_object_root():
    with pytest.raises(SnapshotValidationError, match="snapshot root must be an object"):
        load_snapshot([])


def test_load_snapshot_rejects_non_list_section():
    with pytest.raises(SnapshotValidationError, match="processes must be a list"):
        load_snapshot({"processes": {}})


def test_load_snapshot_reports_section_index():
    with pytest.raises(
        SnapshotValidationError,
        match=r"processes\[0\]: pid must be an integer >= 0",
    ):
        load_snapshot(
            {
                "processes": [
                    {
                        "pid": "4",
                        "ppid": 0,
                        "name": "bad.exe",
                        "cmd": None,
                        "in_active_list": True,
                        "present_in_pool": True,
                        "threads": 1,
                    }
                ]
            }
        )


def test_process_rejects_negative_thread_count():
    with pytest.raises(SnapshotValidationError, match="threads must be an integer >= 0"):
        Process(
            pid=4,
            ppid=0,
            name="bad.exe",
            cmd=None,
            in_active_list=True,
            present_in_pool=True,
            threads=-1,
        )


def test_finding_rejects_unknown_severity():
    with pytest.raises(SnapshotValidationError, match="severity must be low, medium, or high"):
        Finding(
            ts="2026-07-06T00:00:00+00:00",
            detector="unit",
            severity="critical",
            pid=None,
            description="Bad severity",
            tags=["test"],
        )


def test_ti_rules_validate_root_and_patterns(tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps({"pattern": "x"}), encoding="utf-8")

    with pytest.raises(SnapshotValidationError, match="TI rules file must contain a JSON list"):
        _load_ti_rules(rules_path)

    rules_path.write_text(json.dumps([{"pattern": 42}]), encoding="utf-8")

    with pytest.raises(SnapshotValidationError, match=r"TI rules\[0\]\.pattern must be a string"):
        _load_ti_rules(rules_path)

    rules_path.write_text(json.dumps([{"pattern": "x", "id": 42}]), encoding="utf-8")

    with pytest.raises(SnapshotValidationError, match=r"TI rules\[0\]\.id must be a string"):
        _load_ti_rules(rules_path)


def test_cli_reports_snapshot_validation_error(monkeypatch, tmp_path, capsys):
    snapshot_path = tmp_path / "bad_snapshot.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "processes": [
                    {
                        "pid": "4",
                        "ppid": 0,
                        "name": "bad.exe",
                        "cmd": None,
                        "in_active_list": True,
                        "present_in_pool": True,
                        "threads": 1,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["volguard", "scan", "--image", str(snapshot_path), "--out", str(tmp_path / "out")],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
    assert "processes[0]: pid must be an integer >= 0" in capsys.readouterr().err
