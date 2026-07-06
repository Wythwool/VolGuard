from volguard.core.data_models import Process
from volguard.plugins.hidden_processes import detect_hidden_processes


def test_hidden_process_detects_pool_only():
    procs = [
        Process(
            pid=1,
            ppid=0,
            name="init",
            cmd=None,
            in_active_list=True,
            present_in_pool=True,
            threads=1,
        ),
        Process(
            pid=2,
            ppid=1,
            name="ghost.exe",
            cmd=None,
            in_active_list=False,
            present_in_pool=True,
            threads=2,
        ),
    ]
    findings = detect_hidden_processes(procs)
    assert any(f.pid == 2 for f in findings)
