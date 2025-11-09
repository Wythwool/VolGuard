from __future__ import annotations
from pathlib import Path
from typing import Dict, Any
from rich.table import Table
from rich.console import Console
from jinja2 import Template

_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>VolGuard Report</title>
<style>
body{font-family:ui-sans-serif,system-ui;margin:2rem;}
table{border-collapse:collapse;width:100%;}
th,td{border:1px solid #ddd;padding:8px;}
th{background:#f3f4f6;text-align:left;}
.bad{color:#b91c1c;font-weight:600;}
.ok{color:#065f46;font-weight:600;}
</style>
</head><body>
<h1>VolGuard findings</h1>
<p><b>OS:</b> {{ os_version }} &nbsp; <b>Snapshot:</b> {{ timestamp }}</p>
<table>
<thead><tr><th>Time (UTC)</th><th>Detector</th><th>Severity</th><th>PID</th><th>Description</th><th>Tags</th></tr></thead>
<tbody>
{% for f in findings %}
<tr>
  <td>{{ f.ts }}</td>
  <td>{{ f.detector }}</td>
  <td class="{{ 'bad' if f.severity!='low' else 'ok' }}">{{ f.severity }}</td>
  <td>{{ f.pid if f.pid is not none else '' }}</td>
  <td>{{ f.description }}</td>
  <td>{{ ','.join(f.tags) }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</body></html>"""

def write_report(summary: Dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    # JSON
    (out / "summary.json").write_text(__import__("json").dumps(summary, indent=2), encoding="utf-8")
    # HTML
    html = Template(_HTML).render(**summary)
    (out / "report.html").write_text(html, encoding="utf-8")
    # Console pretty table (optional artifact)
    table = Table(title="VolGuard findings")
    table.add_column("Time")
    table.add_column("Detector")
    table.add_column("Severity")
    table.add_column("PID")
    table.add_column("Description")
    table.add_column("Tags")
    for f in summary["findings"]:
        table.add_row(f["ts"], f["detector"], f["severity"], str(f["pid"] or ""), f["description"], ",".join(f["tags"]))
    Console().print(table)
