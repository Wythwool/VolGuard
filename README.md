# VolGuard

Detectors and helpers for Windows memory forensics. Includes four analysis passes you can reuse in Volatility3-style workflows or on synthetic snapshots:

- Hidden processes (psscan vs ActiveProcessLinks)
- DKOM anomalies
- SSDT hooks (kernel pointers that look off)
- ETW Threat Intelligence pattern matches (against command-line rules)

## Install

```bash
python -m venv .venv && . .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .[dev]
```

## Quick demo (synthetic snapshot)

```bash
volguard scan --image tests/fixtures/snapshot_win11_24h2_case1.json --out out
```

Outputs:
- `out/summary.json` — machine-readable findings
- `out/report.html` — simple timeline for humans

## Structure

- `volguard/core/` — dataclasses and the offline scanner (`scan_snapshot`)
- `volguard/plugins/` — pure-python detectors (no framework imports)
- `volguard/report.py` — HTML/JSON writers
- `volguard/cli.py` — CLI wrapper

The code is written so tests run on synthetic fixtures without heavy memory images. To use in Volatility3, adapt the detectors inside your plugin wrappers and feed them real enumerations (process lists, SSDT entries, ETW chunks).

## Tests

```bash
pytest -q
```

## License

MIT

Tip: see `tests/fixtures` for demo data.
