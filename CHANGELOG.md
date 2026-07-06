# Changelog

## Unreleased

## [0.3.0] - 2026-07-06
- Fixed package discovery so editable installs only include the `volguard` package.
- Added GitHub Actions CI for install, lint, format, tests, and package build.
- Cleaned the existing code and tests so the baseline passes ruff and pytest.
- Added snapshot and TI rule validation with short CLI errors for bad input files.
- Added source hashing, generated metadata, severity counts, and stable finding timestamps.
- Added CSV exports and a `scan-dir` command with a batch index.

## [0.2.0] - 2025-11-09
- Clean rewrite without placeholders
- Deterministic CLI and HTML report
- Tests on synthetic fixtures
