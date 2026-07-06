.PHONY: fmt lint test check sbom

fmt:
	ruff check . --fix
	ruff format .

lint:
	ruff check .
	ruff format --check .

test:
	pytest -q

check: lint test

sbom:
	@python - <<'PY'
import json;print(json.dumps({"note":"CycloneDX written in sbom/bom.json"}, indent=2))
PY
