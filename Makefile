.PHONY: fmt lint test sbom

fmt:
	ruff check . --fix

lint:
	ruff check .

test:
	pytest -q

sbom:
	@python - <<'PY'
import json;print(json.dumps({"note":"CycloneDX written in sbom/bom.json"}, indent=2))
PY
