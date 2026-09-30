PY ?= python3.13
VENV := .venv
BIN := $(VENV)/bin

.PHONY: venv lock install test audit clean

venv:
	test -d $(VENV) || uv venv --python $(PY) $(VENV)

# Pinned, hashed lockfiles (pip-tools compatible format).
lock:
	uv pip compile pyproject.toml --generate-hashes -o requirements.lock
	uv pip compile pyproject.toml --extra dev --generate-hashes -o requirements-dev.lock

install: venv
	uv pip sync --python $(BIN)/python --require-hashes requirements-dev.lock
	uv pip install --python $(BIN)/python --no-deps -e .

test:
	$(BIN)/pytest

audit:
	$(BIN)/pip-audit -r requirements.lock
	$(BIN)/bandit -q -r mailwarden

clean:
	rm -rf $(VENV) .pytest_cache build dist *.egg-info
