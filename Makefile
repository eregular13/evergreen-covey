.PHONY: prove test unit venv clean

VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

$(VENV)/bin/python:
	python3 -m venv $(VENV) || ( \
	  rm -rf $(VENV); \
	  sudo apt-get update && sudo apt-get install -y python3.12-venv; \
	  python3 -m venv $(VENV); \
	)
	$(PIP) install -U pip
	$(PIP) install -e ".[dev]"

venv: $(VENV)/bin/python

unit: venv
	$(PY) -m pytest -q -m "not integration"

test: venv
	$(PY) -m pytest -q

# Full prove: BYO nmap (install on this VM if needed), shard the loopback
# lab, run pass1+pass2 through the Covey runner, then unit + integration tests.
prove: venv
	$(PY) -m covey prove
	$(PY) -m pytest -q

clean:
	rm -rf out .pytest_cache src/*.egg-info *.egg-info
