.PHONY: prove prove-rustscan prove-fping test unit venv export clean

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

# Pack export from an existing prove/run out/ (no scanner spawn).
export: venv
	$(PY) -m covey export --out out

# Full prove: BYO nmap (install on this VM if needed), shard the loopback
# lab, run pass1+pass2 through the Covey runner, export pack_drop, then tests.
prove: venv
	$(PY) -m covey prove
	$(PY) -m covey export --out out
	$(PY) -m pytest -q

# Second e2e-proven adapter. BYO rustscan (GitHub release on this VM only).
# Does not replace `make prove` (nmap stays the default).
prove-rustscan: venv
	$(PY) -m covey prove --adapter rustscan --out out/rustscan

# Third e2e-proven adapter. BYO fping (apt on this VM only).
# Does not replace `make prove` (nmap stays the default).
prove-fping: venv
	$(PY) -m covey prove --adapter fping --out out/fping

clean:
	rm -rf out .pytest_cache src/*.egg-info *.egg-info
