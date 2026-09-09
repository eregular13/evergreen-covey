.PHONY: prove prove-rustscan prove-fping prove-naabu prove-nping prove-httpx prove-sslscan prove-tlsx prove-whatweb prove-hping3 prove-onesixtyone test unit venv export clean

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

# Fourth e2e-proven adapter. BYO naabu (GitHub release on this VM only).
# Does not replace `make prove` (nmap stays the default).
prove-naabu: venv
	$(PY) -m covey prove --adapter naabu --out out/naabu

# Fifth e2e-proven adapter. BYO nping (nmap apt on this VM only).
# Unprivileged --tcp-connect against the loopback lab listener.
# Does not replace `make prove` (nmap stays the default).
prove-nping: venv
	$(PY) -m covey prove --adapter nping --out out/nping

# Sixth e2e-proven adapter. BYO httpx (GitHub release on this VM only).
# Needs an HTTP 200 lab, not a bare TCP accept.
# Does not replace `make prove` (nmap stays the default).
prove-httpx: venv
	$(PY) -m covey prove --adapter httpx --out out/httpx

# Seventh e2e-proven adapter. BYO sslscan (apt on this VM only).
# Needs a TLS handshake lab, not HTTP or a bare TCP accept.
# Does not replace `make prove` (nmap stays the default).
prove-sslscan: venv
	$(PY) -m covey prove --adapter sslscan --out out/sslscan

# Eighth e2e-proven adapter. BYO tlsx (GitHub release on this VM only).
# Needs a TLS handshake lab, not HTTP or a bare TCP accept.
# Does not replace `make prove` (nmap stays the default).
prove-tlsx: venv
	$(PY) -m covey prove --adapter tlsx --out out/tlsx

# Ninth e2e-proven adapter. BYO whatweb (apt on this VM only).
# Needs an HTTP 200 lab, not a bare TCP accept.
# Does not replace `make prove` (nmap stays the default).
prove-whatweb: venv
	$(PY) -m covey prove --adapter whatweb --out out/whatweb

# Tenth e2e-proven adapter. BYO hping3 (apt + setcap on this VM only).
# ICMP on loopback; no TCP lab listener. Raw sockets need CAP_NET_RAW.
# Does not replace `make prove` (nmap stays the default).
prove-hping3: venv
	$(PY) -m covey prove --adapter hping3 --out out/hping3

# Eleventh e2e-proven adapter. BYO onesixtyone (apt on this VM only).
# Needs an SNMPv1 GetResponse lab, not a UDP echo.
# Does not replace `make prove` (nmap stays the default).
prove-onesixtyone: venv
	$(PY) -m covey prove --adapter onesixtyone --out out/onesixtyone

clean:
	rm -rf out .pytest_cache src/*.egg-info *.egg-info
