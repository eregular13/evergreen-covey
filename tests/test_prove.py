from __future__ import annotations

from pathlib import Path

import pytest

from covey.prove import run_prove
from covey.runner import resolve_nmap
from covey.scope import load


def test_committed_lab_scope_is_signed_and_tiny():
    scope = load(Path("examples/scope.lab.yaml"))
    assert scope.demo is True
    assert scope.max_workers <= 4
    cidrs = [t.listed for t in scope.targets]
    assert cidrs == ["127.0.0.0/28"]
    assert all(not c.endswith("/8") for c in cidrs)
    assert "0.0.0.0/0" not in cidrs


@pytest.mark.integration
def test_prove_invokes_byo_nmap(tmp_path: Path):
    try:
        resolve_nmap()
    except Exception:
        pytest.skip("BYO nmap not available")
    summary = run_prove(out_root=tmp_path, install_if_missing=False)
    assert summary["ok"] is True
    assert len(summary["shards"]) >= 2
    assert summary["pass1_workers"] >= 2
    assert summary["pass2_ran"] >= 1
    assert summary["live_hosts"]
    assert all(h.startswith("127.0.0.") for h in summary["live_hosts"])
    xmls = list(tmp_path.glob("shards/*/scan.xml"))
    assert len(xmls) >= 3
