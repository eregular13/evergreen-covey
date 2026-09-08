from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from covey.adapters.registry import (
    E2E_PROVEN_ADAPTERS,
    LIVE_ADAPTER_IDS,
    UNPROVEN_ADAPTERS,
)
from covey.cli import main
from covey.errors import RunnerError
from covey.export import export_pack
from covey.prove import run_prove
from covey.runner import resolve_exec, resolve_nmap
from covey.scope import load

REPO_ROOT = Path(__file__).resolve().parents[1]
HONESTY_DOCS = (REPO_ROOT / "PROVE.md", REPO_ROOT / "README.md")


def test_committed_lab_scope_is_signed_and_tiny():
    scope = load(Path("examples/scope.lab.yaml"))
    assert scope.demo is True
    assert scope.max_workers <= 4
    cidrs = [t.listed for t in scope.targets]
    assert cidrs == ["127.0.0.0/28"]
    assert all(not c.endswith("/8") for c in cidrs)
    assert "0.0.0.0/0" not in cidrs
    assert scope.deepen.ports == "22"


def test_committed_rustscan_lab_scope_is_signed_and_tiny():
    scope = load(Path("examples/scope.lab.rustscan.yaml"))
    assert scope.demo is True
    assert scope.adapter == "rustscan"
    assert scope.max_workers <= 4
    cidrs = [t.listed for t in scope.targets]
    assert cidrs == ["127.0.0.0/28"]
    assert all(not c.endswith("/8") for c in cidrs)
    assert "0.0.0.0/0" not in cidrs
    assert scope.deepen.ports == "18080"


def test_committed_fping_lab_scope_is_signed_and_tiny():
    scope = load(Path("examples/scope.lab.fping.yaml"))
    assert scope.demo is True
    assert scope.adapter == "fping"
    assert scope.max_workers <= 4
    cidrs = [t.listed for t in scope.targets]
    assert cidrs == ["127.0.0.0/28"]
    assert all(not c.endswith("/8") for c in cidrs)
    assert "0.0.0.0/0" not in cidrs
    assert scope.deepen.ports is None


def test_committed_naabu_lab_scope_is_signed_and_tiny():
    scope = load(Path("examples/scope.lab.naabu.yaml"))
    assert scope.demo is True
    assert scope.adapter == "naabu"
    assert scope.max_workers <= 4
    cidrs = [t.listed for t in scope.targets]
    assert cidrs == ["127.0.0.0/28"]
    assert all(not c.endswith("/8") for c in cidrs)
    assert "0.0.0.0/0" not in cidrs
    assert scope.deepen.ports == "18080"


def test_e2e_proven_adapters_are_nmap_rustscan_fping_naabu():
    assert E2E_PROVEN_ADAPTERS == ("nmap", "rustscan", "fping", "naabu")
    assert len(UNPROVEN_ADAPTERS) == 16
    assert set(E2E_PROVEN_ADAPTERS).isdisjoint(UNPROVEN_ADAPTERS)
    assert set(E2E_PROVEN_ADAPTERS) | set(UNPROVEN_ADAPTERS) == set(LIVE_ADAPTER_IDS)
    assert UNPROVEN_ADAPTERS == tuple(
        name for name in LIVE_ADAPTER_IDS if name not in E2E_PROVEN_ADAPTERS
    )


@pytest.mark.parametrize("name", UNPROVEN_ADAPTERS)
def test_prove_refuses_unproven_adapter(name: str):
    with pytest.raises(RunnerError, match="argv\\+unit only"):
        run_prove(adapter=name, install_if_missing=False)


@pytest.mark.parametrize("name", UNPROVEN_ADAPTERS)
def test_cli_prove_unproven_adapter_fails_closed(name: str, tmp_path: Path, capsys):
    assert main(["prove", "--adapter", name, "--no-install", "--out", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    blob = f"{captured.out}\n{captured.err}"
    assert "argv+unit only" in blob
    assert name in blob


@pytest.mark.parametrize("name", UNPROVEN_ADAPTERS)
def test_module_prove_unproven_adapter_fails_closed(name: str, tmp_path: Path):
    env = os.environ.copy()
    src = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "covey",
            "prove",
            "--adapter",
            name,
            "--no-install",
            "--out",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    blob = f"{proc.stdout}\n{proc.stderr}"
    assert "argv+unit only" in blob
    assert name in blob


def test_honesty_docs_follow_e2e_proven_source_of_truth():
    texts = {path.name: path.read_text(encoding="utf-8") for path in HONESTY_DOCS}
    for name, text in texts.items():
        assert "E2E_PROVEN_ADAPTERS" in text, f"{name} must cite E2E_PROVEN_ADAPTERS"
        assert "argv+unit only" in text, f"{name} must say remaining adapters are argv+unit only"
        lowered = text.lower()
        assert "do not claim" in lowered and "live" in lowered
        for proven in E2E_PROVEN_ADAPTERS:
            assert proven in text
        for unproven in UNPROVEN_ADAPTERS:
            # A live-e2e claim would look like a numbered prove row or a
            # successful `prove --adapter <id>` recipe without fail-closed.
            assert f"make prove-{unproven}" not in text
            success = re.search(
                rf"python(?:3)? -m covey prove --adapter {re.escape(unproven)}(?![^\n]*fail)",
                text,
            )
            if success:
                window = text[max(0, success.start() - 80) : success.end() + 80]
                assert "fails closed" in window or "fail closed" in window, (
                    f"{name} offers live prove for {unproven}"
                )

    prove = texts["PROVE.md"]
    for unproven in UNPROVEN_ADAPTERS:
        assert f"`{unproven}`" in prove, f"PROVE.md must list unproven {unproven}"
    assert "fails closed" in prove
    assert "`UNPROVEN_ADAPTERS`" in prove or "UNPROVEN_ADAPTERS" in prove
    assert re.search(r"^\| 3 \| `fping`", prove, re.MULTILINE)
    assert re.search(r"^\| 4 \| `naabu`", prove, re.MULTILINE)
    fifth = re.search(r"^\| 5 \|", prove, re.MULTILINE)
    assert fifth is None, "PROVE.md must not add a fifth live e2e row"

    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "prove-rustscan" in makefile
    assert "prove-fping" in makefile
    assert "prove-naabu" in makefile
    for unproven in UNPROVEN_ADAPTERS:
        assert f"prove-{unproven}" not in makefile, (
            f"Makefile must not grow a live prove target for {unproven}"
        )


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
    pack = export_pack(tmp_path)
    meta = Path(pack["pack"]) / "meta.json"
    assert meta.is_file()
    assert (Path(pack["pack"]) / "README_EXPORT.md").is_file()
    assert (Path(pack["pack"]) / "in" / "nmap").is_dir()


@pytest.mark.integration
def test_prove_invokes_byo_rustscan(tmp_path: Path):
    try:
        resolve_exec("rustscan")
    except Exception:
        pytest.skip("BYO rustscan not available")
    summary = run_prove(
        out_root=tmp_path, adapter="rustscan", install_if_missing=False
    )
    assert summary["ok"] is True
    assert summary["adapter"] == "rustscan"
    assert len(summary["shards"]) >= 2
    assert summary["pass1_workers"] >= 2
    assert summary["pass2_ran"] >= 1
    assert summary["live_hosts"]
    assert all(h.startswith("127.0.0.") for h in summary["live_hosts"])
    argv_files = list(tmp_path.glob("shards/p1-*/argv.json"))
    assert len(argv_files) >= 2
    stdout_files = list(tmp_path.glob("shards/p1-*/stdout.log"))
    assert len(stdout_files) >= 2
    greppable = "\n".join(p.read_text(encoding="utf-8") for p in stdout_files)
    assert " -> [" in greppable


@pytest.mark.integration
def test_prove_invokes_byo_fping(tmp_path: Path):
    try:
        resolve_exec("fping")
    except Exception:
        pytest.skip("BYO fping not available")
    summary = run_prove(
        out_root=tmp_path, adapter="fping", install_if_missing=False
    )
    assert summary["ok"] is True
    assert summary["adapter"] == "fping"
    assert len(summary["shards"]) >= 2
    assert summary["pass1_workers"] >= 2
    assert summary["pass2_ran"] >= 1
    assert summary["live_hosts"]
    assert all(h.startswith("127.0.0.") for h in summary["live_hosts"])
    argv_files = list(tmp_path.glob("shards/p1-*/argv.json"))
    assert len(argv_files) >= 2
    stdout_files = list(tmp_path.glob("shards/p1-*/stdout.log"))
    assert len(stdout_files) >= 2
    alive = "\n".join(p.read_text(encoding="utf-8") for p in stdout_files)
    assert "127.0.0." in alive
    for path in argv_files:
        argv = path.read_text(encoding="utf-8")
        assert "fping" in argv.lower()


@pytest.mark.integration
def test_prove_invokes_byo_naabu(tmp_path: Path):
    try:
        resolve_exec("naabu")
    except Exception:
        pytest.skip("BYO naabu not available")
    summary = run_prove(
        out_root=tmp_path, adapter="naabu", install_if_missing=False
    )
    assert summary["ok"] is True
    assert summary["adapter"] == "naabu"
    assert len(summary["shards"]) >= 2
    assert summary["pass1_workers"] >= 2
    assert summary["pass2_ran"] >= 1
    assert summary["live_hosts"]
    assert all(h.startswith("127.0.0.") for h in summary["live_hosts"])
    argv_files = list(tmp_path.glob("shards/p1-*/argv.json"))
    assert len(argv_files) >= 2
    stdout_files = list(tmp_path.glob("shards/p1-*/stdout.log"))
    assert len(stdout_files) >= 2
    greppable = "\n".join(p.read_text(encoding="utf-8") for p in stdout_files)
    assert ":18080" in greppable
    for path in argv_files:
        argv = path.read_text(encoding="utf-8")
        assert "naabu" in argv.lower()
        assert "18080" in argv
