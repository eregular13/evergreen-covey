from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from covey.adapters.registry import UNPROVEN_ADAPTERS
from covey.cli import build_parser, main
from covey.client_day_dry import (
    SAMPLE_PURPOSE,
    UNPROVEN_FOUR,
    format_dry,
    lab_hmac_only,
    run_dry,
)
from covey.errors import RunnerError
from covey.scope import HMAC_ENV

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
CLIENT_EXAMPLE = REPO_ROOT / "examples" / "scope.client.example.yaml"


def _unproven_template(tmp_path: Path, adapter: str) -> Path:
    data = yaml.safe_load(CLIENT_EXAMPLE.read_text(encoding="utf-8"))
    data["adapter"] = adapter
    path = tmp_path / f"scope.{adapter.replace('-', '_')}.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_unproven_four_match_registry():
    assert tuple(UNPROVEN_FOUR) == UNPROVEN_ADAPTERS
    assert UNPROVEN_ADAPTERS == ("masscan", "arp-scan", "netdiscover", "zmap")


def test_scripts_exist_and_lock_license():
    sh = (SCRIPTS / "client_day_dry.sh").read_text(encoding="utf-8")
    ps1 = (SCRIPTS / "client_day_dry.ps1").read_text(encoding="utf-8")
    for text in (sh, ps1):
        assert "client-day-dry" in text
        assert "strict-e2e" in text
        assert "apt-get install" not in text
        assert "apt install" not in text
        assert "sudo apt" not in text
        assert "nmap.org" not in text
        assert "LICENSE-LOCK" in text
        assert "SAMPLE" in text
        assert "RiskReady" in text
        lowered = text.lower()
        assert "never apt-install" in lowered or "never apt-get" in lowered
    assert "#!/usr/bin/env bash" in sh
    assert '-m covey client-day-dry' in sh
    assert "client-day-dry" in ps1


def test_readme_and_client_day_doc_lead_with_dry():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    docs = (REPO_ROOT / "docs" / "CLIENT_DAY.md").read_text(encoding="utf-8")
    assert "scripts/client_day_dry.sh" in readme.splitlines()[2]
    assert "client_day_dry.ps1" in readme
    assert "scripts/client_day_dry.sh" in docs
    assert "ready --strict-e2e" in docs
    assert "SAMPLE ≠ client" in docs
    assert "RiskReady" in docs
    lock = (REPO_ROOT / "LICENSE-LOCK.md").read_text(encoding="utf-8")
    assert "client-day-dry" in lock
    assert "client_day_dry.sh" in lock


def test_cli_lists_client_day_dry():
    text = build_parser().format_help()
    assert "client-day-dry" in text
    assert "strict-e2e" in text


def test_dry_sign_ready_plan_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    called = {"ensure": False, "run": False}

    def boom(*_a, **_k):
        called["ensure"] = True
        raise AssertionError("client-day-dry must not prove-install")

    def no_run(*_a, **_k):
        called["run"] = True
        raise AssertionError("client-day-dry must not spawn")

    monkeypatch.setattr("covey.runner.ensure_nmap", boom)
    monkeypatch.setattr("covey.cli.run_plan", no_run)
    monkeypatch.setenv(HMAC_ENV, "must-not-be-used-for-sample-dry")

    work = tmp_path / "work"
    summary = run_dry(work=work, repo=REPO_ROOT)
    assert summary["ok"] is True
    assert summary["install"] is False
    assert summary["spawn"] is False
    assert summary["sample"] is True
    assert summary["demo"] is True
    assert called["ensure"] is False
    assert called["run"] is False
    assert isinstance(summary["elapsed_s"], float)

    staged = work / "scope.yaml"
    data = yaml.safe_load(staged.read_text(encoding="utf-8"))
    assert data["demo"] is True
    assert data["signature"]
    assert data["consent"]["purpose"] == SAMPLE_PURPOSE
    assert data["adapter"] == "nmap"

    example = yaml.safe_load(CLIENT_EXAMPLE.read_text(encoding="utf-8"))
    assert "signature" not in example
    assert example["demo"] is False

    plan_text = (work / "plan.json").read_text(encoding="utf-8")
    assert '"adapter": "nmap"' in plan_text
    assert '"workers"' in plan_text
    assert summary["pack_drop"]
    pack = Path(summary["pack_drop"])
    assert pack.is_dir()
    assert (pack / "meta.json").is_file()
    meta = (pack / "meta.json").read_text(encoding="utf-8")
    assert "covey.pack_drop.v1" in meta
    assert "evergreen-covey" in meta

    text = format_dry(summary)
    assert "elapsed" in text
    assert "pack_drop" in text
    assert "SAMPLE ≠ client" in text
    assert "no apt-install" in text or "install   false" in text


def test_cli_client_day_dry(tmp_path: Path, capsys):
    work = tmp_path / "cli-work"
    assert main(["client-day-dry", "--work", str(work)]) == 0
    out = capsys.readouterr().out
    assert "client-day dry" in out
    assert "elapsed" in out
    assert "pack_drop" in out
    assert (work / "plan.json").is_file()
    assert (work / "ready.json").is_file()
    assert (work / "sample_run" / "pack_drop" / "meta.json").is_file()


@pytest.mark.parametrize("name", UNPROVEN_FOUR)
def test_dry_strict_e2e_refuses_unproven(tmp_path: Path, name: str):
    src = _unproven_template(tmp_path, name)
    work = tmp_path / "refuse"
    with pytest.raises(RunnerError, match="argv\\+unit only"):
        run_dry(work=work, scope_src=src, repo=REPO_ROOT)
    assert not (work / "plan.json").exists()


@pytest.mark.parametrize("name", UNPROVEN_FOUR)
def test_cli_client_day_dry_refuses_unproven(tmp_path: Path, name: str, capsys):
    src = _unproven_template(tmp_path, name)
    work = tmp_path / f"cli-{name}"
    assert main(
        ["client-day-dry", "--scope", str(src), "--work", str(work)]
    ) == 1
    err = capsys.readouterr().err
    assert "argv+unit only" in err
    assert name in err


def test_dry_no_export_still_plans(tmp_path: Path):
    work = tmp_path / "no-export"
    summary = run_dry(work=work, repo=REPO_ROOT, no_export=True)
    assert summary["ok"] is True
    assert summary["pack_drop"] is None
    assert "disabled" in summary["export"]
    assert (work / "plan.json").is_file()


def test_dry_reports_byo_miss(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def missing(_name: str = "nmap", **_k):
        raise RunnerError("nmap not found on PATH")

    monkeypatch.setattr("covey.ready.resolve_exec", missing)
    work = tmp_path / "miss"
    summary = run_dry(work=work, repo=REPO_ROOT)
    assert "nmap" in summary["missing"]
    assert summary["ok"] is True
    assert summary["install"] is False
    text = format_dry(summary)
    assert "BYO miss" in text
    assert "nmap" in text
    assert "no apt-install" in text


def test_lab_hmac_only_restores_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(HMAC_ENV, "restore-me")
    with lab_hmac_only():
        assert HMAC_ENV not in __import__("os").environ
    assert __import__("os").environ[HMAC_ENV] == "restore-me"


def test_shell_script_invokes_entry(tmp_path: Path):
    script = SCRIPTS / "client_day_dry.sh"
    assert script.is_file()
    text = script.read_text(encoding="utf-8")
    assert 'exec "$PY" -m covey client-day-dry "$@"' in text
    mode = script.stat().st_mode
    assert mode & stat.S_IXUSR


def test_shell_script_runs_dry(tmp_path: Path):
    script = SCRIPTS / "client_day_dry.sh"
    work = tmp_path / "script-work"
    env = os.environ.copy()
    env["PYTHON"] = sys.executable
    env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(
        [str(script), "--work", str(work)],
        cwd=str(REPO_ROOT),
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "elapsed" in proc.stdout
    assert "pack_drop" in proc.stdout
    assert (work / "plan.json").is_file()
    assert (work / "sample_run" / "pack_drop").is_dir()
