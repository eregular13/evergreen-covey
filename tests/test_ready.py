from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from covey.adapters.registry import (
    ADAPTER_HOST_NEEDS,
    E2E_PROVEN_ADAPTERS,
    LIVE_ADAPTER_IDS,
    UNPROVEN_ADAPTERS,
    desktop_or_host_adapters,
    host_need,
)
from covey.cli import main
from covey.errors import RunnerError, ScopeError
from covey.ready import check_ready, format_ready
from tests.helpers import write_scope

REPO_ROOT = Path(__file__).resolve().parents[1]
UNPROVEN_FOUR = ("masscan", "arp-scan", "netdiscover", "zmap")


def test_host_needs_cover_every_live_adapter():
    assert set(ADAPTER_HOST_NEEDS) == set(LIVE_ADAPTER_IDS)
    for name in LIVE_ADAPTER_IDS:
        need = host_need(name)
        assert "desktop_or_host" in need
        assert need["needs"]
        assert need["reason"]
    for name in UNPROVEN_ADAPTERS:
        assert host_need(name)["desktop_or_host"] is True
    desktop = desktop_or_host_adapters()
    assert set(UNPROVEN_FOUR) <= set(desktop)
    assert "hping3" in desktop
    assert "nbtscan" in desktop
    assert "unicornscan" in desktop
    assert "nmap" not in desktop
    assert "rustscan" not in desktop


def test_ready_unsigned_scope_refused(tmp_path: Path):
    path = tmp_path / "scope.yaml"
    path.write_text("version: 1\n", encoding="utf-8")
    with pytest.raises(ScopeError, match="unsigned|empty"):
        check_ready(path)


@pytest.mark.parametrize("name", E2E_PROVEN_ADAPTERS)
def test_ready_reports_e2e_proven_and_never_installs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
):
    called = {"ensure": False}

    def boom(*_a, **_k):
        called["ensure"] = True
        raise AssertionError("ready must not prove-install")

    monkeypatch.setattr("covey.runner.ensure_nmap", boom)
    monkeypatch.setattr("covey.runner.ensure_rustscan", boom)
    path = write_scope(tmp_path / "scope.yaml", adapter=name)
    summary = check_ready(path, require_binary=False)
    assert summary["ok"] is True
    assert summary["install"] is False
    assert summary["spawn"] is False
    assert called["ensure"] is False
    row = next(item for item in summary["adapters"] if item["adapter"] == name)
    assert row["e2e_proven"] is True
    assert name not in summary["unproven"]


@pytest.mark.parametrize("name", UNPROVEN_FOUR)
def test_ready_reports_unproven_desktop(tmp_path: Path, name: str):
    path = write_scope(tmp_path / "scope.yaml", adapter=name)
    summary = check_ready(path, require_binary=False)
    assert name in summary["unproven"]
    row = next(item for item in summary["adapters"] if item["adapter"] == name)
    assert row["e2e_proven"] is False
    assert row["desktop_or_host"] is True
    assert summary["install"] is False
    assert summary["spawn"] is False


@pytest.mark.parametrize("name", UNPROVEN_FOUR)
def test_ready_strict_e2e_fails_closed(tmp_path: Path, name: str):
    path = write_scope(tmp_path / "scope.yaml", adapter=name)
    with pytest.raises(RunnerError, match="argv\\+unit only"):
        check_ready(path, require_binary=False, strict_e2e=True)


def test_ready_missing_binary_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = write_scope(tmp_path / "scope.yaml", adapter="nmap")

    def missing(_name: str = "nmap", **_k):
        raise RunnerError("nmap not found on PATH")

    monkeypatch.setattr("covey.ready.resolve_exec", missing)
    summary = check_ready(path, require_binary=True)
    assert summary["ok"] is False
    assert "nmap" in summary["missing"]
    assert summary["install"] is False


def test_cli_ready_plan_only_writes_json(tmp_path: Path, capsys):
    path = write_scope(tmp_path / "scope.yaml", adapter="nmap")
    dest = tmp_path / "ready.json"
    assert main(["ready", "--scope", str(path), "--plan-only", "--out", str(dest)]) == 0
    captured = capsys.readouterr()
    assert "e2e_proven" in captured.out
    assert "install   false" in captured.out
    blob = dest.read_text(encoding="utf-8")
    assert "surface map" in blob
    assert '"install": false' in blob


def test_cli_ready_strict_e2e_unproven_exits_nonzero(tmp_path: Path):
    path = write_scope(tmp_path / "scope.yaml", adapter="masscan")
    assert main(["ready", "--scope", str(path), "--plan-only", "--strict-e2e"]) == 1


def test_ready_file_drop_needs_no_binary(tmp_path: Path):
    drop = tmp_path / "in" / "openvas.xml"
    drop.parent.mkdir(parents=True)
    drop.write_text("<openvas/>\n", encoding="utf-8")
    path = write_scope(
        tmp_path / "scope.yaml",
        adapter="nmap",
        targets=[{"file_drop": "in/openvas.xml"}],
    )
    summary = check_ready(path, require_binary=True)
    assert summary["ok"] is True
    assert summary["file_drop"] is True
    assert summary["missing"] == []
    assert "no live spawn" in summary["adapters"][0]["binary"]


def test_format_ready_lists_unproven_and_honesty():
    text = format_ready(
        {
            "ok": False,
            "scope": "scope.yaml",
            "demo": False,
            "signer": "client",
            "purpose": "authorized",
            "adapter": "masscan",
            "pipeline": ["masscan"],
            "file_drop": False,
            "adapters": [
                {
                    "adapter": "masscan",
                    "e2e_proven": False,
                    "desktop_or_host": True,
                    "reason": "raw SYN",
                    "needs": ("BYO masscan",),
                    "binary_ok": False,
                    "binary": "missing",
                }
            ],
            "missing": ["masscan"],
            "unproven": ["masscan"],
            "desktop_or_host": ["masscan"],
            "honesty": "surface map ≠ honeypot validated ≠ control operating effectiveness",
        }
    )
    assert "argv+unit only" in text
    assert "prove fails closed" in text
    assert "desktop" in text.lower()
    assert "surface map" in text


def test_client_example_is_unsigned_production_template():
    path = REPO_ROOT / "examples" / "scope.client.example.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["demo"] is False
    assert "signature" not in data
    assert data["adapter"] == "nmap"
    assert data["allow_wide"] is False
    cidrs = [row["cidr"] for row in data["targets"]]
    assert cidrs == ["10.42.0.0/28"]
    assert "0.0.0.0/0" not in cidrs
    with pytest.raises(ScopeError, match="unsigned"):
        check_ready(path)
