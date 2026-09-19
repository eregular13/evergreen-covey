from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from covey.cli import build_parser, main
from covey.errors import RunnerError, ScopeError
from covey.scope import HMAC_ENV, load, sign_file
from tests.helpers import write_scope


def _unsigned_body(*, demo: bool | None = None) -> str:
    lines = [
        "version: 1",
        "consent:",
        "  signed: true",
        "  signer: client",
        "  purpose: authorized-engagement",
        "window:",
        "  start: '2026-01-01T00:00:00Z'",
        "  end: '2029-12-31T23:59:59Z'",
        "adapter: nmap",
        "targets:",
        "  - cidr: 10.42.0.0/28",
    ]
    if demo is True:
        lines.insert(1, "demo: true")
    elif demo is False:
        lines.insert(1, "demo: false")
    return "\n".join(lines) + "\n"


def test_sign_with_hmac_does_not_force_demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(HMAC_ENV, "client-day-unit-test-key")
    path = tmp_path / "scope.yaml"
    path.write_text(_unsigned_body(), encoding="utf-8")
    signed = sign_file(path)
    assert signed["demo"] is False
    scope = load(path)
    assert scope.demo is False
    assert scope.signer == "client"


def test_sign_without_hmac_defaults_demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(HMAC_ENV, raising=False)
    path = tmp_path / "scope.yaml"
    path.write_text(_unsigned_body(), encoding="utf-8")
    signed = sign_file(path)
    assert signed["demo"] is True


def test_sign_demo_false_without_hmac_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv(HMAC_ENV, raising=False)
    path = tmp_path / "scope.yaml"
    path.write_text(_unsigned_body(demo=False), encoding="utf-8")
    with pytest.raises(ScopeError, match="COVEY_SCOPE_HMAC_KEY"):
        sign_file(path)


def test_cli_sign_demo_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(HMAC_ENV, raising=False)
    path = tmp_path / "scope.yaml"
    path.write_text(_unsigned_body(), encoding="utf-8")
    assert main(["sign", "--scope", str(path), "--demo"]) == 0
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["demo"] is True
    assert data["signature"]


def test_assess_missing_binary_fails_before_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = write_scope(tmp_path / "scope.yaml", adapter="nmap")
    spawned = {"run": False}

    def no_bin(_name: str = "nmap", **_k):
        raise RunnerError("nmap not found on PATH")

    def no_run(*_a, **_k):
        spawned["run"] = True
        raise AssertionError("assess must not spawn when BYO is missing")

    monkeypatch.setattr("covey.ready.resolve_exec", no_bin)
    monkeypatch.setattr("covey.cli.run_plan", no_run)
    assert main(["assess", "--scope", str(path), "--out", str(tmp_path / "out")]) == 1
    assert spawned["run"] is False


def test_cli_lists_ready_and_assess():
    text = build_parser().format_help()
    assert "ready" in text
    assert "assess" in text
    assert "client-day" in text.lower() or "preflight" in text.lower()
