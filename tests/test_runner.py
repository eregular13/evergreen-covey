from __future__ import annotations

from pathlib import Path

import pytest

from covey.errors import RunnerError
from covey.runner import ExecSpec, resolve_nmap


def test_local_wrap_replaces_binary():
    spec = ExecSpec(kind="local", nmap="/usr/bin/nmap", display="/usr/bin/nmap")
    argv = spec.wrap(["nmap", "-sn", "127.0.0.1"], cwd=Path("."))
    assert argv[0] == "/usr/bin/nmap"
    assert argv[1:] == ["-sn", "127.0.0.1"]


def test_docker_wrap_forces_entrypoint():
    spec = ExecSpec(kind="docker", nmap="instrumentisto/nmap", display="docker://instrumentisto/nmap")
    argv = spec.wrap(["nmap", "-sn", "-oA", "out/scan", "127.0.0.1"], cwd=Path("/work/repo"))
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "--entrypoint" in argv
    assert argv[argv.index("--entrypoint") + 1] == "nmap"
    assert argv[-4:] == ["-sn", "-oA", "out/scan", "127.0.0.1"]
    assert "nmap" != argv[-5] or argv[argv.index("--entrypoint") + 1] == "nmap"


def test_resolve_respects_covey_nmap(monkeypatch, tmp_path: Path):
    fake = tmp_path / "nmap"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("COVEY_NMAP", str(fake))
    spec = resolve_nmap()
    assert spec.kind == "local"
    assert spec.nmap == str(fake)


def test_resolve_docker_ref_without_docker_fails(monkeypatch):
    monkeypatch.setenv("COVEY_NMAP", "docker://example/nmap")
    monkeypatch.setattr("covey.runner.shutil.which", lambda name: None)
    with pytest.raises(RunnerError, match="docker"):
        resolve_nmap()
