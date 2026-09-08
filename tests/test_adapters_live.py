from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from covey.adapters import LIVE_ADAPTER_IDS, adapter_for
from covey.adapters.common import tile_broadcast, tile_hosts, tile_range
from covey.errors import AdapterError

FIXTURES = Path(__file__).parent / "fixtures"
ADAPTER_FIXTURES = FIXTURES / "adapters"
TILE = "10.42.0.0/30"
LIVE = ["10.42.0.1", "10.42.0.2"]
PREFIX = "shards/p1-s00/scan"
EXPECT_PARSE = ("10.9.8.7", "10.9.8.8")


def _seed_artifacts(name: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if name == "nmap":
        shutil.copy(FIXTURES / "scan_up.xml", dest / "scan.xml")
        return
    if name == "masscan":
        text = (ADAPTER_FIXTURES / "masscan.json").read_text(encoding="utf-8")
        (dest / "scan.json").write_text(text, encoding="utf-8")
        return
    src = ADAPTER_FIXTURES / f"{name}.txt"
    text = src.read_text(encoding="utf-8")
    (dest / "stdout.log").write_text(text, encoding="utf-8")
    (dest / "scan.txt").write_text(text, encoding="utf-8")


@pytest.mark.parametrize("name", LIVE_ADAPTER_IDS)
def test_pass1_argv_nonempty_uses_tile(name: str):
    adapter = adapter_for(name)
    argv = adapter.pass1_argv(TILE, PREFIX)
    assert argv
    assert argv[0]
    blob = " ".join(argv)
    files = {}
    if hasattr(adapter, "stage_files"):
        files = adapter.stage_files("pass1", TILE, PREFIX)
    combined = blob + "\n" + "".join(files.values())
    start, last = tile_range(TILE)
    assert (
        TILE in combined
        or any(host in combined for host in tile_hosts(TILE))
        or tile_broadcast(TILE) in combined
        or start in combined
        or last in combined
    )


@pytest.mark.parametrize("name", LIVE_ADAPTER_IDS)
def test_pass2_argv_nonempty_and_refuses_empty(name: str):
    adapter = adapter_for(name)
    with pytest.raises(AdapterError):
        adapter.pass2_argv([], "shards/p2-s00/scan")
    argv = adapter.pass2_argv(LIVE, "shards/p2-s00/scan")
    assert argv
    template = adapter.pass2_argv_template("shards/p2-s00/scan")
    assert template
    files = {}
    if hasattr(adapter, "stage_files"):
        files = adapter.stage_files("pass2", ",".join(LIVE), "shards/p2-s00/scan")
    combined = " ".join(argv) + "\n" + "".join(files.values())
    assert any(host in combined for host in LIVE)


@pytest.mark.parametrize("name", LIVE_ADAPTER_IDS)
def test_parse_live_hosts_from_family_fixture(name: str, tmp_path: Path):
    adapter = adapter_for(name)
    _seed_artifacts(name, tmp_path)
    hosts = adapter.parse_live_hosts(tmp_path)
    assert hosts
    if name == "nmap":
        assert hosts == ["127.0.0.1", "127.0.0.3"]
        return
    for expect in EXPECT_PARSE:
        assert expect in hosts


def test_tile_hosts_expands_slash30():
    assert tile_hosts("10.42.0.0/30") == ["10.42.0.1", "10.42.0.2"]
    assert tile_hosts("10.42.0.5/32") == ["10.42.0.5"]


@pytest.mark.integration
def test_optional_fping_resolve():
    import shutil

    from covey.runner import resolve_exec

    if not shutil.which("fping"):
        pytest.skip("BYO fping not available")
    spec = resolve_exec("fping")
    assert spec.kind == "local"
    assert spec.entrypoint == "fping"
