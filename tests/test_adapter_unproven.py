from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.registry import UNPROVEN_ADAPTERS, adapter_for
from covey.errors import AdapterError
from covey.plan import build_plan
from covey.scope import load
from tests.helpers import signed_scope_dict

FIXTURES = Path(__file__).parent / "fixtures" / "adapters"
UNPROVEN_FOUR = ("masscan", "arp-scan", "netdiscover", "zmap")
TILE = "10.42.0.0/30"
PREFIX = "shards/p1-s00/scan"
LIVE = ["10.42.0.1", "10.42.0.2"]


def test_unproven_four_match_registry():
    assert UNPROVEN_ADAPTERS == UNPROVEN_FOUR


@pytest.mark.parametrize("name", UNPROVEN_FOUR)
def test_unproven_pass1_argv_uses_tile_not_spawn(name: str):
    adapter = adapter_for(name)
    argv = adapter.pass1_argv(TILE, PREFIX)
    assert argv
    assert argv[0] == name
    blob = " ".join(argv)
    assert TILE in blob or "10.42.0." in blob


@pytest.mark.parametrize("name", UNPROVEN_FOUR)
def test_unproven_pass2_refuses_empty_and_targets_live_hosts(name: str):
    adapter = adapter_for(name)
    with pytest.raises(AdapterError):
        adapter.pass2_argv([], PREFIX)
    argv = adapter.pass2_argv(LIVE, PREFIX)
    blob = " ".join(argv)
    assert any(host in blob for host in LIVE) or "{hosts}" in " ".join(
        adapter.pass2_argv_template(PREFIX)
    )


@pytest.mark.parametrize("name", UNPROVEN_FOUR)
def test_unproven_parse_live_hosts_from_fixture(name: str, tmp_path: Path):
    adapter = adapter_for(name)
    dest = tmp_path
    if name == "masscan":
        (dest / "scan.json").write_text(
            (FIXTURES / "masscan.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
    else:
        (dest / "stdout.log").write_text(
            (FIXTURES / f"{name}.txt").read_text(encoding="utf-8"), encoding="utf-8"
        )
    hosts = adapter.parse_live_hosts(dest)
    assert "10.9.8.7" in hosts
    assert "10.9.8.8" in hosts


@pytest.mark.parametrize("name", UNPROVEN_FOUR)
def test_unproven_plans_without_spawn(name: str):
    scope = load(
        signed_scope_dict(
            adapter=name,
            targets=[{"cidr": "10.42.0.0/30"}],
            pass2={"ports": "80"},
        )
    )
    plan = build_plan(scope, out_root="out")
    assert plan.adapter == name
    assert plan.pass1_workers[0].argv is not None
    assert plan.pass1_workers[0].argv[0] == name
    assert plan.pass2_workers[0].argv is None
    assert plan.pass2_workers[0].argv_template is not None
