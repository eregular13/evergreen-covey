from __future__ import annotations

import pytest

from covey.errors import AdapterError, ShardError
from covey.plan import adapter_for, build_plan
from covey.scope import load
from tests.helpers import signed_scope_dict


def test_plan_has_pass1_argv_and_pass2_template():
    scope = load(signed_scope_dict(targets=[{"cidr": "10.42.0.0/30"}]))
    plan = build_plan(scope, out_root="out")
    assert plan.shards == ["10.42.0.0/30"]
    assert len(plan.pass1_workers) == 1
    assert len(plan.pass2_workers) == 1
    p1 = plan.pass1_workers[0]
    assert p1.argv is not None
    assert p1.argv[0] == "nmap"
    assert "-sn" in p1.argv
    assert "10.42.0.0/30" in p1.argv
    p2 = plan.pass2_workers[0]
    assert p2.argv is None
    assert p2.argv_template is not None
    assert "-sV" in p2.argv_template
    assert "{hosts}" in p2.argv_template


def test_lab_slash28_tiles_to_four_shards():
    scope = load(
        signed_scope_dict(
            tile={"default_prefix": 24, "small_prefix": 30},
            targets=[{"cidr": "127.0.0.0/28"}],
        )
    )
    plan = build_plan(scope, out_root="out")
    assert len(plan.shards) >= 2
    assert plan.shards == [
        "127.0.0.0/30",
        "127.0.0.4/30",
        "127.0.0.8/30",
        "127.0.0.12/30",
    ]
    assert plan.max_workers == 2


def test_max_shards_cap():
    scope = load(
        signed_scope_dict(
            max_shards=1,
            tile={"default_prefix": 24, "small_prefix": 30},
            targets=[{"cidr": "10.42.0.0/28"}],
        )
    )
    with pytest.raises(ShardError, match="max_shards"):
        build_plan(scope)


def test_openvas_live_plan_refused():
    with pytest.raises(AdapterError, match="file_drop"):
        adapter_for("openvas")
    scope = load(signed_scope_dict(adapter="openvas"))
    with pytest.raises(AdapterError, match="file_drop"):
        build_plan(scope)
