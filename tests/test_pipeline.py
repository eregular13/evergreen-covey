from __future__ import annotations

import pytest

from covey.errors import ScopeError
from covey.plan import build_plan
from covey.scope import from_mapping, load
from tests.helpers import signed_scope_dict


def test_pipeline_sets_adapter_to_first_stage():
    data = signed_scope_dict(pipeline=["nmap", "httpx", "sslscan"])
    scope = from_mapping(data)
    assert scope.adapter == "nmap"
    assert scope.pipeline == ("nmap", "httpx", "sslscan")


def test_pipeline_nuclei_refused():
    data = signed_scope_dict(pipeline=["nmap", "nuclei"])
    with pytest.raises(ScopeError, match="LICENSE-LOCK"):
        from_mapping(data)


def test_pipeline_openvas_refused():
    data = signed_scope_dict(pipeline=["nmap", "openvas"])
    with pytest.raises(ScopeError, match="file_drop"):
        from_mapping(data)


def test_pipeline_too_long_refused():
    data = signed_scope_dict(
        pipeline=["nmap", "httpx", "sslscan", "tlsx", "whatweb", "nping"]
    )
    with pytest.raises(ScopeError, match="longer"):
        from_mapping(data)


def test_pipeline_duplicate_refused():
    data = signed_scope_dict(pipeline=["nmap", "nmap"])
    with pytest.raises(ScopeError, match="duplicate"):
        from_mapping(data)


def test_single_adapter_plan_unchanged():
    scope = load(signed_scope_dict(targets=[{"cidr": "10.42.0.0/30"}]))
    plan = build_plan(scope, out_root="out")
    assert plan.adapter == "nmap"
    assert plan.pipeline == ["nmap"]
    assert len(plan.pass1_workers) == 1
    assert len(plan.pass2_workers) == 1
    assert plan.pipe_workers == []


def test_pipeline_plan_skips_first_adapter_pass2():
    scope = load(
        signed_scope_dict(
            pipeline=["nmap", "httpx", "sslscan"],
            targets=[{"cidr": "10.42.0.0/30"}],
            pass2={"ports": "80,443"},
        )
    )
    plan = build_plan(scope, out_root="out")
    assert plan.adapter == "nmap"
    assert plan.pipeline == ["nmap", "httpx", "sslscan"]
    assert len(plan.pass1_workers) == 1
    assert plan.pass1_workers[0].argv[0] == "nmap"
    assert plan.pass2_workers == []
    tools = [w.tool for w in plan.pipe_workers]
    assert tools == ["httpx", "sslscan"]
    assert all(w.stage.startswith("pipe:") for w in plan.pipe_workers)
    assert plan.pipe_workers[0].argv_template is not None
    assert plan.pipe_workers[0].argv_template[0] == "httpx"
    assert plan.pipe_workers[1].argv_template[0] == "sslscan"
