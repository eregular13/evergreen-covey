from __future__ import annotations

from pathlib import Path

import pytest

from covey.errors import ScopeError
from covey.plan import build_plan
from covey.scope import load
from tests.helpers import signed_scope_dict


def test_pass2_ports_flow_into_nmap_plan():
    scope = load(
        signed_scope_dict(
            targets=[{"cidr": "10.42.0.0/30"}],
            pass2={"ports": "22,80,443", "host_timeout": "5s"},
        )
    )
    assert scope.deepen.ports == "22,80,443"
    assert scope.deepen.host_timeout == "5s"
    plan = build_plan(scope, out_root="out")
    template = plan.pass2_workers[0].argv_template
    assert template is not None
    assert template[template.index("-p") + 1] == "22,80,443"
    assert template[template.index("--host-timeout") + 1] == "5s"
    assert plan.to_dict()["deepen"]["ports"] == "22,80,443"


def test_deepen_alias_and_list_ports():
    scope = load(
        signed_scope_dict(
            targets=[{"cidr": "10.42.0.0/30"}],
            deepen={"ports": [22, 3389]},
        )
    )
    assert scope.deepen.ports == "22,3389"


def test_empty_pass2_ports_refused():
    with pytest.raises(ScopeError, match="empty"):
        load(signed_scope_dict(pass2={"ports": ""}))


def test_injectable_ports_refused():
    with pytest.raises(ScopeError, match="invalid"):
        load(signed_scope_dict(pass2={"ports": "22; rm -rf /"}))


def test_unsigned_still_refused_with_ports():
    data = signed_scope_dict(pass2={"ports": "22"})
    data.pop("signature")
    with pytest.raises(ScopeError, match="unsigned"):
        load(data)


def test_masscan_honors_scope_ports():
    scope = load(
        signed_scope_dict(
            adapter="masscan",
            targets=[{"cidr": "10.42.0.0/30"}],
            pass2={"ports": "25,587"},
        )
    )
    plan = build_plan(scope, out_root="out")
    blob = " ".join(plan.pass2_workers[0].argv_template or [])
    assert "-p25,587" in blob


def test_lab_scope_declares_pass2_ports():
    scope = load(Path("examples/scope.lab.yaml"))
    assert scope.deepen.ports == "22"
