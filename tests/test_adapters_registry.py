from __future__ import annotations

import pytest

from covey.adapters import (
    E2E_PROVEN_ADAPTERS,
    FILE_DROP_IDS,
    FORBIDDEN_LIVE,
    LIVE_ADAPTER_IDS,
    UNPROVEN_ADAPTERS,
    OpenVASFileDrop,
    adapter_for,
    file_drop_adapter,
    list_live_adapters,
)
from covey.errors import AdapterError
from covey.plan import adapter_for as plan_adapter_for
from covey.plan import build_plan
from covey.scope import load
from tests.helpers import signed_scope_dict


def test_registry_lists_exactly_20_live_ids():
    ids = list_live_adapters()
    assert ids == LIVE_ADAPTER_IDS
    assert len(ids) == 20
    assert len(set(ids)) == 20
    assert ids[0] == "nmap"
    assert E2E_PROVEN_ADAPTERS == (
        "nmap",
        "rustscan",
        "fping",
        "naabu",
        "nping",
        "httpx",
        "sslscan",
        "tlsx",
        "whatweb",
        "hping3",
        "onesixtyone",
        "nbtscan",
        "braa",
    )
    assert all(name in ids for name in E2E_PROVEN_ADAPTERS)
    assert UNPROVEN_ADAPTERS == tuple(
        name for name in ids if name not in E2E_PROVEN_ADAPTERS
    )
    assert len(UNPROVEN_ADAPTERS) == 7


@pytest.mark.parametrize("name", LIVE_ADAPTER_IDS)
def test_adapter_for_returns_named_live_adapter(name: str):
    adapter = adapter_for(name)
    assert adapter.name == name
    assert adapter.file_drop_only is False


def test_plan_adapter_for_is_the_registry():
    assert plan_adapter_for("masscan").name == "masscan"


def test_unknown_adapter_refused():
    with pytest.raises(AdapterError, match="unknown adapter"):
        adapter_for("definitely-not-a-covey-tool")


@pytest.mark.parametrize("name", sorted(FORBIDDEN_LIVE))
def test_forbidden_live_wrappers_refused(name: str):
    with pytest.raises(AdapterError, match="LICENSE-LOCK"):
        adapter_for(name)


@pytest.mark.parametrize("name", sorted(FILE_DROP_IDS))
def test_openvas_class_is_file_drop_only(name: str):
    with pytest.raises(AdapterError, match="file_drop"):
        adapter_for(name)
    stub = file_drop_adapter(name)
    assert isinstance(stub, OpenVASFileDrop)
    assert stub.file_drop_only is True
    with pytest.raises(AdapterError, match="file_drop"):
        stub.pass1_argv("10.0.0.0/30", "out/scan")
    with pytest.raises(AdapterError, match="file_drop"):
        stub.pass2_argv_template("out/scan")
    with pytest.raises(AdapterError, match="file_drop"):
        stub.pass2_argv(["10.0.0.1"], "out/scan")


def test_openvas_live_plan_refused():
    scope = load(signed_scope_dict(adapter="openvas"))
    with pytest.raises(AdapterError, match="file_drop"):
        build_plan(scope)


def test_scope_adapter_masscan_plans_masscan_argv():
    scope = load(signed_scope_dict(adapter="masscan", targets=[{"cidr": "10.42.0.0/30"}]))
    plan = build_plan(scope, out_root="out")
    assert plan.adapter == "masscan"
    assert plan.pass1_workers[0].argv is not None
    assert plan.pass1_workers[0].argv[0] == "masscan"
    assert "10.42.0.0/30" in plan.pass1_workers[0].argv
