from __future__ import annotations

import pytest

from covey.errors import ScopeError
from covey.plan import build_plan
from covey.scope import from_mapping, load
from tests.helpers import signed_scope_dict


def test_host_target_loads_without_cidr_expansion():
    data = signed_scope_dict(targets=[{"host": "web.lab.example"}])
    scope = from_mapping(data)
    assert len(scope.targets) == 1
    assert scope.targets[0].kind == "host"
    assert scope.targets[0].value == "web.lab.example"
    assert scope.targets[0].listed == "web.lab.example"


def test_url_target_http_only():
    data = signed_scope_dict(targets=[{"url": "http://127.0.0.1:18081/"}])
    scope = from_mapping(data)
    assert scope.targets[0].kind == "url"
    assert scope.targets[0].value == "http://127.0.0.1:18081/"


def test_domain_target_loads():
    data = signed_scope_dict(targets=[{"domain": "lab.example"}])
    scope = from_mapping(data)
    assert scope.targets[0].kind == "domain"
    assert scope.targets[0].value == "lab.example"


def test_file_drop_target_relative_path():
    data = signed_scope_dict(targets=[{"file_drop": "in/nessus/lab.nessus"}])
    scope = from_mapping(data)
    assert scope.targets[0].kind == "file_drop"
    assert scope.targets[0].value == "in/nessus/lab.nessus"


def test_file_url_refused():
    data = signed_scope_dict(targets=[{"url": "file:///etc/passwd"}])
    with pytest.raises(ScopeError, match="http"):
        from_mapping(data)


def test_wildcard_host_refused():
    data = signed_scope_dict(targets=[{"host": "*"}])
    with pytest.raises(ScopeError, match="wide spray|refused"):
        from_mapping(data)


def test_domain_default_route_refused():
    data = signed_scope_dict(targets=[{"domain": "0.0.0.0/0"}])
    with pytest.raises(ScopeError):
        from_mapping(data)


def test_file_drop_path_traversal_refused():
    data = signed_scope_dict(targets=[{"file_drop": "../secrets.xml"}])
    with pytest.raises(ScopeError, match="traversal|file_drop"):
        from_mapping(data)


def test_mixed_kind_keys_refused():
    data = signed_scope_dict(targets=[{"cidr": "10.42.0.0/28", "host": "web.lab"}])
    with pytest.raises(ScopeError, match="exactly one"):
        from_mapping(data)


def test_string_target_still_cidr():
    data = signed_scope_dict(targets=["10.42.1.0/28"])
    scope = from_mapping(data)
    assert scope.targets[0].kind == "cidr"
    assert scope.targets[0].cidr == "10.42.1.0/28"


def test_host_plan_is_one_shard_not_a_slash28():
    scope = load(signed_scope_dict(targets=[{"host": "web.lab.example"}]))
    plan = build_plan(scope, out_root="out")
    assert plan.shards == ["web.lab.example"]
    assert "web.lab.example" in plan.pass1_workers[0].argv


def test_url_plan_passes_url_to_argv():
    scope = load(signed_scope_dict(targets=[{"url": "https://web.lab.example"}]))
    plan = build_plan(scope, out_root="out")
    assert plan.shards == ["https://web.lab.example"]
