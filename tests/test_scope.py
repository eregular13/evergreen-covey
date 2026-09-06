from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from covey.errors import ScopeError
from covey.scope import from_mapping, load, sign_mapping
from tests.helpers import signed_scope_dict


def test_empty_scope_refused():
    with pytest.raises(ScopeError, match="empty"):
        load("")
    with pytest.raises(ScopeError, match="empty"):
        load("   \n")
    with pytest.raises(ScopeError, match="empty"):
        from_mapping({})


def test_unsigned_refused():
    data = signed_scope_dict()
    data.pop("signature")
    with pytest.raises(ScopeError, match="unsigned"):
        from_mapping(data)
    data["signature"] = ""
    with pytest.raises(ScopeError, match="unsigned"):
        from_mapping(data)


def test_consent_signed_false_refused():
    data = signed_scope_dict(consent={"signed": False, "signer": "x", "purpose": "y"})
    with pytest.raises(ScopeError, match="unsigned"):
        from_mapping(data)


def test_bad_signature_refused():
    data = signed_scope_dict()
    data["signature"] = "0" * 64
    with pytest.raises(ScopeError, match="invalid"):
        from_mapping(data)


def test_star_target_refused():
    data = signed_scope_dict(targets=["*"])
    with pytest.raises(ScopeError, match="wide spray"):
        from_mapping(data)


def test_default_route_refused_even_with_allow_wide():
    data = signed_scope_dict(allow_wide=True, targets=[{"cidr": "0.0.0.0/0", "allow_wide": True}])
    with pytest.raises(ScopeError):
        from_mapping(data)


def test_slash8_without_allow_wide_refused():
    data = signed_scope_dict(targets=[{"cidr": "10.0.0.0/8"}])
    with pytest.raises(ScopeError, match="allow_wide"):
        from_mapping(data)


def test_slash16_without_allow_wide_refused():
    data = signed_scope_dict(targets=[{"cidr": "10.0.0.0/16"}])
    with pytest.raises(ScopeError, match="/8–/16"):
        from_mapping(data)


def test_slash16_with_allow_wide_and_listed_parent_accepted():
    data = signed_scope_dict(
        allow_wide=True,
        max_shards=256,
        targets=[{"cidr": "10.0.0.0/16", "allow_wide": True}],
    )
    scope = from_mapping(data)
    assert scope.targets[0].listed == "10.0.0.0/16"
    assert scope.allow_wide is True


def test_window_closed_refused():
    now = datetime.now(timezone.utc)
    past = {
        "start": (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    data = signed_scope_dict(window=past)
    with pytest.raises(ScopeError, match="window closed"):
        load(data)


def test_missing_signer_refused():
    data = signed_scope_dict(consent={"signed": True, "signer": "", "purpose": "x"})
    with pytest.raises(ScopeError, match="signer"):
        from_mapping(data)


def test_valid_signed_demo_loads():
    data = signed_scope_dict()
    scope = load(data)
    assert scope.demo is True
    assert scope.max_workers == 2
    assert len(scope.targets) == 1


def test_sign_mapping_is_stable():
    data = signed_scope_dict()
    again = sign_mapping({k: v for k, v in data.items() if k != "signature"})
    assert again["signature"] == data["signature"]
