from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from covey.scope import sign_mapping


def signed_scope_dict(**overrides) -> dict:
    now = datetime.now(timezone.utc)
    data: dict = {
        "version": 1,
        "demo": True,
        "consent": {
            "signed": True,
            "signer": "unit-test",
            "purpose": "covey unit test",
        },
        "window": {
            "start": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "adapter": "nmap",
        "max_workers": 2,
        "allow_wide": False,
        "tile": {"default_prefix": 24, "small_prefix": 28},
        "targets": [{"cidr": "10.42.0.0/28"}],
    }
    for key, value in overrides.items():
        if key in {"consent", "window", "tile"} and isinstance(value, dict):
            merged = dict(data.get(key) or {})
            merged.update(value)
            data[key] = merged
        else:
            data[key] = value
    return sign_mapping(deepcopy(data))


def write_scope(path: Path, **overrides) -> Path:
    data = signed_scope_dict(**overrides)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path
