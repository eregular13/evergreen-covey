from __future__ import annotations

from tests.helpers import signed_scope_dict


def pytest_configure(config) -> None:
    del config


__all__ = ["signed_scope_dict"]
