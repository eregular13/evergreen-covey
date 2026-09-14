from __future__ import annotations

import sys

import pytest

from covey.errors import RunnerError
from covey.runner import ensure_nmap


def test_windows_prove_install_needs_byo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        "covey.runner.resolve_nmap",
        lambda: (_ for _ in ()).throw(RunnerError("nmap not on PATH")),
    )
    with pytest.raises(RunnerError, match="need BYO binary \\+ SCOPE"):
        ensure_nmap(install_if_missing=True)
