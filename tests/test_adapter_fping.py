from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.fping import FpingAdapter
from covey.errors import AdapterError


def test_pass1_is_aqg_range():
    argv = FpingAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "fping"
    assert "-a" in argv
    assert "-q" in argv
    assert "-g" in argv
    assert "10.42.0.0" in argv
    assert "10.42.0.3" in argv


def test_pass2_counts_against_live_hosts():
    argv = FpingAdapter().pass2_argv(["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan")
    assert argv[0] == "fping"
    assert "-a" in argv
    assert "-c" in argv
    assert argv[argv.index("-c") + 1] == "3"
    assert "127.0.0.1" in argv
    assert "127.0.0.5" in argv
    assert "10.42.0.0/30" not in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        FpingAdapter().pass2_argv([], "out/scan")


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text("127.0.0.1\n127.0.0.5\n", encoding="utf-8")
    assert FpingAdapter().parse_live_hosts(tmp_path) == ["127.0.0.1", "127.0.0.5"]
