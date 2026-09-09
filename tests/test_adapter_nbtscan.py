from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.nbtscan import NbtscanAdapter, parse_nbtscan_live_hosts
from covey.errors import AdapterError


def test_pass1_is_script_friendly_cidr():
    argv = NbtscanAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "nbtscan"
    assert argv[argv.index("-s") + 1] == ":"
    assert argv[argv.index("-t") + 1] == "500"
    assert argv[-1] == "10.42.0.0/30"


def test_pass2_is_verbose_against_hosts():
    argv = NbtscanAdapter().pass2_argv(
        ["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan"
    )
    assert argv[0] == "nbtscan"
    assert "-v" in argv
    assert argv[argv.index("-s") + 1] == ":"
    assert "127.0.0.1" in argv
    assert "127.0.0.5" in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        NbtscanAdapter().pass2_argv([], "out/scan")


def test_parse_name_table_ignores_echo_and_banner():
    text = "\n".join(
        [
            "Doing NBT name scan for addresses from 127.0.0.1",
            "127.0.0.1:<unknown>::<unknown>:",
            "10.9.8.7:SERVER:00:UNIQUE",
            "10.9.8.8:WORKSTATION:00:UNIQUE",
            "127.0.0.5:COVEYLAB       :00U",
            "127.0.0.5:MAC:00:11:22:33:44:55",
            "8.8.8.8:<unknown>::<unknown>:",
        ]
    )
    assert parse_nbtscan_live_hosts(text) == [
        "10.9.8.7",
        "10.9.8.8",
        "127.0.0.5",
    ]


def test_parse_echo_and_banner_are_not_live():
    assert parse_nbtscan_live_hosts(
        "Doing NBT name scan for addresses from 127.0.0.1\n"
        "127.0.0.1:<unknown>::<unknown>:\n"
    ) == []


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "127.0.0.5:COVEYLAB       ::<unknown>:00:11:22:33:44:55\n",
        encoding="utf-8",
    )
    assert NbtscanAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]
