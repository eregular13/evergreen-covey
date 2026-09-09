from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.unicornscan import (
    LOOPBACK_SOURCE,
    UnicornscanAdapter,
    parse_unicornscan_live_hosts,
)
from covey.errors import AdapterError


def test_pass1_is_tcp_syn_on_tile_with_default_ports():
    argv = UnicornscanAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "unicornscan"
    assert argv[argv.index("-mT")] == "-mT"
    assert argv[-1] == f"10.42.0.0/30:{UnicornscanAdapter.default_pass2_ports}"
    assert "-i" not in argv
    assert "-s" not in argv


def test_pass1_loopback_uses_lo_and_non_tile_source():
    argv = UnicornscanAdapter().pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "unicornscan"
    assert argv[argv.index("-mT")] == "-mT"
    assert argv[argv.index("-i") + 1] == "lo"
    assert argv[argv.index("-s") + 1] == LOOPBACK_SOURCE
    assert LOOPBACK_SOURCE.startswith("127.")
    assert LOOPBACK_SOURCE not in {"127.0.0.1", "127.0.0.2"}
    assert argv[-1].startswith("127.0.0.0/30:")


def test_pass2_rescans_live_hosts():
    argv = UnicornscanAdapter().pass2_argv(
        ["10.42.0.1", "10.42.0.2"], "shards/p2-s00/scan"
    )
    assert argv[0] == "unicornscan"
    assert "-mT" in argv
    assert argv[-2:] == [
        f"10.42.0.1:{UnicornscanAdapter.default_pass2_ports}",
        f"10.42.0.2:{UnicornscanAdapter.default_pass2_ports}",
    ]
    assert "-i" not in argv


def test_pass2_loopback_hosts_use_lo_source():
    argv = UnicornscanAdapter().pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert argv[argv.index("-i") + 1] == "lo"
    assert argv[argv.index("-s") + 1] == LOOPBACK_SOURCE
    assert argv[-1].startswith("127.0.0.1:")


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        UnicornscanAdapter().pass2_argv([], "out/scan")


def test_parse_tcp_open_ignores_closed_and_banners():
    text = "\n".join(
        [
            "Some banner 8.8.8.8 should be ignored",
            "TCP closed 127.0.0.2:18080  ttl 127",
            "TCP open 10.9.8.7:80  ttl 64",
            "TCP open         unknown[18080]		from 127.0.0.1  ttl 127",
            "TCP open 10.9.8.8:443  ttl 64",
            "TCP closed	         unknown[18080]		from 10.9.8.9  ttl 127",
        ]
    )
    assert parse_unicornscan_live_hosts(text) == ["10.9.8.7", "127.0.0.1", "10.9.8.8"]


def test_parse_closed_and_empty_are_not_live():
    assert parse_unicornscan_live_hosts("TCP closed 127.0.0.1:18080  ttl 127\n") == []
    assert parse_unicornscan_live_hosts("") == []


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "TCP open         unknown[18080]		from 127.0.0.5  ttl 127\n",
        encoding="utf-8",
    )
    assert UnicornscanAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = UnicornscanAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[-1] == "127.0.0.0/30:18080"
    assert p2[-1] == "127.0.0.1:18080"
    assert p1[p1.index("-i") + 1] == "lo"
    assert p2[p2.index("-s") + 1] == LOOPBACK_SOURCE
