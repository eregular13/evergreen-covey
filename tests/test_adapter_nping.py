from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.nping import NpingAdapter, parse_nping_live_hosts
from covey.errors import AdapterError


def test_pass1_is_tcp_connect_with_scope_ports():
    argv = NpingAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "nping"
    assert "--tcp-connect" in argv
    assert "--tcp" not in argv
    assert "--icmp" not in argv
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == NpingAdapter.default_pass2_ports
    assert "10.42.0.1" in argv
    assert "10.42.0.2" in argv
    assert "10.42.0.0/30" not in argv


def test_pass2_is_nping_only_against_hosts():
    argv = NpingAdapter().pass2_argv(["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan")
    assert argv[0] == "nping"
    assert "--tcp-connect" in argv
    assert "127.0.0.1" in argv
    assert "127.0.0.5" in argv
    assert "10.42.0.0/30" not in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        NpingAdapter().pass2_argv([], "out/scan")


def test_parse_handshake_ignores_refused_and_banners():
    text = "\n".join(
        [
            "Some banner 8.8.8.8 should be ignored",
            "RCVD (0.0013s) Handshake with 127.0.0.1:18080 completed",
            "RCVD (0.2025s) Handshake with 10.9.8.7:80 completed",
            "RCVD (0.4036s) Possible TCP RST received from 10.9.8.9:18080 --> Connection refused",
            "RCVD (0.0010s) ICMP [10.9.8.8 > 10.0.0.1 Echo reply (type=0/code=0) id=1 seq=1] IP [ttl=64]",
        ]
    )
    assert parse_nping_live_hosts(text) == ["127.0.0.1", "10.9.8.7", "10.9.8.8"]


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "RCVD (0.0013s) Handshake with 127.0.0.5:18080 completed\n",
        encoding="utf-8",
    )
    assert NpingAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = NpingAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[p1.index("-p") + 1] == "18080"
    assert p2[p2.index("-p") + 1] == "18080"
    assert "--tcp-connect" in p1
    assert "--tcp-connect" in p2
