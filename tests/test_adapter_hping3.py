from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.hping3 import Hping3Adapter, parse_hping3_live_hosts
from covey.errors import AdapterError


def test_pass1_is_icmp_to_first_tile_host():
    argv = Hping3Adapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "hping3"
    assert "--icmp" in argv
    assert argv[argv.index("-c") + 1] == "3"
    assert argv[-1] == "10.42.0.1"
    assert "10.42.0.2" not in argv
    assert "10.42.0.3" not in argv


def test_pass2_is_syn_against_first_live_host():
    argv = Hping3Adapter().pass2_argv(["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan")
    assert argv[0] == "hping3"
    assert "--syn" in argv
    assert argv[argv.index("-p") + 1] == Hping3Adapter.default_pass2_ports
    assert argv[argv.index("-c") + 1] == "2"
    assert "127.0.0.1" in argv
    assert "127.0.0.5" in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        Hping3Adapter().pass2_argv([], "out/scan")


def test_parse_ip_eq_ignores_banner_and_loss():
    text = "\n".join(
        [
            "HPING 8.8.8.8 (eth0 8.8.8.8): icmp mode set, 28 headers + 0 data bytes",
            "len=28 ip=127.0.0.1 ttl=127 id=1 icmp_seq=0 rtt=3.8 ms",
            "len=28 ip=10.9.8.7 ttl=64 id=2 icmp_seq=0 rtt=0.2 ms",
            "len=40 ip=10.9.8.8 ttl=64 DF id=0 sport=80 flags=RA seq=0 win=0 rtt=0.3 ms",
            "--- 8.8.8.8 hping statistic ---",
            "3 packets transmitted, 0 packets received, 100% packet loss",
        ]
    )
    assert parse_hping3_live_hosts(text) == ["127.0.0.1", "10.9.8.7", "10.9.8.8"]


def test_parse_banner_only_is_not_live():
    text = "\n".join(
        [
            "HPING 10.9.8.7 (lo 10.9.8.7): icmp mode set, 28 headers + 0 data bytes",
            "--- 10.9.8.7 hping statistic ---",
            "3 packets transmitted, 0 packets received, 100% packet loss",
        ]
    )
    assert parse_hping3_live_hosts(text) == []


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "len=28 ip=127.0.0.5 ttl=127 id=1 icmp_seq=0 rtt=3.9 ms\n",
        encoding="utf-8",
    )
    assert Hping3Adapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_pass2_syn():
    adapter = Hping3Adapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[-1] == "127.0.0.1"
    assert "--icmp" in p1
    assert p2[p2.index("-p") + 1] == "18080"
    assert "127.0.0.1" in p2
