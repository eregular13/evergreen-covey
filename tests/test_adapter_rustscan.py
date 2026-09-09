from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.rustscan import (
    RustscanAdapter,
    parse_rustscan_live_hosts,
    parse_rustscan_services,
)
from covey.errors import AdapterError


def test_pass1_is_greppable_no_nmap_passthrough():
    argv = RustscanAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "rustscan"
    assert "-a" in argv
    assert argv[argv.index("-a") + 1] == "10.42.0.0/30"
    assert "-g" in argv
    assert "--scripts" in argv
    assert argv[argv.index("--scripts") + 1] == "none"
    assert "--" not in argv
    assert "-p" in argv


def test_pass2_is_rustscan_only_against_hosts():
    argv = RustscanAdapter().pass2_argv(["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan")
    assert argv[0] == "rustscan"
    assert "-g" in argv
    assert "--" not in argv
    assert "127.0.0.1,127.0.0.5" in argv
    assert "10.42.0.0/30" not in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        RustscanAdapter().pass2_argv([], "out/scan")


def test_parse_greppable_and_open_lines():
    text = "\n".join(
        [
            "Some banner 8.8.8.8 should be ignored",
            "127.0.0.1 -> [18080]",
            "Open 10.9.8.7:80",
            "Open 10.9.8.7:443",
            "10.9.8.8 -> [22]",
        ]
    )
    assert parse_rustscan_live_hosts(text) == ["127.0.0.1", "10.9.8.7", "10.9.8.8"]
    services = parse_rustscan_services(text)
    assert {(row["address"], row["port"]) for row in services} == {
        ("127.0.0.1", "18080"),
        ("10.9.8.7", "80"),
        ("10.9.8.7", "443"),
        ("10.9.8.8", "22"),
    }


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text("127.0.0.5 -> [18080]\n", encoding="utf-8")
    assert RustscanAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = RustscanAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[p1.index("-p") + 1] == "18080"
    assert p2[p2.index("-p") + 1] == "18080"
