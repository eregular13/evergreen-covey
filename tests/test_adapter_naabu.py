from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.naabu import NaabuAdapter, parse_naabu_live_hosts
from covey.errors import AdapterError


def test_pass1_is_connect_scan_with_scope_ports():
    argv = NaabuAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "naabu"
    assert "-host" in argv
    assert argv[argv.index("-host") + 1] == "10.42.0.0/30"
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == NaabuAdapter.default_pass2_ports
    assert "-top-ports" not in argv
    assert "-scan-type" in argv
    assert argv[argv.index("-scan-type") + 1] == "connect"
    assert argv[argv.index("-o") + 1] == "shards/p1-s00/scan.txt"


def test_pass2_is_naabu_only_against_hosts():
    argv = NaabuAdapter().pass2_argv(["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan")
    assert argv[0] == "naabu"
    assert argv[argv.index("-host") + 1] == "127.0.0.1,127.0.0.5"
    assert "10.42.0.0/30" not in argv
    assert "-scan-type" in argv
    assert argv[argv.index("-scan-type") + 1] == "connect"


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        NaabuAdapter().pass2_argv([], "out/scan")


def test_parse_ip_port_lines_ignores_banners():
    text = "\n".join(
        [
            "Some banner 8.8.8.8 should be ignored",
            "127.0.0.1:18080",
            "10.9.8.7:80",
            "10.9.8.7:443",
            "10.9.8.8:22",
        ]
    )
    assert parse_naabu_live_hosts(text) == ["127.0.0.1", "10.9.8.7", "10.9.8.8"]


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text("127.0.0.5:18080\n", encoding="utf-8")
    assert NaabuAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = NaabuAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[p1.index("-p") + 1] == "18080"
    assert p2[p2.index("-p") + 1] == "18080"
    assert "-top-ports" not in p1
