from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.sslscan import SslscanAdapter, parse_sslscan_live_hosts
from covey.errors import AdapterError


def test_pass1_is_first_host_with_scope_port():
    argv = SslscanAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "sslscan"
    assert "--xml=shards/p1-s00/scan.xml" in argv
    assert "--no-colour" in argv
    assert argv[-1] == f"10.42.0.1:{SslscanAdapter.default_pass2_ports}"
    assert "10.42.0.2" not in argv


def test_pass2_is_sslscan_only_against_first_host():
    argv = SslscanAdapter().pass2_argv(["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan")
    assert argv[0] == "sslscan"
    assert "--show-certificate" in argv
    assert argv[argv.index("--no-colour") + 1] == (
        f"127.0.0.1:{SslscanAdapter.default_pass2_ports}"
    )
    assert "127.0.0.5" in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        SslscanAdapter().pass2_argv([], "out/scan")


def test_parse_connected_to_ignores_error_and_banners():
    text = "\n".join(
        [
            "Some banner 8.8.8.8 should be ignored",
            "ERROR: Could not open a connection to host 10.9.8.9 (10.9.8.9) on port 443.",
            "Connected to 127.0.0.1",
            "Testing SSL server 127.0.0.1 on port 18080 using SNI name 127.0.0.1",
            ' <ssltest host="10.9.8.7" sniname="10.9.8.7" port="443">',
            "Connected to 10.9.8.8",
        ]
    )
    assert parse_sslscan_live_hosts(text) == ["127.0.0.1", "10.9.8.8", "10.9.8.7"]


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "Connected to 127.0.0.5\nTesting SSL server 127.0.0.5 on port 18080\n",
        encoding="utf-8",
    )
    assert SslscanAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = SslscanAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[-1] == "127.0.0.1:18080"
    assert p2[-1] == "127.0.0.1:18080"
