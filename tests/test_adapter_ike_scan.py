from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.ike_scan import IkeScanAdapter, parse_ike_scan_live_hosts
from covey.errors import AdapterError


def test_pass1_is_main_mode_on_tile_with_default_port():
    argv = IkeScanAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "ike-scan"
    assert "--sport=0" in argv
    assert "--dport=500" in argv
    assert "--timeout=500" in argv
    assert "--retry=1" in argv
    assert argv[-1] == "10.42.0.0/30"
    assert "--aggressive" not in argv


def test_pass2_is_aggressive_against_hosts():
    argv = IkeScanAdapter().pass2_argv(
        ["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan"
    )
    assert argv[0] == "ike-scan"
    assert "--sport=0" in argv
    assert "--dport=500" in argv
    assert "--aggressive" in argv
    assert "--id=vpn" in argv
    assert argv[-2:] == ["127.0.0.1", "127.0.0.5"]


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        IkeScanAdapter().pass2_argv([], "out/scan")


def test_parse_handshake_ignores_echo_notify_malformed():
    text = "\n".join(
        [
            "Starting ike-scan 1.9.5 with 4 hosts",
            "127.0.0.1	Main Mode Handshake returned HDR=(CKY-R=0000000000000000) (8 transforms)",
            "10.9.8.7	Main Mode Handshake returned HDR=(CKY-R=434f5645594c4142) (8 transforms)",
            "10.9.8.8	Main Mode Handshake returned (HDR: (CKY-I=...))",
            "8.8.8.8	Notify message 14 (NO-PROPOSAL-CHOSEN)",
            "127.0.0.5	Short or malformed ISAKMP packet returned: 28 bytes",
            "127.0.0.9	Aggressive Mode Handshake returned HDR=(CKY-R=434f5645594c4142) (4 transforms)",
            "Ending ike-scan 1.9.5: 4 hosts scanned.  2 returned handshake; 1 returned notify",
        ]
    )
    assert parse_ike_scan_live_hosts(text) == [
        "10.9.8.7",
        "10.9.8.8",
        "127.0.0.9",
    ]


def test_parse_self_echo_and_notify_are_not_live():
    assert (
        parse_ike_scan_live_hosts(
            "127.0.0.1	Main Mode Handshake returned HDR=(CKY-R=0000000000000000)\n"
        )
        == []
    )
    assert parse_ike_scan_live_hosts("127.0.0.1	Notify message 14\n") == []
    assert parse_ike_scan_live_hosts("") == []


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "127.0.0.5	Main Mode Handshake returned HDR=(CKY-R=434f5645594c4142) (8 transforms)\n",
        encoding="utf-8",
    )
    assert IkeScanAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = IkeScanAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert "--dport=18080" in p1
    assert "--dport=18080" in p2
