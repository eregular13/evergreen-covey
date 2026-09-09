from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.braa import BraaAdapter, SYS_DESCR, SYS_NAME, parse_braa_live_hosts
from covey.errors import AdapterError


def test_pass1_is_per_host_sysdescr_with_default_port():
    argv = BraaAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "braa"
    assert argv[1:] == [
        f"public@10.42.0.1:{BraaAdapter.default_pass2_ports}:{SYS_DESCR}",
        f"public@10.42.0.2:{BraaAdapter.default_pass2_ports}:{SYS_DESCR}",
    ]


def test_pass2_is_braa_only_against_hosts():
    argv = BraaAdapter().pass2_argv(
        ["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan"
    )
    assert argv[0] == "braa"
    assert argv[1:] == [
        f"public@127.0.0.1:{BraaAdapter.default_pass2_ports}:{SYS_DESCR}",
        f"public@127.0.0.1:{BraaAdapter.default_pass2_ports}:{SYS_NAME}",
        f"public@127.0.0.5:{BraaAdapter.default_pass2_ports}:{SYS_DESCR}",
        f"public@127.0.0.5:{BraaAdapter.default_pass2_ports}:{SYS_NAME}",
    ]


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        BraaAdapter().pass2_argv([], "out/scan")


def test_parse_oid_lines_ignores_dispatch_errors():
    text = "\n".join(
        [
            "127.0.0.1: Message cannot be dispatched!",
            "10.9.8.7:.1.3.6.1.2.1.1.1.0:Linux",
            "10.9.8.8:.1.3.6.1.2.1.1.1.0:Cisco",
            "127.0.0.5:20ms:sysDescr:covey-snmp-lab",
            "8.8.8.8:20ms:sysDescr:Error: timeout",
        ]
    )
    assert parse_braa_live_hosts(text) == [
        "10.9.8.7",
        "10.9.8.8",
        "127.0.0.5",
    ]


def test_parse_timeout_and_dispatch_are_not_live():
    assert parse_braa_live_hosts("127.0.0.1: Message cannot be dispatched!\n") == []
    assert parse_braa_live_hosts("") == []


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "127.0.0.5:20ms:sysDescr:covey-snmp-lab\n",
        encoding="utf-8",
    )
    assert BraaAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = BraaAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert "public@127.0.0.1:18080:" in p1[1]
    assert all(":18080:" in token for token in p2[1:])
