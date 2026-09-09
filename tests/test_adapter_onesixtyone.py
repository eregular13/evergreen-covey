from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.onesixtyone import (
    OnesixtyoneAdapter,
    parse_onesixtyone_live_hosts,
)
from covey.errors import AdapterError


def test_pass1_is_hosts_file_with_scope_port():
    argv = OnesixtyoneAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "onesixtyone"
    assert argv[argv.index("-c") + 1] == "shards/p1-s00/scan.comm"
    assert argv[argv.index("-i") + 1] == "shards/p1-s00/scan.hosts"
    assert argv[argv.index("-o") + 1] == "shards/p1-s00/scan.txt"
    assert argv[argv.index("-p") + 1] == OnesixtyoneAdapter.default_pass2_ports


def test_pass1_stages_tile_hosts_and_communities():
    files = OnesixtyoneAdapter().stage_files("pass1", "10.42.0.0/30", "shards/p1-s00/scan")
    assert files["shards/p1-s00/scan.hosts"] == "10.42.0.1\n10.42.0.2\n"
    assert files["shards/p1-s00/scan.comm"] == "public\nprivate\n"


def test_pass2_is_onesixtyone_only_against_hosts():
    argv = OnesixtyoneAdapter().pass2_argv(
        ["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan"
    )
    assert argv[0] == "onesixtyone"
    assert argv[argv.index("-i") + 1] == "shards/p2-s00/scan.hosts"
    files = OnesixtyoneAdapter().stage_files(
        "pass2", "127.0.0.1,127.0.0.5", "shards/p2-s00/scan"
    )
    assert files["shards/p2-s00/scan.hosts"] == "127.0.0.1\n127.0.0.5\n"
    assert "community" in files["shards/p2-s00/scan.comm"]


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        OnesixtyoneAdapter().pass2_argv([], "out/scan")


def test_parse_community_lines_ignores_echo_and_sidecars():
    text = "\n".join(
        [
            "Scanning 2 hosts, 2 communities",
            "127.0.0.1",
            "127.0.0.1 Unable to decode SNMP packet: PDU type not RESPONSE (0xa2)",
            "10.9.8.7 [public] Linux",
            "10.9.8.8 [private] Router",
            "8.8.8.8 [public] Unable to decode SNMP packet: wrong header",
            "127.0.0.5 [public] covey-snmp-lab",
        ]
    )
    assert parse_onesixtyone_live_hosts(text) == [
        "10.9.8.7",
        "10.9.8.8",
        "127.0.0.5",
    ]


def test_parse_hosts_sidecar_is_not_live():
    assert parse_onesixtyone_live_hosts("127.0.0.1\n127.0.0.5\n") == []


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "127.0.0.5 [public] covey-snmp-lab\n",
        encoding="utf-8",
    )
    assert OnesixtyoneAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = OnesixtyoneAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[p1.index("-p") + 1] == "18080"
    assert p2[p2.index("-p") + 1] == "18080"
