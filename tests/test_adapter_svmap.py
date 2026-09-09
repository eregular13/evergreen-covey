from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.svmap import SvmapAdapter, parse_svmap_live_hosts
from covey.errors import AdapterError


def test_pass1_is_options_on_tile_with_default_port():
    argv = SvmapAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "svmap"
    assert argv[argv.index("-p") + 1] == "5060"
    assert argv[argv.index("-P") + 1] == "0"
    assert argv[-1] == "10.42.0.0/30"
    assert "-o" not in argv
    assert "--fp" not in argv


def test_pass2_rescans_live_hosts():
    argv = SvmapAdapter().pass2_argv(
        ["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan"
    )
    assert argv[0] == "svmap"
    assert argv[argv.index("-p") + 1] == "5060"
    assert argv[argv.index("-P") + 1] == "0"
    assert argv[-2:] == ["127.0.0.1", "127.0.0.5"]
    assert "-o" not in argv
    assert "--fp" not in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        SvmapAdapter().pass2_argv([], "out/scan")


def test_parse_sip_device_table_ignores_unknown_and_banners():
    text = "\n".join(
        [
            "WARNING:root:found nothing",
            "+-----------------+---------------+",
            "| SIP Device      | User Agent    |",
            "+=================+===============+",
            "| 127.0.0.1:18080 | unknown       |",
            "| 10.9.8.7:5060   | Asterisk PBX  |",
            "| 10.9.8.8:18080  | covey-sip-lab |",
            "| 8.8.8.8:5060    | unknown       |",
            "Some banner 1.1.1.1 should be ignored",
            "+-----------------+---------------+",
        ]
    )
    assert parse_svmap_live_hosts(text) == ["10.9.8.7", "10.9.8.8"]


def test_parse_echo_and_unknown_are_not_live():
    assert parse_svmap_live_hosts("WARNING:root:found nothing\n") == []
    assert (
        parse_svmap_live_hosts(
            "| 127.0.0.1:18080 | unknown |\n"
        )
        == []
    )
    assert parse_svmap_live_hosts("") == []


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "| 127.0.0.5:18080 | covey-sip-lab |\n",
        encoding="utf-8",
    )
    assert SvmapAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = SvmapAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[p1.index("-p") + 1] == "18080"
    assert p2[p2.index("-p") + 1] == "18080"
    assert p1[p1.index("-P") + 1] == "0"
    assert p2[p2.index("-P") + 1] == "0"
