from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.httpx import HttpxAdapter, parse_httpx_live_hosts
from covey.errors import AdapterError


def test_pass1_is_silent_list_with_scope_ports():
    argv = HttpxAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "httpx"
    assert "-silent" in argv
    assert "-l" in argv
    assert argv[argv.index("-l") + 1] == "shards/p1-s00/scan.hosts"
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == HttpxAdapter.default_pass2_ports
    assert argv[argv.index("-o") + 1] == "shards/p1-s00/scan.txt"


def test_pass1_stages_tile_hosts_file():
    files = HttpxAdapter().stage_files("pass1", "10.42.0.0/30", "shards/p1-s00/scan")
    assert files["shards/p1-s00/scan.hosts"] == "10.42.0.1\n10.42.0.2\n"


def test_pass2_is_httpx_only_against_hosts():
    argv = HttpxAdapter().pass2_argv(["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan")
    assert argv[0] == "httpx"
    assert "-title" in argv
    assert "-status-code" in argv
    assert "-tech-detect" in argv
    assert argv[argv.index("-l") + 1] == "shards/p2-s00/scan.hosts"
    files = HttpxAdapter().stage_files(
        "pass2", "127.0.0.1,127.0.0.5", "shards/p2-s00/scan"
    )
    assert files["shards/p2-s00/scan.hosts"] == "127.0.0.1\n127.0.0.5\n"


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        HttpxAdapter().pass2_argv([], "out/scan")


def test_parse_url_lines_ignores_banners():
    text = "\n".join(
        [
            "Some banner 8.8.8.8 should be ignored",
            "http://127.0.0.1:18080",
            "https://10.9.8.7 [200] [lab]",
            "http://10.9.8.8",
        ]
    )
    assert parse_httpx_live_hosts(text) == ["127.0.0.1", "10.9.8.7", "10.9.8.8"]


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "http://127.0.0.5:18080 [200]\n",
        encoding="utf-8",
    )
    assert HttpxAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = HttpxAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert p1[p1.index("-p") + 1] == "18080"
    assert p2[p2.index("-p") + 1] == "18080"
