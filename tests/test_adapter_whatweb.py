from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.whatweb import WhatwebAdapter, parse_whatweb_live_hosts
from covey.errors import AdapterError


def test_pass1_is_aggression_one_with_scope_port_urls():
    argv = WhatwebAdapter().pass1_argv("10.42.0.0/30", "shards/p1-s00/scan")
    assert argv[0] == "whatweb"
    assert "--log-brief=shards/p1-s00/scan.txt" in argv
    assert "--no-errors" in argv
    assert "--colour=never" in argv
    assert argv[argv.index("-a") + 1] == "1"
    assert "http://10.42.0.1:80" in argv
    assert "http://10.42.0.2:80" in argv


def test_pass2_is_aggression_three_against_live_urls():
    argv = WhatwebAdapter().pass2_argv(["127.0.0.1", "127.0.0.5"], "shards/p2-s00/scan")
    assert argv[0] == "whatweb"
    assert argv[argv.index("-a") + 1] == "3"
    assert "http://127.0.0.1:80" in argv
    assert "http://127.0.0.5:80" in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError, match="empty"):
        WhatwebAdapter().pass2_argv([], "out/scan")


def test_parse_url_lines_ignores_banners():
    text = "\n".join(
        [
            "Some banner 8.8.8.8 should be ignored",
            "http://127.0.0.1:18080 [200 OK] Country[RESERVED][ZZ]",
            "http://10.9.8.7 [200 OK] IP[8.8.8.8]",
            "https://10.9.8.8 [200 OK] Apache[2.4]",
        ]
    )
    assert parse_whatweb_live_hosts(text) == ["127.0.0.1", "10.9.8.7", "10.9.8.8"]


def test_parse_live_hosts_from_stdout(tmp_path: Path):
    (tmp_path / "stdout.log").write_text(
        "http://127.0.0.5:18080 [200 OK] Country[RESERVED][ZZ]\n",
        encoding="utf-8",
    )
    assert WhatwebAdapter().parse_live_hosts(tmp_path) == ["127.0.0.5"]


def test_scope_ports_flow_into_both_passes():
    adapter = WhatwebAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "18080", "host_timeout": None})())
    p1 = adapter.pass1_argv("127.0.0.0/30", "shards/p1-s00/scan")
    p2 = adapter.pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert "http://127.0.0.1:18080" in p1
    assert "http://127.0.0.2:18080" in p1
    assert "http://127.0.0.1:18080" in p2
