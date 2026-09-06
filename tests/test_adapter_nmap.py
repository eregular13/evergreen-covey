from __future__ import annotations

from pathlib import Path

import pytest

from covey.adapters.base import materialize_template
from covey.adapters.nmap import NmapAdapter, parse_gnmap_live_hosts, parse_nmap_xml_live_hosts
from covey.errors import AdapterError

FIXTURES = Path(__file__).parent / "fixtures"


def test_pass1_is_discover_only():
    argv = NmapAdapter().pass1_argv("10.42.0.0/30", "out/shards/p1-s00/scan")
    assert argv[0] == "nmap"
    assert "-sn" in argv
    assert "-sV" not in argv
    assert "10.42.0.0/30" in argv
    assert argv[argv.index("-oA") + 1] == "out/shards/p1-s00/scan"


def test_pass2_is_version_against_hosts_not_cidr():
    adapter = NmapAdapter()
    argv = adapter.pass2_argv(["127.0.0.1", "127.0.0.2"], "out/shards/p2-s00/scan")
    assert "-sV" in argv
    assert "-sn" not in argv
    assert "127.0.0.1" in argv
    assert "127.0.0.2" in argv
    assert "10.42.0.0/30" not in argv


def test_pass2_refuses_empty_hosts():
    with pytest.raises(AdapterError):
        NmapAdapter().pass2_argv([], "out/scan")


def test_materialize_hosts_token():
    assert materialize_template(["nmap", "-sV", "{hosts}"], ["127.0.0.1"]) == [
        "nmap",
        "-sV",
        "127.0.0.1",
    ]


def test_parse_xml_live_hosts():
    hosts = parse_nmap_xml_live_hosts(FIXTURES / "scan_up.xml")
    assert hosts == ["127.0.0.1", "127.0.0.3"]


def test_parse_gnmap_live_hosts():
    hosts = parse_gnmap_live_hosts(FIXTURES / "scan_up.gnmap")
    assert hosts == ["127.0.0.1", "10.0.0.9"]


def test_parse_live_hosts_prefers_xml(tmp_path: Path):
    xml = (FIXTURES / "scan_up.xml").read_text(encoding="utf-8")
    (tmp_path / "scan.xml").write_text(xml, encoding="utf-8")
    (tmp_path / "scan.gnmap").write_text("Host: 9.9.9.9 () Status: Up\n", encoding="utf-8")
    assert NmapAdapter().parse_live_hosts(tmp_path) == ["127.0.0.1", "127.0.0.3"]
