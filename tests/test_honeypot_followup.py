from __future__ import annotations

import json
from pathlib import Path

from covey.adapters.httpx import HttpxAdapter, parse_httpx_live_hosts
from covey.export import export_pack
from covey.findings import findings_from_httpx_jsonl, map_finding


def test_httpx_pass2_emits_json_not_just_title():
    argv = HttpxAdapter().pass2_argv(["127.0.0.1"], "shards/p2-s00/scan")
    assert "-json" in argv
    assert "-include-response-header" in argv or "-irh" in argv
    assert "-title" in argv
    assert "-H" in argv or "-header" in argv
    header_val = argv[argv.index("-H") + 1] if "-H" in argv else argv[argv.index("-header") + 1]
    assert "text/html" in header_val.lower()
    assert argv[argv.index("-o") + 1].endswith(".jsonl") or argv[argv.index("-o") + 1].endswith(".txt")


def test_httpx_stages_hostname_as_url_when_single_port():
    adapter = HttpxAdapter()
    adapter.apply_deepen(type("D", (), {"ports": "8081", "host_timeout": None})())
    files = adapter.stage_files("pass1", "honeypot", "shards/p1-s00/scan")
    assert files["shards/p1-s00/scan.hosts"] == "http://honeypot:8081\n"


def test_httpx_jsonl_headers_drive_hsts_and_cookie():
    text = json.dumps(
        {
            "url": "http://172.26.0.2:8081",
            "host": "172.26.0.2",
            "port": "8081",
            "scheme": "http",
            "status_code": 200,
            "title": "phpMyAdmin",
            "webserver": "Werkzeug/3.1.8 Python/3.12.14",
            "tech": ["Flask:3.1.8", "Python:3.12.14"],
            "header": {
                "server": "Werkzeug/3.1.8 Python/3.12.14",
                "set_cookie": "session=abc; HttpOnly; Path=/",
                "content_type": "text/html",
            },
        }
    )
    assert parse_httpx_live_hosts(text) == ["172.26.0.2"]
    names = {row["name"] for row in findings_from_httpx_jsonl(text)}
    assert "Cleartext HTTP" in names
    assert "Missing HSTS" in names
    assert "Insecure session cookie" in names
    assert "Server banner disclosure" in names
    assert "Werkzeug/Flask development server exposed" in names
    assert "phpMyAdmin interface exposed" in names


def test_httpx_jsonl_title_drives_phpmyadmin():
    text = json.dumps(
        {
            "url": "http://172.26.0.2:8081",
            "host": "172.26.0.2",
            "scheme": "http",
            "status_code": 200,
            "title": "phpMyAdmin",
            "header": {"content_type": "text/html"},
        }
    )
    names = {row["name"] for row in findings_from_httpx_jsonl(text)}
    assert "phpMyAdmin interface exposed" in names


def test_httpx_jsonl_cpe_only_drives_phpmyadmin():
    text = json.dumps(
        {
            "url": "http://172.26.0.2:8081",
            "host": "172.26.0.2",
            "scheme": "http",
            "status_code": 200,
            "header": {"content_type": "text/html"},
            "cpe": "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.1:*:*:*:*:*:*:*",
        }
    )
    names = {row["name"] for row in findings_from_httpx_jsonl(text)}
    assert "phpMyAdmin interface exposed" in names
    assert "Werkzeug/Flask development server exposed" not in names


def test_werkzeug_catalog_maps():
    mapped = map_finding("Werkzeug/Flask development server exposed", "172.26.0.2", "low")
    assert mapped["mapped"] is True
    assert mapped["weakness"] == "Werkzeug/Flask development server exposed"


def test_export_merges_pipeline_httpx_services(tmp_path: Path):
    shards = tmp_path / "shards"
    nmap = shards / "p1-s00"
    httpx = shards / "pipe01-s00"
    nmap.mkdir(parents=True)
    httpx.mkdir(parents=True)
    (nmap / "live_hosts.json").write_text('["172.26.0.2"]\n', encoding="utf-8")
    (httpx / "stdout.log").write_text(
        "http://172.26.0.2:8081 [404] [Flask:3.1.8]\n", encoding="utf-8"
    )
    (httpx / "argv.json").write_text('["httpx","-silent"]\n', encoding="utf-8")
    (tmp_path / "plan.json").write_text(
        json.dumps(
            {
                "adapter": "nmap",
                "pipeline": ["nmap", "httpx"],
                "created_at": "2026-09-12T00:00:00+00:00",
                "signer": "lab",
                "purpose": "pipeline merge",
                "shards": ["honeypot"],
                "workers": [],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "run_report.json").write_text(
        json.dumps(
            {
                "ok": True,
                "exec": "nmap",
                "max_workers": 1,
                "pass1": [
                    {
                        "id": "p1-s00",
                        "shard_id": "s00",
                        "artifact_dir": str(nmap),
                        "live_hosts": ["172.26.0.2"],
                    }
                ],
                "pass2": [
                    {
                        "id": "pipe01-s00",
                        "shard_id": "s00",
                        "artifact_dir": str(httpx),
                        "live_hosts": ["172.26.0.2"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    summary = export_pack(tmp_path)
    pack = Path(summary["pack"])
    assets = [
        json.loads(line)
        for line in (pack / "assets.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    services = [row for row in assets if row["kind"] == "service"]
    assert any(row.get("port") == 8081 for row in services)
