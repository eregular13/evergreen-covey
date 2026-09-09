from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from covey.adapters.nmap import parse_gnmap_services, parse_nmap_xml_services
from covey.adapters.registry import E2E_PROVEN_ADAPTERS
from covey.errors import ExportError
from covey.export import export_pack
from covey.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
ADAPTER_FIXTURES = FIXTURES / "adapters"

# stdout.log-class e2e-proven adapters. nmap is XML/gnmap (see _seed_run).
STDOUT_FIXTURES: dict[str, str] = {
    "rustscan": "rustscan.txt",
    "fping": "fping.txt",
    "naabu": "naabu.txt",
    "nping": "nping.txt",
    "httpx": "httpx.txt",
    "sslscan": "sslscan.txt",
    "tlsx": "tlsx.txt",
    "whatweb": "whatweb.txt",
    "hping3": "hping3.txt",
    "onesixtyone": "onesixtyone.txt",
    "nbtscan": "nbtscan.txt",
    "braa": "braa.txt",
    "ike-scan": "ike-scan.txt",
    "svmap": "svmap.txt",
    "unicornscan": "unicornscan.txt",
}


def _seed_run(tmp_path: Path) -> Path:
    shards = tmp_path / "shards"
    p1 = shards / "p1-s00"
    p2 = shards / "p2-s00"
    p1.mkdir(parents=True)
    p2.mkdir(parents=True)
    (p1 / "scan.xml").write_text(
        (FIXTURES / "scan_up.xml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (p1 / "live_hosts.json").write_text(
        json.dumps(["127.0.0.1", "127.0.0.3"]) + "\n", encoding="utf-8"
    )
    (p2 / "scan.xml").write_text(
        (FIXTURES / "scan_open.xml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (p2 / "scan.gnmap").write_text(
        (FIXTURES / "scan_open.gnmap").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "plan.json").write_text(
        json.dumps(
            {
                "adapter": "nmap",
                "created_at": "2026-09-08T00:00:00+00:00",
                "signer": "prove-lab",
                "purpose": "evergreen-covey loopback prove",
                "deepen": {"ports": "22"},
                "shards": ["127.0.0.0/30"],
                "workers": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "run_report.json").write_text(
        json.dumps(
            {
                "ok": True,
                "exec": "/usr/bin/nmap",
                "max_workers": 2,
                "pass1": [
                    {
                        "id": "p1-s00",
                        "shard_id": "s00",
                        "artifact_dir": str(p1),
                        "live_hosts": ["127.0.0.1", "127.0.0.3"],
                        "skipped": False,
                    }
                ],
                "pass2": [
                    {
                        "id": "p2-s00",
                        "shard_id": "s00",
                        "artifact_dir": str(p2),
                        "live_hosts": [],
                        "skipped": False,
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return tmp_path


def _seed_stdout_run(tmp_path: Path, adapter: str, fixture_name: str) -> Path:
    shards = tmp_path / "shards"
    p1 = shards / "p1-s00"
    p1.mkdir(parents=True)
    stdout = (ADAPTER_FIXTURES / fixture_name).read_text(encoding="utf-8")
    (p1 / "stdout.log").write_text(stdout, encoding="utf-8")
    (tmp_path / "plan.json").write_text(
        json.dumps(
            {
                "adapter": adapter,
                "created_at": "2026-09-08T00:00:00+00:00",
                "signer": "prove-lab",
                "purpose": f"evergreen-covey {adapter} export",
                "shards": ["127.0.0.0/30"],
                "workers": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "run_report.json").write_text(
        json.dumps(
            {
                "ok": True,
                "exec": adapter,
                "max_workers": 1,
                "pass1": [
                    {
                        "id": "p1-s00",
                        "shard_id": "s00",
                        "artifact_dir": str(p1),
                        "live_hosts": [],
                        "skipped": False,
                    }
                ],
                "pass2": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return tmp_path


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def test_parse_open_services_ignores_closed():
    xml = parse_nmap_xml_services(FIXTURES / "scan_open.xml")
    assert xml == [
        {
            "address": "127.0.0.1",
            "protocol": "tcp",
            "port": "22",
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
        }
    ]
    gnmap = parse_gnmap_services(FIXTURES / "scan_open.gnmap")
    assert gnmap[0]["port"] == "22"
    assert gnmap[0]["state"] == "open"
    assert all(row["port"] != "80" for row in gnmap)


def test_export_writes_pack_layout(tmp_path: Path):
    run = _seed_run(tmp_path)
    summary = export_pack(run)
    pack = Path(summary["pack"])
    assert pack == run / "pack_drop"
    for name in (
        "meta.json",
        "assets.jsonl",
        "findings.jsonl",
        "README_EXPORT.md",
    ):
        assert (pack / name).is_file()
    assert (pack / "in" / "nmap").is_dir()
    assert (pack / "evidence" / "p2-s00.xml").is_file()
    assert list((pack / "in" / "nmap").glob("*.xml"))

    meta = json.loads((pack / "meta.json").read_text(encoding="utf-8"))
    assert meta["schema"] == "evergreen.pack_drop.v1"
    assert meta["adapter"] == "nmap"
    assert meta["scope"]["signer"] == "prove-lab"
    assert meta["scope"]["purpose"] == "evergreen-covey loopback prove"
    assert "signature" not in meta["scope"]
    assert meta["honesty"]["surface_map"] is True
    assert meta["honesty"]["honeypot_validated"] is False
    assert meta["honesty"]["control_operating_effectiveness"] is False
    assert "surface map" in meta["honesty"]["note"]
    assert meta["ingest"]["mode"] == "file_drop"
    assert meta["ingest"]["riskready_post"] is False
    assert meta["deepen"]["ports"] == "22"
    assert meta["versions"]["covey"]
    assert "nmap" in (meta["versions"]["tool"] or "").lower() or meta["versions"]["tool"]

    readme = (pack / "README_EXPORT.md").read_text(encoding="utf-8")
    assert "file_drop" in readme
    assert "RiskReady" in readme
    assert "surface map" in readme
    assert "honeypot validated" in readme
    assert "operating effectiveness" in readme

    assets = [
        json.loads(line)
        for line in (pack / "assets.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    hosts = [row for row in assets if row["kind"] == "host"]
    services = [row for row in assets if row["kind"] == "service"]
    assert {row["address"] for row in hosts} >= {"127.0.0.1", "127.0.0.3"}
    assert any(row["port"] == 22 and row["state"] == "open" for row in services)

    findings = [
        json.loads(line)
        for line in (pack / "findings.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert findings
    assert all(row["claim"] == "open_port_observed" for row in findings)
    assert all(row["severity"] == "info" for row in findings)
    assert all("control_failure" in row["not_claimed"] for row in findings)
    assert all(row.get("port") == 22 for row in findings)


def test_export_rustscan_stdout_writes_hosts_and_services(tmp_path: Path):
    run = _seed_stdout_run(tmp_path, "rustscan", "rustscan.txt")
    summary = export_pack(run)
    pack = Path(summary["pack"])
    meta = json.loads((pack / "meta.json").read_text(encoding="utf-8"))
    assert meta["adapter"] == "rustscan"
    assert meta["honesty"]["surface_map"] is True
    assert meta["honesty"]["honeypot_validated"] is False
    assert meta["honesty"]["control_operating_effectiveness"] is False
    assert meta["ingest"]["riskready_post"] is False
    assets = _read_jsonl(pack / "assets.jsonl")
    hosts = {row["address"] for row in assets if row["kind"] == "host"}
    services = [row for row in assets if row["kind"] == "service"]
    assert hosts == {"10.9.8.7", "10.9.8.8"}
    assert {(row["address"], row["port"]) for row in services} == {
        ("10.9.8.7", 80),
        ("10.9.8.7", 443),
        ("10.9.8.8", 22),
    }
    assert all(row["state"] == "open" for row in services)
    findings = _read_jsonl(pack / "findings.jsonl")
    assert findings
    assert all(row["claim"] == "open_port_observed" for row in findings)
    assert all(row["severity"] == "info" for row in findings)
    assert all("vulnerability" in row["not_claimed"] for row in findings)
    assert all("control_operating_effectiveness" in row["not_claimed"] for row in findings)


def test_export_httpx_stdout_writes_hosts_and_https_services(tmp_path: Path):
    run = _seed_stdout_run(tmp_path, "httpx", "httpx.txt")
    summary = export_pack(run)
    pack = Path(summary["pack"])
    assets = _read_jsonl(pack / "assets.jsonl")
    hosts = {row["address"] for row in assets if row["kind"] == "host"}
    services = [row for row in assets if row["kind"] == "service"]
    assert hosts == {"10.9.8.7", "10.9.8.8"}
    assert {(row["address"], row["port"], row["service"]) for row in services} == {
        ("10.9.8.7", 443, "https"),
        ("10.9.8.8", 443, "https"),
    }
    findings = _read_jsonl(pack / "findings.jsonl")
    assert all(row["claim"] == "open_port_observed" for row in findings)
    assert all(row.get("port") == 443 for row in findings)


def test_export_unicornscan_stdout_writes_tcp_open_only(tmp_path: Path):
    run = _seed_stdout_run(tmp_path, "unicornscan", "unicornscan.txt")
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "\n".join(
            [
                "TCP closed 10.9.8.9:80  ttl 64",
                "TCP open 10.9.8.7:80  ttl 64",
                "TCP open         unknown[18080]		from 127.0.0.1  ttl 127",
                "TCP open 10.9.8.8:443  ttl 64",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    summary = export_pack(run)
    pack = Path(summary["pack"])
    assets = _read_jsonl(pack / "assets.jsonl")
    hosts = {row["address"] for row in assets if row["kind"] == "host"}
    services = [row for row in assets if row["kind"] == "service"]
    assert hosts == {"10.9.8.7", "127.0.0.1", "10.9.8.8"}
    assert {(row["address"], row["port"]) for row in services} == {
        ("10.9.8.7", 80),
        ("127.0.0.1", 18080),
        ("10.9.8.8", 443),
    }
    assert all(row["protocol"] == "tcp" for row in services)
    assert "10.9.8.9" not in hosts


def test_stdout_fixtures_cover_non_nmap_e2e_proven():
    assert set(STDOUT_FIXTURES) == set(E2E_PROVEN_ADAPTERS) - {"nmap"}


@pytest.mark.parametrize("adapter", E2E_PROVEN_ADAPTERS)
def test_export_normalizes_all_e2e_proven_adapters(tmp_path: Path, adapter: str):
    if adapter == "nmap":
        run = _seed_run(tmp_path)
    else:
        run = _seed_stdout_run(tmp_path, adapter, STDOUT_FIXTURES[adapter])
    summary = export_pack(run)
    pack = Path(summary["pack"])
    meta = json.loads((pack / "meta.json").read_text(encoding="utf-8"))
    assert meta["adapter"] == adapter
    assert meta["honesty"]["surface_map"] is True
    assert meta["honesty"]["control_operating_effectiveness"] is False
    assert "vulnerability" not in json.dumps(meta["honesty"])
    assets = _read_jsonl(pack / "assets.jsonl")
    hosts = [row for row in assets if row["kind"] == "host"]
    assert hosts, f"{adapter} export must write at least one host"
    findings = _read_jsonl(pack / "findings.jsonl")
    assert all(row["claim"] == "open_port_observed" for row in findings)
    assert all("vulnerability" in row["not_claimed"] for row in findings)


def test_export_no_findings_without_open_ports(tmp_path: Path):
    run = tmp_path / "run"
    shard = run / "shards" / "p1-s00"
    shard.mkdir(parents=True)
    (shard / "scan.xml").write_text(
        (FIXTURES / "scan_up.xml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (run / "plan.json").write_text(
        json.dumps({"adapter": "nmap", "signer": "x", "purpose": "y", "shards": []})
        + "\n",
        encoding="utf-8",
    )
    (run / "run_report.json").write_text(
        json.dumps(
            {
                "ok": True,
                "exec": "nmap",
                "pass1": [
                    {
                        "artifact_dir": str(shard),
                        "live_hosts": ["127.0.0.1"],
                    }
                ],
                "pass2": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    summary = export_pack(run)
    findings = (Path(summary["pack"]) / "findings.jsonl").read_text(encoding="utf-8")
    assert findings == ""


def test_export_refuses_empty_out(tmp_path: Path):
    with pytest.raises(ExportError, match="no Covey run artifacts"):
        export_pack(tmp_path)


def test_cli_export(tmp_path: Path):
    run = _seed_run(tmp_path)
    assert main(["export", "--out", str(run)]) == 0
    assert (run / "pack_drop" / "meta.json").is_file()


def test_evidence_matrix_covers_required_lanes():
    data = yaml.safe_load(Path("docs/evidence_matrix.yaml").read_text(encoding="utf-8"))
    ids = [row["id"] for row in data["lanes"]]
    assert ids == [
        "identity_idp",
        "mdm_endpoint",
        "cloud_saas",
        "email_dns",
        "covey_surface",
        "vm_file_drop",
        "honeypot_fleet",
        "interview_docs",
        "logging_backup_ir",
    ]
    assert data["honesty"]["riskready_post"] is False
    covey = next(row for row in data["lanes"] if row["id"] == "covey_surface")
    assert "open_port_observed" in covey["sor"]["finding"]
    assert covey["sor"]["poam"] == []


def test_honeypot_schemas_exist():
    event = json.loads(Path("schemas/honeypot_event.v1.json").read_text(encoding="utf-8"))
    session = json.loads(
        Path("schemas/session_summary.v1.json").read_text(encoding="utf-8")
    )
    assert event["title"] == "honeypot_event.v1"
    assert session["title"] == "session_summary.v1"
    assert "event_id" in event["required"]
    assert "session_id" in session["required"]
    assert Path("docs/honeypot_pack_drop.md").is_file()
