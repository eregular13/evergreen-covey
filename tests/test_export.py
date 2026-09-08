from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from covey.adapters.nmap import parse_gnmap_services, parse_nmap_xml_services
from covey.errors import ExportError
from covey.export import export_pack
from covey.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


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
