from __future__ import annotations

from pathlib import Path

import pytest

from covey.cli import main
from covey.errors import ExportError, GateError
from covey.export import export_pack
from covey.grc import (
    CISO_ASSET_HEADER,
    CISO_EVIDENCE_HEADER,
    push_ciso_assets_evidences,
    write_ciso,
)
from tests.test_export import _seed_run, _seed_stdout_run


def test_export_help_lists_targets() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["export", "--help"])
    assert ei.value.code == 0


def test_export_riskready_wrap_dead(tmp_path: Path) -> None:
    assert main(["export", "--out", str(tmp_path), "--target", "riskready"]) == 2
    with pytest.raises(ExportError, match="WRAP_DEAD"):
        export_pack(tmp_path, target="riskready")


def test_export_all_writes_ciso_opengrc_probo(tmp_path: Path) -> None:
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    summary = export_pack(run, target="all")
    pack = Path(summary["pack"])
    assets = (pack / "ciso-assistant" / "assets.csv").read_text(encoding="utf-8")
    findings = (pack / "ciso-assistant" / "findings.csv").read_text(encoding="utf-8")
    poam = (pack / "ciso-assistant" / "poam.csv").read_text(encoding="utf-8")
    assert "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets" in assets
    assert "ref_id,name,description,severity,status,filtering_labels" in findings
    assert "Cleartext HTTP" in findings
    assert "Cleartext HTTP" in poam
    assert "CPG 2.W" in poam
    og = (pack / "opengrc" / "assets.csv").read_text(encoding="utf-8")
    assert "Asset Tag,Name,Hostname,IP Address,Asset Type,Status,Notes,Active" in og
    risks = (pack / "opengrc" / "risks.csv").read_text(encoding="utf-8")
    assert "Code,Name,Description" in risks
    assert "Cleartext HTTP" in risks
    plan = (pack / "probo" / "findings_plan.json").read_text(encoding="utf-8")
    assert "createFinding" in plan
    assert "addFinding" not in plan
    assert "No createRisk" in plan
    assert "Dual-gate live not implemented" not in plan
    assert "GATE_PROBO" in plan
    assert summary["http"] is False


def test_httpx_https_fixture_does_not_invent_hsts(tmp_path: Path) -> None:
    run = _seed_stdout_run(tmp_path, "httpx", "httpx.txt")
    summary = export_pack(run, target="pack_drop")
    pack = Path(summary["pack"])
    text = (pack / "findings.jsonl").read_text(encoding="utf-8")
    assert "Missing HSTS" not in text
    assert "open_port_observed" in text


def test_mock_sink_rejects_wrong_headers() -> None:
    assert CISO_ASSET_HEADER[0] == "ref_id"
    bad = ["id", "title"]
    assert bad != CISO_ASSET_HEADER
    assert bad != CISO_EVIDENCE_HEADER


def test_missing_gate_no_http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[int] = []
    monkeypatch.delenv("CISO_URL", raising=False)
    monkeypatch.delenv("CISO_TOKEN", raising=False)
    with pytest.raises(GateError):
        push_ciso_assets_evidences(
            assets=[{"name": "x", "description": "y"}],
            evidences=[{"name": "e", "description": "d"}],
            cwd=tmp_path,
            poster=lambda *a, **k: called.append(1) or 200,
        )
    assert called == []


def test_no_api_risks_except_refuse() -> None:
    text = (Path(__file__).resolve().parents[1] / "src" / "covey" / "grc.py").read_text(
        encoding="utf-8"
    )
    assert text.count("refused POST /api/risks") >= 1
    assert not any(
        "Request" in line and "/api/risks" in line
        for line in text.splitlines()
    )


def test_export_live_ciso_without_gate_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CISO_URL", raising=False)
    monkeypatch.delenv("CISO_TOKEN", raising=False)
    monkeypatch.delenv("CISO_FINDINGS_ASSESSMENT", raising=False)
    monkeypatch.delenv("COVEY_PUSH_DIR", raising=False)
    _seed_run(tmp_path)
    assert main(["export", "--out", str(tmp_path), "--target", "ciso", "--live"]) == 2


def test_opengrc_mapping_cites_risks_create_body_not_unconfirmed(tmp_path: Path) -> None:
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    summary = export_pack(run, target="opengrc")
    mapping = (Path(summary["pack"]) / "opengrc" / "MAPPING.md").read_text(encoding="utf-8")
    assert "/api/risks" in mapping
    assert "Sanctum" in mapping
    assert "schema unconfirmed" not in mapping.lower()
    assert summary["http"] is False


def test_write_ciso_finding_rows_map_action_to_recommendation(tmp_path: Path) -> None:
    dest = tmp_path / "ciso-assistant"
    result = write_ciso(
        dest,
        assets=[{"address": "172.26.0.2", "kind": "host", "adapter": "nmap"}],
        findings=[
            {
                "title": "Cleartext HTTP",
                "name": "Cleartext HTTP",
                "severity": "medium",
                "claim": "misconfig_observed",
                "address": "172.26.0.2",
                "mapped": True,
                "weakness": "Cleartext HTTP",
                "action": "Enforce TLS; redirect HTTP to HTTPS.",
                "honesty": (
                    "surface map ≠ honeypot validated ≠ control operating effectiveness"
                ),
                "cpg": ["CPG 2.W"],
                "csf": ["PR.DS-02"],
            }
        ],
        evidence=[],
    )
    row = result["finding_rows"][0]
    assert row["recommendation"] == "Enforce TLS; redirect HTTP to HTTPS."
    assert "surface map" in row["observation"]
    assert "operating effectiveness" in row["observation"]
    header = (dest / "findings.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header == "ref_id,name,description,severity,status,filtering_labels"
