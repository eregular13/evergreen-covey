from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from covey.cli import main
from covey.errors import ExportError, GateError
from covey.export import export_pack
from covey.grc import (
    fetch_ciso_finding,
    fetch_probo_finding,
    push_ciso_assets_evidences,
    push_ciso_findings,
    push_probo_findings,
    refuse_opengrc_live,
    refuse_riskready,
)
from tests.test_export import _seed_run


def test_riskready_stays_wrap_dead():
    with pytest.raises(ExportError, match="WRAP_DEAD"):
        refuse_riskready()
    assert main(["export", "--target", "riskready", "--live"]) == 2


def test_ciso_live_without_gate_raises_and_posts_nothing(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CISO_URL", raising=False)
    monkeypatch.delenv("CISO_TOKEN", raising=False)
    posted: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append(url)
        return 201

    with pytest.raises(GateError, match="dual-gate"):
        push_ciso_assets_evidences(
            assets=[{"name": "a", "description": "d", "type": "PR"}],
            evidences=[{"name": "e", "description": "d"}],
            cwd=tmp_path,
            poster=poster,
        )
    assert posted == []


def test_ciso_live_assets_evidences_posts_not_risks(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18080")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return 201

    result = push_ciso_assets_evidences(
        assets=[{"name": "172.26.0.2", "description": "host", "type": "PR"}],
        evidences=[{"name": "scan.xml", "description": "nmap xml"}],
        cwd=tmp_path,
        poster=poster,
    )
    assert result["http"] is True
    urls = [row[0] for row in posted]
    assert any(u.endswith("/assets/") for u in urls)
    assert any(u.endswith("/evidences/") for u in urls)
    assert not any("/api/risks" in u for u in urls)


def test_ciso_assets_post_folder_uuid_and_return_ids(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FOLDER", "22222222-3333-4444-5555-666666666666")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []
    asset_id = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return {"status": 201, "body": {"id": asset_id, "name": "memcached"}}

    result = push_ciso_assets_evidences(
        assets=[{"name": "memcached", "description": "host", "type": "PR"}],
        evidences=[],
        cwd=tmp_path,
        poster=poster,
    )
    url, body = posted[0]
    assert url.endswith("/assets/")
    assert body["folder"] == "22222222-3333-4444-5555-666666666666"
    assert body["name"] == "memcached"
    assert result["asset_ids"] == [asset_id]
    assert "/api/risks" not in url


def test_ciso_evidences_post_folder_uuid_and_return_ids(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FOLDER", "22222222-3333-4444-5555-666666666666")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []
    evidence_id = "dddddddd-eeee-ffff-aaaa-111111111111"

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return {"status": 201, "body": {"id": evidence_id, "name": "p1-s00.xml"}}

    result = push_ciso_assets_evidences(
        assets=[],
        evidences=[{"name": "p1-s00.xml", "description": "nmap xml"}],
        cwd=tmp_path,
        poster=poster,
    )
    url, body = posted[0]
    assert url.endswith("/evidences/")
    assert body["folder"] == "22222222-3333-4444-5555-666666666666"
    assert body["name"] == "p1-s00.xml"
    assert result["evidence_ids"] == [evidence_id]
    assert "/api/risks" not in url


def test_ciso_evidences_400_reuses_get_by_name_id(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FOLDER", "22222222-3333-4444-5555-666666666666")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    existing = "24f319df-a4e1-415f-8f78-1a94075a6461"
    posted: list[str] = []
    got: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        raise urllib.error.HTTPError(url, 400, "Bad Request", None, io.BytesIO(b"{}"))

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        got.append(url)
        return {"count": 1, "results": [{"id": existing, "name": "scan.xml"}]}

    result = push_ciso_assets_evidences(
        assets=[],
        evidences=[{"name": "scan.xml", "description": "nmap xml"}],
        cwd=tmp_path,
        poster=poster,
        getter=getter,
    )
    assert result["evidence_ids"] == [existing]
    assert posted and posted[0].endswith("/evidences/")
    assert got and "name=scan.xml" in got[0]
    assert "/evidences/" in got[0]
    assert not any("/api/risks" in url for url in posted + got)


def test_ciso_evidences_400_get_name_mismatch_does_not_reuse_id(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FOLDER", "22222222-3333-4444-5555-666666666666")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []
    got: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        raise urllib.error.HTTPError(url, 400, "Bad Request", None, io.BytesIO(b"{}"))

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        got.append(url)
        return {
            "count": 1,
            "results": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "name": "other.xml"}],
        }

    result = push_ciso_assets_evidences(
        assets=[],
        evidences=[{"name": "scan.xml", "description": "nmap xml"}],
        cwd=tmp_path,
        poster=poster,
        getter=getter,
    )
    assert result["evidence_ids"] == []
    assert got and "name=scan.xml" in got[0]
    assert not any("/api/risks" in url for url in posted + got)


def test_ciso_evidences_400_multiple_exact_name_hits_does_not_reuse_id(
    monkeypatch, tmp_path: Path
):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FOLDER", "22222222-3333-4444-5555-666666666666")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []
    got: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        raise urllib.error.HTTPError(url, 400, "Bad Request", None, io.BytesIO(b"{}"))

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        got.append(url)
        return {
            "count": 4,
            "results": [
                {"id": "5ef28d64-b832-47a8-927e-6c411ff21cb5", "name": "scan.xml"},
                {"id": "11111111-1111-1111-1111-111111111111", "name": "scan.xml"},
                {"id": "22222222-2222-2222-2222-222222222222", "name": "scan.xml"},
                {"id": "33333333-3333-3333-3333-333333333333", "name": "scan.xml"},
            ],
        }

    result = push_ciso_assets_evidences(
        assets=[],
        evidences=[{"name": "scan.xml", "description": "nmap xml"}],
        cwd=tmp_path,
        poster=poster,
        getter=getter,
    )
    assert result["evidence_ids"] == []
    assert got and "name=scan.xml" in got[0]
    assert not any("/api/risks" in url for url in posted + got)


def test_ciso_assets_400_reuses_get_by_name_id(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FOLDER", "22222222-3333-4444-5555-666666666666")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    existing = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    posted: list[str] = []
    got: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        raise urllib.error.HTTPError(url, 400, "Bad Request", None, io.BytesIO(b"{}"))

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        got.append(url)
        return {"count": 1, "results": [{"id": existing, "name": "172.26.0.9"}]}

    result = push_ciso_assets_evidences(
        assets=[{"name": "172.26.0.9", "description": "host", "type": "PR"}],
        evidences=[],
        cwd=tmp_path,
        poster=poster,
        getter=getter,
    )
    assert result["asset_ids"] == [existing]
    assert posted and posted[0].endswith("/assets/")
    assert got and "name=172.26.0.9" in got[0]
    assert "/assets/" in got[0]
    assert not any("/api/risks" in url for url in posted + got)


def test_ciso_assets_400_get_name_mismatch_does_not_reuse_id(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FOLDER", "22222222-3333-4444-5555-666666666666")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []
    got: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        raise urllib.error.HTTPError(url, 409, "Conflict", None, io.BytesIO(b"{}"))

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        got.append(url)
        return {
            "count": 1,
            "results": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "name": "other-host"}],
        }

    result = push_ciso_assets_evidences(
        assets=[{"name": "172.26.0.9", "description": "host", "type": "PR"}],
        evidences=[],
        cwd=tmp_path,
        poster=poster,
        getter=getter,
    )
    assert result["asset_ids"] == []
    assert got and "name=172.26.0.9" in got[0]
    assert not any("/api/risks" in url for url in posted + got)


def test_ciso_assets_prefer_pr_when_host_and_service_share_name(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FOLDER", "22222222-3333-4444-5555-666666666666")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[dict] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        body = json.loads(data.decode("utf-8"))
        posted.append(body)
        return {"status": 201, "body": {"id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "name": body["name"]}}

    result = push_ciso_assets_evidences(
        assets=[
            {"name": "172.26.0.9", "description": "tcp/80 http", "type": "SP"},
            {"name": "172.26.0.9", "description": "host", "type": "PR"},
        ],
        evidences=[],
        cwd=tmp_path,
        poster=poster,
    )
    names = [row["name"] for row in posted if row.get("type")]
    assert names == ["172.26.0.9"]
    assert posted[0]["type"] == "PR"
    assert len(result["asset_ids"]) == 1


def test_ciso_findings_refuse_without_assessment_uuid(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18080")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.delenv("CISO_FINDINGS_ASSESSMENT", raising=False)
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append(url)
        return 201

    with pytest.raises(GateError, match="CISO_FINDINGS_ASSESSMENT"):
        push_ciso_findings(
            findings=[{"name": "Cleartext HTTP", "description": "tls", "severity": "medium"}],
            cwd=tmp_path,
            poster=poster,
        )
    assert posted == []


def test_ciso_findings_post_with_operator_uuid(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18080")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv("CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return 201

    result = push_ciso_findings(
        findings=[
            {
                "name": "Cleartext HTTP",
                "description": "Enforce TLS",
                "severity": "medium",
                "ref_id": "COV-F-0001",
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    assert result["http"] is True
    assert result["posted"] == 1
    url, body = posted[0]
    assert url.endswith("/findings/")
    assert "/api/risks" not in url
    assert body["findings_assessment"] == "11111111-2222-3333-4444-555555555555"
    assert body["name"] == "Cleartext HTTP"


def test_ciso_findings_live_body_uses_int_severity_and_identified_status(
    monkeypatch, tmp_path: Path
):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return 201

    push_ciso_findings(
        findings=[
            {
                "name": "Memcached exposed",
                "description": "Bind to localhost",
                "severity": "high",
                "status": "open",
                "ref_id": "COV-F-0001",
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    body = posted[0][1]
    assert body["severity"] == 3
    assert body["status"] == "identified"
    assert body["findings_assessment"] == "11111111-2222-3333-4444-555555555555"
    assert "/api/risks" not in posted[0][0]


def test_ciso_findings_post_maps_catalog_action_to_recommendation(
    monkeypatch, tmp_path: Path
):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return 201

    push_ciso_findings(
        findings=[
            {
                "name": "Cleartext HTTP",
                "description": "Cleartext HTTP on 172.26.0.2",
                "severity": "medium",
                "status": "open",
                "ref_id": "COV-F-0001",
                "action": "Enforce TLS; redirect HTTP to HTTPS.",
                "honesty": (
                    "surface map ≠ honeypot validated ≠ control operating effectiveness"
                ),
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    body = posted[0][1]
    assert body["recommendation"] == "Enforce TLS; redirect HTTP to HTTPS."
    assert "surface map" in body["observation"]
    assert "operating effectiveness" in body["observation"]
    assert "/api/risks" not in posted[0][0]


def test_ciso_findings_post_includes_asset_uuid_when_provided(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []
    asset_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return 201

    push_ciso_findings(
        findings=[
            {
                "name": "Memcached exposed",
                "description": "Bind to localhost",
                "severity": "high",
                "status": "open",
                "asset": asset_id,
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    body = posted[0][1]
    assert body["asset"] == asset_id
    assert "/api/risks" not in posted[0][0]


def test_ciso_findings_post_includes_evidence_uuids_when_provided(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []
    evidence_id = "cccccccc-dddd-eeee-ffff-000000000001"

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return 201

    push_ciso_findings(
        findings=[
            {
                "name": "Permissive CORS policy",
                "description": "Do not use Access-Control-Allow-Origin: *",
                "severity": "low",
                "status": "open",
                "evidences": [evidence_id],
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    body = posted[0][1]
    assert body["evidences"] == [evidence_id]
    assert "/api/risks" not in posted[0][0]


def test_ciso_findings_post_omits_asset_when_not_uuid(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return 201

    push_ciso_findings(
        findings=[
            {
                "name": "Memcached exposed",
                "description": "Bind to localhost",
                "severity": "high",
                "status": "open",
                "asset": "memcached.coveylab",
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    body = posted[0][1]
    assert "asset" not in body
    assert "/api/risks" not in posted[0][0]


def test_ciso_findings_returns_ids_from_poster_body(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    finding_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        return {
            "status": 201,
            "body": {"id": finding_id, "name": "Memcached exposed"},
        }

    result = push_ciso_findings(
        findings=[
            {
                "name": "Memcached exposed",
                "description": "Bind to localhost",
                "severity": "high",
                "status": "open",
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    assert result["finding_ids"] == [finding_id]
    assert "/api/risks" not in json.dumps(result)


def test_ciso_findings_400_continues_without_name_reuse(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []
    second_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        body = json.loads(data.decode("utf-8"))
        if body.get("name") == "Cleartext HTTP":
            raise urllib.error.HTTPError(
                url, 400, "Bad Request", None, io.BytesIO(b"{}")
            )
        return {"status": 201, "body": {"id": second_id, "name": body.get("name")}}

    result = push_ciso_findings(
        findings=[
            {"name": "Cleartext HTTP", "description": "tls", "severity": "medium"},
            {"name": "Missing HSTS", "description": "hsts", "severity": "medium"},
        ],
        cwd=tmp_path,
        poster=poster,
    )
    assert result["finding_ids"] == [second_id]
    assert result["posted"] == 1
    assert len(posted) == 2
    assert all(url.endswith("/findings/") for url in posted)
    assert not any("name=" in url for url in posted)
    assert not any("/api/risks" in url for url in posted)


def test_ciso_finding_read_back_gets_id_not_risks(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    finding_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    got: list[str] = []

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        got.append(url)
        return {"id": finding_id, "name": "Memcached exposed"}

    body = fetch_ciso_finding(finding_id, cwd=tmp_path, getter=getter)
    assert body["id"] == finding_id
    assert got[0].endswith(f"/findings/{finding_id}/")
    assert not any("/api/risks" in url for url in got)


def test_ciso_finding_read_back_without_gate_no_socket(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CISO_URL", raising=False)
    monkeypatch.delenv("CISO_TOKEN", raising=False)
    got: list[str] = []

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        got.append(url)
        return {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}

    with pytest.raises(GateError, match="dual-gate"):
        fetch_ciso_finding(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            cwd=tmp_path,
            getter=getter,
        )
    assert got == []


def test_export_live_ciso_reads_back_finding_ids(monkeypatch, tmp_path: Path):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    finding_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def fake_assets(**kwargs):
        return {"posted": 1, "http": True, "paths": ["/api/assets/", "/api/evidences/"]}

    def fake_findings(**kwargs):
        return {
            "posted": 1,
            "http": True,
            "paths": ["/api/findings/"],
            "finding_ids": [finding_id],
        }

    fetched: list[str] = []

    def fake_fetch(fid, **kwargs):
        fetched.append(fid)
        return {"id": fid, "name": "Cleartext HTTP"}

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.export.push_ciso_findings", fake_findings)
    monkeypatch.setattr("covey.export.fetch_ciso_finding", fake_fetch)

    summary = export_pack(run, target="ciso", live=True, cwd=tmp_path)
    assert summary["http"] is True
    assert summary["ciso_finding_ids"] == [finding_id]
    assert summary["ciso_findings_read_back"] == [finding_id]
    assert fetched == [finding_id]


def test_export_live_ciso_attaches_finding_to_posted_asset(monkeypatch, tmp_path: Path):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    finding_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    captured: dict[str, list] = {}

    def fake_assets(**kwargs):
        rows = list(kwargs.get("assets") or [])
        ids = [
            f"bbbbbbbb-cccc-dddd-eeee-{index:012d}" for index, _row in enumerate(rows, start=1)
        ]
        captured["assets"] = rows
        captured["asset_ids"] = ids
        return {
            "posted": len(rows),
            "http": True,
            "paths": ["/api/assets/", "/api/evidences/"],
            "asset_ids": ids,
        }

    def fake_findings(**kwargs):
        captured["findings"] = list(kwargs.get("findings") or [])
        return {
            "posted": 1,
            "http": True,
            "paths": ["/api/findings/"],
            "finding_ids": [finding_id],
        }

    def fake_fetch(fid, **kwargs):
        posted_asset = ""
        for row in captured.get("findings") or []:
            value = str(row.get("asset") or "").strip()
            if value:
                posted_asset = value
                break
        body: dict = {"id": fid, "name": "Cleartext HTTP"}
        if posted_asset:
            body["asset"] = {"id": posted_asset, "str": "127.0.0.1"}
        return body

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.export.push_ciso_findings", fake_findings)
    monkeypatch.setattr("covey.export.fetch_ciso_finding", fake_fetch)

    summary = export_pack(run, target="ciso", live=True, cwd=tmp_path)
    assert summary["http"] is True
    names = [str(row.get("name") or "") for row in captured.get("assets") or []]
    assert "127.0.0.1" in names
    host_id = captured["asset_ids"][names.index("127.0.0.1")]
    attached = [row.get("asset") for row in captured.get("findings") or []]
    assert host_id in attached
    assert summary["ciso_findings_read_back_assets"] == [host_id]
    assert "/api/risks" not in json.dumps(captured)


def test_export_live_ciso_read_back_records_asset_id_from_read_serializer(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    finding_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    captured: dict[str, list] = {}

    def fake_assets(**kwargs):
        rows = list(kwargs.get("assets") or [])
        ids = [
            f"bbbbbbbb-cccc-dddd-eeee-{index:012d}"
            for index, _row in enumerate(rows, start=1)
        ]
        captured["assets"] = rows
        captured["asset_ids"] = ids
        return {
            "posted": len(rows),
            "http": True,
            "paths": ["/api/assets/", "/api/evidences/"],
            "asset_ids": ids,
        }

    def fake_findings(**kwargs):
        captured["findings"] = list(kwargs.get("findings") or [])
        return {
            "posted": 1,
            "http": True,
            "paths": ["/api/findings/"],
            "finding_ids": [finding_id],
        }

    def fake_fetch(fid, **kwargs):
        names = [str(row.get("name") or "") for row in captured.get("assets") or []]
        host_id = captured["asset_ids"][names.index("127.0.0.1")]
        return {
            "id": fid,
            "name": "Cleartext HTTP",
            "asset": {"id": host_id, "str": "127.0.0.1"},
        }

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.export.push_ciso_findings", fake_findings)
    monkeypatch.setattr("covey.export.fetch_ciso_finding", fake_fetch)

    summary = export_pack(run, target="ciso", live=True, cwd=tmp_path)
    names = [str(row.get("name") or "") for row in captured.get("assets") or []]
    host_id = captured["asset_ids"][names.index("127.0.0.1")]
    assert summary["ciso_findings_read_back"] == [finding_id]
    assert summary["ciso_findings_read_back_assets"] == [host_id]
    assert "/api/risks" not in json.dumps(summary)


def test_export_live_ciso_attaches_finding_to_posted_evidences(monkeypatch, tmp_path: Path):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    finding_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    evidence_id = "dddddddd-eeee-ffff-aaaa-111111111111"
    captured: dict[str, list] = {}

    def fake_assets(**kwargs):
        rows = list(kwargs.get("assets") or [])
        ids = [
            f"bbbbbbbb-cccc-dddd-eeee-{index:012d}"
            for index, _row in enumerate(rows, start=1)
        ]
        captured["assets"] = rows
        captured["asset_ids"] = ids
        return {
            "posted": len(rows),
            "http": True,
            "paths": ["/api/assets/", "/api/evidences/"],
            "asset_ids": ids,
            "evidence_ids": [evidence_id],
        }

    def fake_findings(**kwargs):
        captured["findings"] = list(kwargs.get("findings") or [])
        return {
            "posted": 1,
            "http": True,
            "paths": ["/api/findings/"],
            "finding_ids": [finding_id],
        }

    def fake_fetch(fid, **kwargs):
        posted_ev = []
        posted_asset = ""
        for row in captured.get("findings") or []:
            value = str(row.get("asset") or "").strip()
            if value:
                posted_asset = value
            posted_ev = list(row.get("evidences") or [])
            if posted_ev:
                break
        body: dict = {"id": fid, "name": "Cleartext HTTP"}
        if posted_asset:
            body["asset"] = {"id": posted_asset, "str": "127.0.0.1"}
        body["evidences"] = [{"id": item, "str": "p1-s00.xml"} for item in posted_ev]
        return body

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.export.push_ciso_findings", fake_findings)
    monkeypatch.setattr("covey.export.fetch_ciso_finding", fake_fetch)

    summary = export_pack(run, target="ciso", live=True, cwd=tmp_path)
    attached = [row.get("evidences") for row in captured.get("findings") or []]
    assert [evidence_id] in attached
    assert summary["ciso_findings_read_back"] == [finding_id]
    assert summary["ciso_findings_read_back_evidences"] == [evidence_id]
    assert "/api/risks" not in json.dumps(captured)


def test_export_live_ciso_read_back_fails_when_posted_evidences_missing_on_get(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    finding_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    evidence_id = "dddddddd-eeee-ffff-aaaa-111111111111"
    captured: dict[str, list] = {}

    def fake_assets(**kwargs):
        rows = list(kwargs.get("assets") or [])
        ids = [
            f"bbbbbbbb-cccc-dddd-eeee-{index:012d}"
            for index, _row in enumerate(rows, start=1)
        ]
        captured["assets"] = rows
        captured["asset_ids"] = ids
        return {
            "posted": len(rows),
            "http": True,
            "paths": ["/api/assets/", "/api/evidences/"],
            "asset_ids": ids,
            "evidence_ids": [evidence_id],
        }

    def fake_findings(**kwargs):
        captured["findings"] = list(kwargs.get("findings") or [])
        return {
            "posted": 1,
            "http": True,
            "paths": ["/api/findings/"],
            "finding_ids": [finding_id],
        }

    def fake_fetch(fid, **kwargs):
        posted_asset = ""
        for row in captured.get("findings") or []:
            value = str(row.get("asset") or "").strip()
            if value:
                posted_asset = value
                break
        body: dict = {"id": fid, "name": "Cleartext HTTP", "evidences": []}
        if posted_asset:
            body["asset"] = {"id": posted_asset, "str": "127.0.0.1"}
        return body

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.export.push_ciso_findings", fake_findings)
    monkeypatch.setattr("covey.export.fetch_ciso_finding", fake_fetch)

    with pytest.raises(GateError, match="evidence"):
        export_pack(run, target="ciso", live=True, cwd=tmp_path)
    assert "/api/risks" not in json.dumps(captured)


def test_export_live_ciso_read_back_fails_when_posted_asset_missing_on_get(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    finding_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    captured: dict[str, list] = {}

    def fake_assets(**kwargs):
        rows = list(kwargs.get("assets") or [])
        ids = [
            f"bbbbbbbb-cccc-dddd-eeee-{index:012d}"
            for index, _row in enumerate(rows, start=1)
        ]
        captured["assets"] = rows
        captured["asset_ids"] = ids
        return {
            "posted": len(rows),
            "http": True,
            "paths": ["/api/assets/", "/api/evidences/"],
            "asset_ids": ids,
        }

    def fake_findings(**kwargs):
        captured["findings"] = list(kwargs.get("findings") or [])
        return {
            "posted": 1,
            "http": True,
            "paths": ["/api/findings/"],
            "finding_ids": [finding_id],
        }

    def fake_fetch(fid, **kwargs):
        return {"id": fid, "name": "Cleartext HTTP", "asset": None}

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.export.push_ciso_findings", fake_findings)
    monkeypatch.setattr("covey.export.fetch_ciso_finding", fake_fetch)

    with pytest.raises(GateError, match="asset"):
        export_pack(run, target="ciso", live=True, cwd=tmp_path)
    assert "/api/risks" not in json.dumps(captured)


def test_export_live_ciso_read_back_fails_when_posted_recommendation_missing_on_get(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    host_id = "bbbbbbbb-cccc-dddd-eeee-000000000001"
    evidence_id = "dddddddd-eeee-ffff-aaaa-111111111111"
    made: list[str] = []

    def fake_assets(**kwargs):
        return {
            "posted": 1,
            "http": True,
            "paths": ["/api/assets/", "/api/evidences/"],
            "asset_ids": [host_id],
            "evidence_ids": [evidence_id],
            "posted_assets": [{"name": "127.0.0.1", "id": host_id, "type": "PR"}],
        }

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        body = json.loads(data.decode("utf-8"))
        fid = f"aaaaaaaa-bbbb-cccc-dddd-{len(made) + 1:012d}"
        made.append(fid)
        assert body.get("recommendation")
        return {"status": 201, "body": {"id": fid, "name": body.get("name")}}

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        fid = url.rstrip("/").split("/")[-1]
        return {
            "id": fid,
            "name": "Cleartext HTTP",
            "asset": {"id": host_id, "str": "127.0.0.1"},
            "evidences": [{"id": evidence_id, "str": "e"}],
        }

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.grc._default_poster", poster)
    monkeypatch.setattr("covey.grc._default_getter", getter)

    with pytest.raises(GateError, match="recommendation"):
        export_pack(run, target="ciso", live=True, cwd=tmp_path)
    assert made
    assert "/api/risks" not in json.dumps(made)


def test_export_live_ciso_read_back_fails_when_posted_observation_missing_on_get(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    host_id = "bbbbbbbb-cccc-dddd-eeee-000000000001"
    evidence_id = "dddddddd-eeee-ffff-aaaa-111111111111"
    made: list[str] = []
    bodies: dict[str, dict] = {}

    def fake_assets(**kwargs):
        return {
            "posted": 1,
            "http": True,
            "paths": ["/api/assets/", "/api/evidences/"],
            "asset_ids": [host_id],
            "evidence_ids": [evidence_id],
            "posted_assets": [{"name": "127.0.0.1", "id": host_id, "type": "PR"}],
        }

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        body = json.loads(data.decode("utf-8"))
        fid = f"aaaaaaaa-bbbb-cccc-dddd-{len(made) + 1:012d}"
        made.append(fid)
        bodies[fid] = body
        assert body.get("observation")
        return {"status": 201, "body": {"id": fid, "name": body.get("name")}}

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        fid = url.rstrip("/").split("/")[-1]
        posted = bodies.get(fid) or {}
        return {
            "id": fid,
            "name": posted.get("name") or "Cleartext HTTP",
            "asset": {"id": host_id, "str": "127.0.0.1"},
            "evidences": [{"id": evidence_id, "str": "e"}],
            "recommendation": posted.get("recommendation") or "",
        }

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.grc._default_poster", poster)
    monkeypatch.setattr("covey.grc._default_getter", getter)

    with pytest.raises(GateError, match="observation"):
        export_pack(run, target="ciso", live=True, cwd=tmp_path)
    assert made
    assert "/api/risks" not in json.dumps(made)


def test_export_live_ciso_read_back_pairs_successful_finding_not_400_row(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80 HTTP/1.1 200 OK\n"
        "https://127.0.0.3:443 HTTP/1.1 200 OK\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    host1 = "bbbbbbbb-cccc-dddd-eeee-000000000001"
    host3 = "bbbbbbbb-cccc-dddd-eeee-000000000003"
    made: list[str] = []
    bodies: dict[str, dict] = {}

    def fake_assets(**kwargs):
        rows = list(kwargs.get("assets") or [])
        ids = []
        for row in rows:
            name = str(row.get("name") or "")
            if name == "127.0.0.1":
                ids.append(host1)
            elif name == "127.0.0.3":
                ids.append(host3)
            else:
                ids.append("bbbbbbbb-cccc-dddd-eeee-000000000099")
        return {
            "posted": len(ids),
            "http": True,
            "paths": ["/api/assets/", "/api/evidences/"],
            "asset_ids": ids,
            "evidence_ids": [],
        }

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        body = json.loads(data.decode("utf-8"))
        if body.get("asset") == host1:
            raise urllib.error.HTTPError(
                url, 400, "Bad Request", None, io.BytesIO(b"{}")
            )
        fid = f"aaaaaaaa-bbbb-cccc-dddd-{len(made) + 1:012d}"
        made.append(fid)
        bodies[fid] = body
        return {"status": 201, "body": {"id": fid, "name": body.get("name")}}

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        fid = url.rstrip("/").split("/")[-1]
        posted = bodies.get(fid) or {}
        return {
            "id": fid,
            "name": posted.get("name") or "Missing HSTS",
            "asset": {"id": host3, "str": "127.0.0.3"},
            "recommendation": posted.get("recommendation") or "",
            "observation": posted.get("observation") or "",
        }

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_assets)
    monkeypatch.setattr("covey.grc._default_poster", poster)
    monkeypatch.setattr("covey.grc._default_getter", getter)

    summary = export_pack(run, target="ciso", live=True, cwd=tmp_path)
    assert made
    assert summary["ciso_finding_ids"] == made
    assert summary["ciso_findings_read_back"] == made
    assert summary["ciso_findings_read_back_assets"] == [host3] * len(made)
    assert host1 not in summary["ciso_findings_read_back_assets"]
    assert "/api/risks" not in json.dumps(summary)


def test_export_live_ciso_wires_asset_from_posted_name_not_index_zip(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80 HTTP/1.1 200 OK\n"
        "https://127.0.0.3:443 HTTP/1.1 200 OK\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.setenv(
        "CISO_FINDINGS_ASSESSMENT", "11111111-2222-3333-4444-555555555555"
    )
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    host3 = "bbbbbbbb-cccc-dddd-eeee-000000000003"
    made: list[str] = []
    wired: list[dict] = []
    bodies: dict[str, dict] = {}

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        body = json.loads(data.decode("utf-8"))
        path = url.split("?", 1)[0].rstrip("/")
        if path.endswith("/assets"):
            name = str(body.get("name") or "")
            if name == "127.0.0.1":
                raise urllib.error.HTTPError(
                    url, 400, "Bad Request", None, io.BytesIO(b"{}")
                )
            if name == "127.0.0.3":
                return {"status": 201, "body": {"id": host3, "name": name}}
            return {
                "status": 201,
                "body": {
                    "id": "bbbbbbbb-cccc-dddd-eeee-000000000099",
                    "name": name,
                },
            }
        if path.endswith("/evidences"):
            return {
                "status": 201,
                "body": {
                    "id": "dddddddd-eeee-ffff-aaaa-111111111111",
                    "name": body.get("name"),
                },
            }
        if path.endswith("/findings"):
            fid = f"aaaaaaaa-bbbb-cccc-dddd-{len(made) + 1:012d}"
            made.append(fid)
            bodies[fid] = body
            return {"status": 201, "body": {"id": fid, "name": body.get("name")}}
        raise AssertionError(url)

    def getter(url: str, *, headers: dict, timeout: float = 10) -> dict:
        if "/assets/?" in url:
            return {"count": 0, "results": []}
        if "/evidences/?" in url:
            return {"count": 0, "results": []}
        fid = url.rstrip("/").split("/")[-1]
        posted = bodies.get(fid) or {}
        asset = str(posted.get("asset") or "")
        out: dict = {"id": fid, "name": posted.get("name")}
        out["asset"] = {"id": asset, "str": "host"} if asset else None
        out["evidences"] = [
            {"id": item, "str": "e"} for item in (posted.get("evidences") or [])
        ]
        out["recommendation"] = str(posted.get("recommendation") or "")
        out["observation"] = str(posted.get("observation") or "")
        return out

    from covey.grc import push_ciso_findings as real_push_findings

    def wrap_findings(**kwargs):
        wired.extend(list(kwargs.get("findings") or []))
        return real_push_findings(**kwargs)

    monkeypatch.setattr("covey.grc._default_poster", poster)
    monkeypatch.setattr("covey.grc._default_getter", getter)
    monkeypatch.setattr("covey.export.push_ciso_findings", wrap_findings)

    summary = export_pack(run, target="ciso", live=True, cwd=tmp_path)
    host1_assets = [
        str(row.get("asset") or "")
        for row in wired
        if str(row.get("address") or "") == "127.0.0.1"
    ]
    host3_assets = [
        str(row.get("asset") or "")
        for row in wired
        if str(row.get("address") or "") == "127.0.0.3"
    ]
    assert host1_assets
    assert host3_assets
    assert host3 not in host1_assets
    assert all(item == host3 for item in host3_assets)
    assert host3 in summary["ciso_findings_read_back_assets"]
    assert "/api/risks" not in json.dumps(summary)


def test_opengrc_live_refused():
    with pytest.raises(GateError, match=r"/api/risks") as exc:
        refuse_opengrc_live()
    text = str(exc.value)
    assert "title" in text
    assert "likelihood" in text
    assert "impact" in text
    assert "Sanctum" in text
    assert "No socket" in text
    assert "schema unconfirmed" not in text.lower()


def test_probo_live_without_gate_no_socket(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("PROBO_TENANT", raising=False)
    posted: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append(url)
        return 200

    with pytest.raises(GateError, match="http=false"):
        push_probo_findings(
            findings=[{"title": "Cleartext HTTP", "severity": "medium", "description": "x"}],
            cwd=tmp_path,
            poster=poster,
        )
    assert posted == []


def test_probo_live_posts_addFinding_not_createRisk(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.setenv("PROBO_ORGANIZATION", "org_lab_not_a_scan_target")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return 200

    result = push_probo_findings(
        findings=[
            {
                "title": "Cleartext HTTP",
                "severity": "medium",
                "description": "Enforce TLS",
                "assets": ["172.26.0.2"],
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    assert result["http"] is True
    url, body = posted[0]
    assert "graphql" in url.lower()
    query = json.dumps(body).lower()
    compact = query.replace("_", "")
    assert "createfinding" in compact
    assert "addfinding" not in compact
    assert "createrisk" not in compact
    assert "192.168.10.130" not in query


def test_export_live_all_missing_probo_gate_posts_nothing(monkeypatch, tmp_path: Path):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:18800")
    monkeypatch.setenv("CISO_TOKEN", "lab-token")
    monkeypatch.delenv("PROBO_TENANT", raising=False)
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_CISO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []

    def fake_ciso_assets(**kwargs):
        posted.append("ciso-assets")
        return {"posted": 1, "http": True, "paths": ["/api/assets/", "/api/evidences/"]}

    def fake_ciso_findings(**kwargs):
        posted.append("ciso-findings")
        return {"posted": 1, "http": True, "paths": ["/api/findings/"], "finding_ids": []}

    def fake_probo(**kwargs):
        posted.append("probo")
        return {"posted": 1, "http": True, "operation": "addFinding"}

    monkeypatch.setattr("covey.export.push_ciso_assets_evidences", fake_ciso_assets)
    monkeypatch.setattr("covey.export.push_ciso_findings", fake_ciso_findings)
    monkeypatch.setattr("covey.export.push_probo_findings", fake_probo)

    with pytest.raises(GateError, match="http=false"):
        export_pack(run, target="all", live=True, cwd=tmp_path)
    assert posted == []
    assert "/api/risks" not in json.dumps(posted)


def test_probo_live_without_organization_no_socket(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.delenv("PROBO_ORGANIZATION", raising=False)
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> int:
        posted.append(url)
        return 200

    with pytest.raises(GateError, match="http=false"):
        push_probo_findings(
            findings=[{"title": "Cleartext HTTP", "severity": "medium", "description": "x"}],
            cwd=tmp_path,
            poster=poster,
        )
    assert posted == []


def test_probo_live_posts_createFinding_input_not_addFinding(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.setenv("PROBO_ORGANIZATION", "org_lab_not_a_scan_target")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict, dict]] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append((url, json.loads(data.decode("utf-8")), headers))
        return {
            "status": 200,
            "body": {
                "data": {
                    "createFinding": {
                        "findingEdge": {"node": {"id": "finding_lab_gid"}}
                    }
                }
            },
        }

    result = push_probo_findings(
        findings=[
            {
                "title": "Cleartext HTTP",
                "severity": "medium",
                "description": "Enforce TLS",
                "assets": ["172.26.0.2"],
            }
        ],
        cwd=tmp_path,
        poster=poster,
    )
    assert result["http"] is True
    assert result["operation"] == "createFinding"
    assert result["finding_ids"] == ["finding_lab_gid"]
    url, body, headers = posted[0]
    assert url.endswith("/api/console/v1/graphql")
    query = json.dumps(body)
    compact = query.lower().replace("_", "")
    assert "createfinding" in compact
    assert "addfinding" not in compact
    assert "createrisk" not in compact
    assert "/api/risks" not in url
    assert "192.168.10.130" not in query
    variables = body["variables"]["input"]
    assert variables["organizationId"] == "org_lab_not_a_scan_target"
    assert variables["kind"] == "OBSERVATION"
    assert variables["status"] == "OPEN"
    assert variables["priority"] == "MEDIUM"
    assert "Cleartext HTTP" in variables["description"]
    assert "title" not in variables
    assert "severity" not in variables
    assert "riskId" not in variables
    assert "Bearer lab-token" in str(headers.get("Authorization") or "")


def test_probo_graphql_errors_fail_closed_no_finding_ids(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.setenv("PROBO_ORGANIZATION", "org_lab_not_a_scan_target")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        return {
            "status": 200,
            "body": {
                "errors": [{"message": "CreateFindingInput rejected"}],
                "data": None,
            },
        }

    with pytest.raises(GateError, match="GraphQL"):
        push_probo_findings(
            findings=[
                {
                    "title": "Cleartext HTTP",
                    "severity": "medium",
                    "description": "Enforce TLS",
                    "assets": ["172.26.0.2"],
                }
            ],
            cwd=tmp_path,
            poster=poster,
        )
    assert posted and "graphql" in posted[0].lower()
    assert "/api/risks" not in posted[0]


def test_export_live_probo_reads_back_finding_ids(monkeypatch, tmp_path: Path):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.setenv("PROBO_ORGANIZATION", "org_lab_not_a_scan_target")
    monkeypatch.delenv("CISO_URL", raising=False)
    monkeypatch.delenv("CISO_TOKEN", raising=False)
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    finding_id = "finding_lab_gid"
    fetched: list[str] = []

    def fake_probo(**kwargs):
        return {
            "posted": 1,
            "http": True,
            "operation": "createFinding",
            "finding_ids": [finding_id],
            "posted_rows": [
                {"id": finding_id, "description": "Cleartext HTTP: Enforce TLS"}
            ],
        }

    def fake_fetch(fid, **kwargs):
        fetched.append(fid)
        return {"id": fid, "description": "Cleartext HTTP: Enforce TLS"}

    monkeypatch.setattr("covey.export.push_probo_findings", fake_probo)
    monkeypatch.setattr(
        "covey.export.fetch_probo_finding", fake_fetch, raising=False
    )

    summary = export_pack(run, target="probo", live=True, cwd=tmp_path)
    assert summary["http"] is True
    assert summary["probo_posted"] == 1
    assert summary["probo_finding_ids"] == [finding_id]
    assert summary["probo_findings_read_back"] == [finding_id]
    assert fetched == [finding_id]
    assert "/api/risks" not in json.dumps(summary)


def test_export_live_probo_read_back_fails_when_posted_description_missing(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.setenv("PROBO_ORGANIZATION", "org_lab_not_a_scan_target")
    monkeypatch.delenv("CISO_URL", raising=False)
    monkeypatch.delenv("CISO_TOKEN", raising=False)
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    finding_id = "finding_lab_gid"
    posted_description = "Cleartext HTTP: Enforce TLS"

    def fake_probo(**kwargs):
        return {
            "posted": 1,
            "http": True,
            "operation": "createFinding",
            "finding_ids": [finding_id],
            "posted_rows": [{"id": finding_id, "description": posted_description}],
        }

    def fake_fetch(fid, **kwargs):
        return {"id": fid, "kind": "OBSERVATION"}

    monkeypatch.setattr("covey.export.push_probo_findings", fake_probo)
    monkeypatch.setattr("covey.export.fetch_probo_finding", fake_fetch)

    with pytest.raises(GateError, match="description"):
        export_pack(run, target="probo", live=True, cwd=tmp_path)


def test_export_live_probo_node_omits_description_fail_closed(
    monkeypatch, tmp_path: Path
):
    run = _seed_run(tmp_path)
    (run / "shards" / "p1-s00" / "stdout.log").write_text(
        "http://127.0.0.1:80\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.setenv("PROBO_ORGANIZATION", "org_lab_not_a_scan_target")
    monkeypatch.delenv("CISO_URL", raising=False)
    monkeypatch.delenv("CISO_TOKEN", raising=False)
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    posted_ids: list[str] = []
    created: dict[str, str] = {}

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        body = json.loads(data.decode("utf-8"))
        query = str(body.get("query") or "")
        compact = query.lower().replace("_", "")
        assert "createrisk" not in compact
        assert "addfinding" not in compact
        assert "/api/risks" not in url
        if "createfinding" in compact:
            fid = f"finding_lab_{len(posted_ids) + 1}"
            posted_ids.append(fid)
            created[fid] = str(body["variables"]["input"]["description"])
            return {
                "status": 200,
                "body": {
                    "data": {
                        "createFinding": {
                            "findingEdge": {"node": {"id": fid}}
                        }
                    }
                },
            }
        fid = str((body.get("variables") or {}).get("id") or "")
        return {
            "status": 200,
            "body": {"data": {"node": {"id": fid, "kind": "OBSERVATION"}}},
        }

    monkeypatch.setattr("covey.grc._default_poster", poster)
    with pytest.raises(GateError, match="description"):
        export_pack(run, target="probo", live=True, cwd=tmp_path)
    assert posted_ids
    assert created


def test_fetch_probo_finding_without_gate_no_socket(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("PROBO_TENANT", raising=False)
    monkeypatch.delenv("PROBO_TOKEN", raising=False)
    monkeypatch.delenv("PROBO_ORGANIZATION", raising=False)
    posted: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        return {"status": 200, "body": {"data": {"node": {"id": "finding_lab_gid"}}}}

    with pytest.raises(GateError, match="http=false"):
        fetch_probo_finding("finding_lab_gid", cwd=tmp_path, poster=poster)
    assert posted == []


def test_fetch_probo_finding_queries_node_not_createRisk(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.setenv("PROBO_ORGANIZATION", "org_lab_not_a_scan_target")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    posted: list[tuple[str, dict]] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append((url, json.loads(data.decode("utf-8"))))
        return {
            "status": 200,
            "body": {
                "data": {
                    "node": {
                        "id": "finding_lab_gid",
                        "description": "Cleartext HTTP: Enforce TLS",
                        "kind": "OBSERVATION",
                    }
                }
            },
        }

    body = fetch_probo_finding("finding_lab_gid", cwd=tmp_path, poster=poster)
    assert body["id"] == "finding_lab_gid"
    assert body["description"] == "Cleartext HTTP: Enforce TLS"
    url, payload = posted[0]
    assert url.endswith("/api/console/v1/graphql")
    compact = json.dumps(payload).lower().replace("_", "")
    assert "node" in compact
    assert "...onfinding" in compact.replace(" ", "")
    assert "createfinding" not in compact
    assert "addfinding" not in compact
    assert "createrisk" not in compact
    assert payload["variables"]["id"] == "finding_lab_gid"
    assert "/api/risks" not in url


def test_fetch_probo_finding_graphql_errors_fail_closed(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PROBO_TENANT", "http://127.0.0.1:18081")
    monkeypatch.setenv("PROBO_TOKEN", "lab-token")
    monkeypatch.setenv("PROBO_ORGANIZATION", "org_lab_not_a_scan_target")
    gate = tmp_path / "push"
    gate.mkdir()
    (gate / "GATE_PROBO").write_text("ok\n", encoding="utf-8")
    posted: list[str] = []

    def poster(url: str, *, data: bytes, headers: dict, timeout: float = 10) -> dict:
        posted.append(url)
        return {
            "status": 200,
            "body": {"errors": [{"message": "Finding not found"}], "data": None},
        }

    with pytest.raises(GateError, match="GraphQL"):
        fetch_probo_finding("finding_lab_gid", cwd=tmp_path, poster=poster)
    assert posted and "graphql" in posted[0].lower()
    assert "/api/risks" not in posted[0]
