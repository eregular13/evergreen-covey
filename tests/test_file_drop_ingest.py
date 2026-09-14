from __future__ import annotations

import json
from pathlib import Path

import pytest

from covey.export import export_pack
from covey.plan import build_plan
from covey.runner import run_plan
from covey.scope import load
from tests.helpers import signed_scope_dict

_NESSUS = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="lab">
    <ReportHost name="10.9.8.7">
      <ReportItem port="443" pluginID="1" pluginName="OpenSSL">
        <cve>CVE-2024-7777</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def test_file_drop_plan_is_ingest_not_spawn() -> None:
    scope = load(signed_scope_dict(targets=[{"file_drop": "in/lab.nessus"}]))
    plan = build_plan(scope, out_root="out")
    assert plan.shards == ["in/lab.nessus"]
    assert plan.pass1_workers == []
    assert plan.pass2_workers == []
    assert plan.pipe_workers == []
    ingest = [row for row in plan.workers if row.stage == "ingest"]
    assert len(ingest) == 1
    assert ingest[0].target == "in/lab.nessus"
    assert ingest[0].argv is None
    assert ingest[0].argv_template is None


def test_file_drop_run_copies_xml_without_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drop = tmp_path / "in"
    drop.mkdir()
    (drop / "lab.nessus").write_text(_NESSUS, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def boom(*args, **kwargs):
        raise AssertionError(f"file_drop must not spawn {args!r}")

    monkeypatch.setattr("covey.runner.subprocess.run", boom)
    monkeypatch.setattr("covey.runner.subprocess.Popen", boom)

    scope = load(signed_scope_dict(targets=[{"file_drop": "in/lab.nessus"}]))
    plan = build_plan(scope, out_root=tmp_path / "out")
    report = run_plan(plan, out_root=tmp_path / "out")
    assert report.ok is True
    copied = tmp_path / "out" / "shards" / "drop-s00" / "scan.xml"
    assert copied.is_file()
    assert "CVE-2024-7777" in copied.read_text(encoding="utf-8")


def test_file_drop_export_promotes_cve_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drop = tmp_path / "in"
    drop.mkdir()
    (drop / "lab.nessus").write_text(_NESSUS, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    scope = load(signed_scope_dict(targets=[{"file_drop": "in/lab.nessus"}]))
    plan = build_plan(scope, out_root=tmp_path / "out")
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / "plan.json").write_text(
        json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    run_plan(plan, out_root=out)
    summary = export_pack(out, target="ciso")
    pack = Path(summary["pack"])
    findings = [
        json.loads(line)
        for line in (pack / "findings.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    ingested = [row for row in findings if row.get("cve") == "CVE-2024-7777"]
    assert ingested and ingested[0]["address"] == "10.9.8.7"
    hosts = {
        row["address"]
        for row in [
            json.loads(line)
            for line in (pack / "assets.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        if row.get("kind") == "host"
    }
    assert "10.9.8.7" in hosts
    assets_csv = (pack / "ciso-assistant" / "assets.csv").read_text(encoding="utf-8")
    assert "10.9.8.7" in assets_csv
    assert ",PR," in assets_csv
