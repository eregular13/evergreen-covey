"""File-true GRC leave-behinds. No RiskReady POST. No live OpenGRC/Probo."""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from covey.errors import ExportError, GateError

CISO_ASSET_HEADER = [
    "ref_id",
    "name",
    "description",
    "domain",
    "type",
    "reference_link",
    "observation",
    "filtering_labels",
    "parent_assets",
]
CISO_EVIDENCE_HEADER = ["name", "description"]
CISO_FINDING_HEADER = [
    "ref_id",
    "name",
    "description",
    "severity",
    "status",
    "filtering_labels",
]
CISO_POAM_HEADER = [
    "weakness",
    "asset",
    "severity",
    "cpg",
    "csf",
    "action",
    "status",
]
CISO_CONTROL_HEADER = [
    "ref_id",
    "name",
    "description",
    "domain",
    "status",
    "category",
    "priority",
    "csf_function",
]
CISO_VULN_HEADER = [
    "ref_id",
    "name",
    "description",
    "status",
    "severity",
    "assets",
    "applied_controls",
]
CISO_SCENARIO_HEADER = [
    "ref_id",
    "assets",
    "threats",
    "name",
    "description",
    "existing_controls",
    "current_impact",
    "current_proba",
    "current_risk",
    "additional_controls",
    "residual_impact",
    "residual_proba",
    "residual_risk",
    "treatment",
]
# LeeMangold/OpenGRC AssetExporter / RiskExporter labels (Data Manager reimport).
OPENGRC_ASSET_HEADER = [
    "Asset Tag",
    "Name",
    "Hostname",
    "IP Address",
    "Asset Type",
    "Status",
    "Notes",
    "Active",
]
OPENGRC_RISK_HEADER = [
    "Code",
    "Name",
    "Description",
    "Status",
    "Inherent Likelihood",
    "Inherent Impact",
    "Inherent Risk",
    "Residual Likelihood",
    "Residual Impact",
    "Residual Risk",
    "Scope",
    "Active",
]
PROBO_BATCH = 25
PROBO_REFUSED_NET = ipaddress.ip_network("192.168.10.0/24")
PROBO_REFUSED_HOST = ipaddress.ip_address("192.168.10.130")
Poster = Callable[..., int]


def _write_csv(
    path: Path,
    header: list[str],
    rows: list[dict[str, str]],
    *,
    delimiter: str = ",",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=header, extrasaction="ignore", delimiter=delimiter
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in header})


def _scenario_level(severity: str) -> str:
    return {
        "info": "Low",
        "low": "Low",
        "medium": "Moderate",
        "high": "High",
        "critical": "Very High",
    }.get((severity or "").lower(), "Low")


def _control_priority(severity: str) -> str:
    return {"critical": "1", "high": "1", "medium": "2", "low": "3"}.get(
        (severity or "").lower(), "3"
    )


def _csf_function(csf: list[str]) -> str:
    blob = " ".join(csf).upper()
    if blob.startswith("DE") or "DE." in blob:
        return "detect"
    if blob.startswith("RS") or "RS." in blob:
        return "respond"
    if blob.startswith("RC") or "RC." in blob:
        return "recover"
    if blob.startswith("ID") or "ID." in blob:
        return "identify"
    return "protect"


def _probo_refused(address: str) -> bool:
    text = (address or "").strip()
    if not text:
        return False
    if text == "192.168.10.0/24":
        return True
    try:
        addr = ipaddress.ip_address(text.split("/")[0])
    except ValueError:
        return False
    return addr in PROBO_REFUSED_NET or addr == PROBO_REFUSED_HOST


def write_ciso(
    dest: Path,
    *,
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    asset_rows = []
    for index, row in enumerate(assets, start=1):
        name = str(row.get("address") or row.get("name") or f"asset-{index}")
        kind = str(row.get("kind") or "host")
        ref = f"COV-{kind[:2].upper()}-{index:04d}"
        desc = kind
        if kind == "service":
            desc = f"{row.get('protocol')}/{row.get('port')} {row.get('service') or ''}".strip()
        asset_rows.append(
            {
                "ref_id": ref,
                "name": name,
                "description": desc,
                "domain": "default",
                "type": "PR" if kind == "host" else "SP",
                "reference_link": "",
                "observation": "",
                "filtering_labels": str(row.get("adapter") or "covey"),
                "parent_assets": "",
            }
        )
    finding_rows = []
    poam_rows = []
    for index, row in enumerate(findings, start=1):
        name = str(row.get("title") or row.get("name") or f"finding-{index}")
        sev = str(row.get("severity") or "info")
        if sev == "info" and row.get("claim") == "open_port_observed":
            continue
        finding_rows.append(
            {
                "ref_id": f"COV-F-{index:04d}",
                "name": name,
                "description": str(row.get("action") or row.get("honesty") or name),
                "severity": sev if sev != "info" else "low",
                "status": "open",
                "filtering_labels": str(row.get("claim") or ""),
                "address": str(row.get("address") or ""),
                "recommendation": str(row.get("action") or ""),
                "observation": str(row.get("honesty") or ""),
            }
        )
        claim = str(row.get("claim") or "")
        if claim == "misconfig_observed":
            weakness = str(row.get("weakness") or "UNMAPPED")
            if not row.get("mapped"):
                weakness = "UNMAPPED"
            poam_rows.append(
                {
                    "weakness": weakness,
                    "asset": str(row.get("address") or ""),
                    "severity": sev,
                    "cpg": ";".join(row.get("cpg") or []),
                    "csf": ";".join(row.get("csf") or []),
                    "action": str(row.get("action") or row.get("reason") or ""),
                    "status": "open",
                }
            )
    evidence_rows = [
        {
            "name": str(item.get("src") or item.get("name") or "evidence"),
            "description": str(item.get("path") or item.get("reason") or "covey evidence"),
        }
        for item in evidence
        if item.get("copied") or item.get("src")
    ]
    if not evidence_rows:
        evidence_rows = [{"name": "covey-run", "description": "Covey pack_drop evidence"}]
    control_rows = []
    seen_ctl: set[str] = set()
    for index, row in enumerate(findings, start=1):
        if not row.get("mapped") or row.get("claim") != "misconfig_observed":
            continue
        ref = f"COV-C-{index:04d}"
        if ref in seen_ctl:
            continue
        seen_ctl.add(ref)
        control_rows.append(
            {
                "ref_id": ref,
                "name": str(row.get("weakness") or row.get("title") or ref),
                "description": str(row.get("action") or ""),
                "domain": "default",
                "status": "to_do",
                "category": "technical",
                "priority": _control_priority(str(row.get("severity") or "")),
                "csf_function": _csf_function(list(row.get("csf") or [])),
            }
        )
    vuln_rows = []
    for index, row in enumerate(findings, start=1):
        cve = str(row.get("cve") or "")
        if row.get("claim") != "vuln_ingested" or not cve.upper().startswith("CVE-"):
            continue
        vuln_rows.append(
            {
                "ref_id": cve.upper(),
                "name": cve.upper(),
                "description": str(row.get("action") or row.get("honesty") or cve),
                "status": "Exploitable",
                "severity": "High",
                "assets": str(row.get("address") or ""),
                "applied_controls": "",
            }
        )
    scenario_rows = []
    for index, row in enumerate(findings, start=1):
        if row.get("claim") != "misconfig_observed" or not row.get("mapped"):
            continue
        level = _scenario_level(str(row.get("severity") or ""))
        scenario_rows.append(
            {
                "ref_id": f"RSK-{index:04d}",
                "assets": str(row.get("address") or ""),
                "threats": str(row.get("adapter") or "covey"),
                "name": str(row.get("title") or row.get("name") or ""),
                "description": str(row.get("action") or row.get("honesty") or ""),
                "existing_controls": "",
                "current_impact": level,
                "current_proba": level,
                "current_risk": level,
                "additional_controls": f"COV-C-{index:04d}",
                "residual_impact": level,
                "residual_proba": level,
                "residual_risk": level,
                "treatment": "mitigate",
            }
        )
    _write_csv(dest / "assets.csv", CISO_ASSET_HEADER, asset_rows)
    _write_csv(dest / "evidences.csv", CISO_EVIDENCE_HEADER, evidence_rows)
    _write_csv(dest / "findings.csv", CISO_FINDING_HEADER, finding_rows)
    _write_csv(dest / "applied_controls.csv", CISO_CONTROL_HEADER, control_rows)
    _write_csv(dest / "vulnerabilities.csv", CISO_VULN_HEADER, vuln_rows)
    _write_csv(
        dest / "risk_scenarios.csv",
        CISO_SCENARIO_HEADER,
        scenario_rows,
        delimiter=";",
    )
    _write_csv(dest / "poam.csv", CISO_POAM_HEADER, poam_rows)
    return {
        "dir": str(dest),
        "assets": len(asset_rows),
        "findings": len(finding_rows),
        "poam": len(poam_rows),
        "controls": len(control_rows),
        "vulnerabilities": len(vuln_rows),
        "asset_rows": asset_rows,
        "evidence_rows": evidence_rows,
        "finding_rows": finding_rows,
    }


def write_opengrc(
    dest: Path,
    *,
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    asset_rows = []
    seen: set[str] = set()
    for index, row in enumerate(assets, start=1):
        name = str(row.get("address") or row.get("name") or f"asset-{index}")
        if name in seen:
            continue
        seen.add(name)
        kind = str(row.get("kind") or "host")
        asset_rows.append(
            {
                "Asset Tag": f"COV-{index:04d}",
                "Name": name[:200],
                "Hostname": name[:200],
                "IP Address": name if kind in {"host", "service"} else "",
                "Asset Type": "Host" if kind == "host" else "Service",
                "Status": "Active",
                "Notes": kind,
                "Active": "true",
            }
        )
    risk_rows = []
    for index, row in enumerate(findings, start=1):
        if row.get("claim") == "open_port_observed":
            continue
        title = str(row.get("title") or row.get("name") or "")[:200]
        risk_rows.append(
            {
                "Code": f"RSK-{index:04d}",
                "Name": title,
                "Description": str(row.get("honesty") or row.get("action") or "")[:500],
                "Status": "Open",
                "Inherent Likelihood": _scenario_level(str(row.get("severity") or "")),
                "Inherent Impact": _scenario_level(str(row.get("severity") or "")),
                "Inherent Risk": _scenario_level(str(row.get("severity") or "")),
                "Residual Likelihood": "",
                "Residual Impact": "",
                "Residual Risk": "",
                "Scope": "covey-surface",
                "Active": "true",
            }
        )
    _write_csv(dest / "assets.csv", OPENGRC_ASSET_HEADER, asset_rows)
    _write_csv(dest / "risks.csv", OPENGRC_RISK_HEADER, risk_rows)
    (dest / "MAPPING.md").write_text(
        "# OpenGRC CSV mapping\n\n"
        "Data Manager import. Live POST refused: create-body is POST /api/risks "
        "(title, description, likelihood, impact; Sanctum). Covey never POSTs /api/risks.\n",
        encoding="utf-8",
    )
    return {"dir": str(dest), "assets": len(asset_rows), "risks": len(risk_rows)}


def _probo_priority(severity: object) -> str:
    key = str(severity or "").strip().lower()
    if key in {"high", "critical"}:
        return "HIGH"
    if key in {"low", "info"}:
        return "LOW"
    return "MEDIUM"


def _probo_description(row: dict[str, Any]) -> str:
    title = str(row.get("title") or row.get("name") or "").strip()
    desc = str(
        row.get("description") or row.get("action") or row.get("honesty") or ""
    ).strip()
    if title and desc:
        text = f"{title}: {desc}"
    else:
        text = title or desc
    return text[:500]


def write_probo(dest: Path, *, findings: list[dict[str, Any]]) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    items = []
    for row in findings:
        if row.get("claim") == "open_port_observed":
            continue
        address = str(row.get("address") or "")
        if _probo_refused(address):
            continue
        description = _probo_description(row)
        if not description:
            continue
        items.append(
            {
                "operation": "createFinding",
                "kind": "OBSERVATION",
                "description": description,
                "status": "OPEN",
                "priority": _probo_priority(row.get("priority") or row.get("severity")),
                "source": "evergreen-covey",
                "assets": [address] if address else [],
            }
        )
    batches = [items[i : i + PROBO_BATCH] for i in range(0, len(items), PROBO_BATCH)] or [[]]
    payload = {
        "kind": "probo-finding-plan",
        "note": (
            "dry-run plan. No createRisk. Batch size 25. "
            "Live is createFinding(CreateFindingInput) after "
            "PROBO_TENANT + PROBO_TOKEN + PROBO_ORGANIZATION + push/GATE_PROBO. "
            "Kind OBSERVATION — not a nonconformity claim."
        ),
        "batch_size": PROBO_BATCH,
        "batches": [
            {"offset": index * PROBO_BATCH, "items": batch}
            for index, batch in enumerate(batches)
        ],
        "count": len(items),
        "items": items,
    }
    path = dest / "findings_plan.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return {"plan_json": str(path), "count": len(items), "batches": len(batches), "items": items}


def refuse_riskready() -> None:
    raise ExportError("WRAP_DEAD: RiskReady stay-out. No HTTP. File drop only.")


def refuse_opengrc_live() -> None:
    raise GateError(
        "OpenGRC live POST refused: LeeMangold/OpenGRC create-body is "
        "POST /api/risks (title, description, likelihood, impact; Sanctum). "
        "Covey never POSTs /api/risks. File-true Data Manager CSVs only. No socket."
    )


def _gate_dir(push_dir: Path | None, cwd: Path | None) -> Path:
    if push_dir is not None:
        return Path(push_dir)
    override = os.environ.get("COVEY_PUSH_DIR", "").strip()
    if override:
        return Path(override)
    return (cwd or Path.cwd()) / "push"


def require_ciso_gate(*, cwd: Path | None = None, push_dir: Path | None = None) -> Path:
    url = os.environ.get("CISO_URL", "").strip()
    token = os.environ.get("CISO_TOKEN", "").strip()
    folder = _gate_dir(push_dir, cwd)
    gate = folder / "GATE_CISO"
    missing: list[str] = []
    if not url:
        missing.append("CISO_URL")
    if not token:
        missing.append("CISO_TOKEN")
    if not gate.is_file():
        missing.append(str(gate))
    if missing:
        raise GateError(
            "CISO live refused: dual-gate failed ("
            + ", ".join(missing)
            + "). No socket."
        )
    return gate


def require_probo_gate(*, cwd: Path | None = None, push_dir: Path | None = None) -> Path:
    tenant = os.environ.get("PROBO_TENANT", "").strip()
    token = os.environ.get("PROBO_TOKEN", "").strip()
    organization = os.environ.get("PROBO_ORGANIZATION", "").strip()
    folder = _gate_dir(push_dir, cwd)
    gate = folder / "GATE_PROBO"
    missing: list[str] = []
    if not tenant:
        missing.append("PROBO_TENANT")
    if not token:
        missing.append("PROBO_TOKEN")
    if not organization:
        missing.append("PROBO_ORGANIZATION")
    if not gate.is_file():
        missing.append(str(gate))
    if missing:
        raise GateError(
            "Probo live refused: tenant/gate missing ("
            + ", ".join(missing)
            + "). http=false"
        )
    return gate


def _default_poster(url: str, *, data: bytes, headers: dict[str, str], timeout: float = 10) -> dict[str, Any]:
    if "/api/risks" in url:
        raise GateError("refused POST /api/risks")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = int(getattr(resp, "status", 200) or 200)
        raw = resp.read()
        body: Any = {}
        if raw:
            try:
                body = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                body = {}
        return {"status": status, "body": body}


def _default_getter(url: str, *, headers: dict[str, str], timeout: float = 10) -> dict[str, Any]:
    if "/api/risks" in url:
        raise GateError("refused POST /api/risks")
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if not raw:
            return {}
        try:
            body = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return body if isinstance(body, dict) else {}


def _posted_id(result: object) -> str | None:
    if not isinstance(result, dict):
        return None
    body = result.get("body") if "body" in result else result
    if not isinstance(body, dict):
        return None
    value = body.get("id")
    text = str(value or "").strip()
    return text if text and _is_uuid(text) else None


def push_ciso_assets_evidences(
    *,
    assets: list[dict[str, str]],
    evidences: list[dict[str, str]],
    cwd: Path | None = None,
    push_dir: Path | None = None,
    poster: Poster | None = None,
    getter: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """POST /api/assets/ and /api/evidences/ only. Dual-gate first. No /api/risks."""
    require_ciso_gate(cwd=cwd, push_dir=push_dir)
    base = os.environ["CISO_URL"].rstrip("/")
    if base.endswith("/api"):
        root = base
    else:
        root = base + "/api"
    token = os.environ["CISO_TOKEN"]
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }
    send = poster or _default_poster
    posted = 0
    asset_ids: list[str] = []
    evidence_ids: list[str] = []
    posted_assets: list[dict[str, str]] = []
    folder = os.environ.get("CISO_FOLDER", "").strip()
    folder_ok = folder if folder and _is_uuid(folder) else ""
    asset_rows = [row for row in assets if str(row.get("type") or "") == "PR"]
    asset_rows.extend(row for row in assets if str(row.get("type") or "") != "PR")
    seen_asset_names: set[str] = set()
    seen_evidence_names: set[str] = set()
    for path, rows in (("/assets/", asset_rows), ("/evidences/", evidences)):
        for row in rows:
            payload: dict[str, Any] = {
                "name": row.get("name") or row.get("ref_id") or "covey",
                "description": row.get("description") or "",
            }
            if path == "/assets/" and row.get("type"):
                payload["type"] = row["type"]
            row_folder = str(row.get("folder") or folder_ok).strip()
            if path in {"/assets/", "/evidences/"} and row_folder and _is_uuid(row_folder):
                payload["folder"] = row_folder
            name = str(payload["name"])
            if path == "/assets/":
                if name in seen_asset_names:
                    continue
                seen_asset_names.add(name)
            if path == "/evidences/":
                if name in seen_evidence_names:
                    continue
                seen_evidence_names.add(name)
            body = json.dumps(payload).encode("utf-8")
            try:
                result = send(root + path, data=body, headers=headers, timeout=10)
            except urllib.error.HTTPError as exc:
                if exc.code in {400, 409}:
                    if path == "/assets/":
                        reused = _ciso_asset_id_by_name(
                            name,
                            root=root,
                            headers=headers,
                            getter=getter,
                        )
                        if reused:
                            asset_ids.append(reused)
                            posted_assets.append(
                                {
                                    "name": name,
                                    "id": reused,
                                    "type": str(payload.get("type") or ""),
                                }
                            )
                    if path == "/evidences/":
                        reused = _ciso_evidence_id_by_name(
                            name,
                            root=root,
                            headers=headers,
                            getter=getter,
                        )
                        if reused:
                            evidence_ids.append(reused)
                    continue
                raise
            posted += 1
            found = _posted_id(result)
            if path == "/assets/" and found:
                asset_ids.append(found)
                posted_assets.append(
                    {
                        "name": name,
                        "id": found,
                        "type": str(payload.get("type") or ""),
                    }
                )
            if path == "/evidences/" and found:
                evidence_ids.append(found)
    return {
        "posted": posted,
        "http": True,
        "paths": ["/api/assets/", "/api/evidences/"],
        "asset_ids": asset_ids,
        "evidence_ids": evidence_ids,
        "posted_assets": posted_assets,
    }


def _ciso_root() -> str:
    base = os.environ["CISO_URL"].rstrip("/")
    return base if base.endswith("/api") else base + "/api"


def _is_uuid(text: str) -> bool:
    parts = text.split("-")
    if len(parts) != 5:
        return False
    return all(part.isalnum() for part in parts) and [len(p) for p in parts] == [8, 4, 4, 4, 12]


def ciso_named_id_from_list(body: dict[str, Any] | None, name: str) -> str:
    """Reuse an existing CISO object id. Exact name match only. Never invent.

    Multiple exact hits are ambiguous — do not pick the first UUID.
    """
    want = str(name or "").strip()
    if not want or not isinstance(body, dict):
        return ""
    rows = body.get("results")
    if not isinstance(rows, list):
        rows = [body]
    hits: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("name") or "").strip() != want:
            continue
        text = str(row.get("id") or "").strip()
        if text and _is_uuid(text) and text not in hits:
            hits.append(text)
    if len(hits) == 1:
        return hits[0]
    return ""


def _ciso_evidence_id_by_name(
    name: str,
    *,
    root: str,
    headers: dict[str, str],
    getter: Callable[..., dict[str, Any]] | None,
) -> str:
    want = str(name or "").strip()
    if not want:
        return ""
    get = getter or _default_getter
    query = urllib.parse.urlencode({"name": want})
    try:
        listed = get(f"{root}/evidences/?{query}", headers=headers, timeout=10)
    except Exception:
        return ""
    return ciso_named_id_from_list(listed if isinstance(listed, dict) else {}, want)


def ciso_evidence_id_from_list(body: dict[str, Any] | None, name: str) -> str:
    """Reuse an existing Evidence id. Exact name match only. Never invent."""
    return ciso_named_id_from_list(body, name)


def ciso_asset_id_from_list(body: dict[str, Any] | None, name: str) -> str:
    """Reuse an existing Asset id. Exact name match only. Never invent."""
    return ciso_named_id_from_list(body, name)


def _ciso_asset_id_by_name(
    name: str,
    *,
    root: str,
    headers: dict[str, str],
    getter: Callable[..., dict[str, Any]] | None,
) -> str:
    want = str(name or "").strip()
    if not want:
        return ""
    get = getter or _default_getter
    query = urllib.parse.urlencode({"name": want})
    try:
        listed = get(f"{root}/assets/?{query}", headers=headers, timeout=10)
    except Exception:
        return ""
    return ciso_asset_id_from_list(listed if isinstance(listed, dict) else {}, want)


# CISO Finding.severity is SmallIntegerField (FindingWriteSerializer). Extra Import CSVs stay strings.
CISO_SEVERITY_INT = {
    "undefined": -1,
    "--": -1,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
CISO_STATUS_LIVE = {
    "open": "identified",
    "opened": "identified",
    "new": "identified",
    "identified": "identified",
    "confirmed": "confirmed",
    "dismissed": "dismissed",
    "assigned": "assigned",
    "in_progress": "in_progress",
    "mitigated": "mitigated",
    "resolved": "resolved",
    "closed": "closed",
    "deprecated": "deprecated",
    "--": "--",
}


def _ciso_severity(value: object) -> int:
    if isinstance(value, bool):
        return CISO_SEVERITY_INT["undefined"]
    if isinstance(value, int) and value in {-1, 0, 1, 2, 3, 4}:
        return value
    key = str(value or "").strip().lower()
    return CISO_SEVERITY_INT.get(key, CISO_SEVERITY_INT["undefined"])


def _ciso_status(value: object) -> str:
    key = str(value or "").strip().lower()
    if not key:
        return "--"
    return CISO_STATUS_LIVE.get(key, "identified")


def push_ciso_findings(
    *,
    findings: list[dict[str, str]],
    cwd: Path | None = None,
    push_dir: Path | None = None,
    poster: Poster | None = None,
) -> dict[str, Any]:
    """POST /api/findings/ only. Requires operator FindingsAssessment UUID. Never invents it."""
    require_ciso_gate(cwd=cwd, push_dir=push_dir)
    assessment = os.environ.get("CISO_FINDINGS_ASSESSMENT", "").strip()
    if not assessment or not _is_uuid(assessment):
        raise GateError(
            "CISO findings live refused: CISO_FINDINGS_ASSESSMENT must be an operator UUID. "
            "No invented FindingsAssessment. No socket."
        )
    root = _ciso_root()
    token = os.environ["CISO_TOKEN"]
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }
    send = poster or _default_poster
    posted = 0
    finding_ids: list[str] = []
    posted_rows: list[dict[str, Any]] = []
    for row in findings:
        name = str(row.get("name") or row.get("title") or "").strip()
        if not name:
            continue
        payload = {
            "name": name,
            "description": str(row.get("description") or ""),
            "ref_id": str(row.get("ref_id") or ""),
            "severity": _ciso_severity(row.get("severity")),
            "status": _ciso_status(row.get("status")),
            "findings_assessment": assessment,
        }
        rec = str(row.get("recommendation") or row.get("action") or "").strip()
        if rec:
            payload["recommendation"] = rec
        obs = str(row.get("observation") or row.get("honesty") or "").strip()
        if obs:
            payload["observation"] = obs
        asset = str(row.get("asset") or "").strip()
        if asset and _is_uuid(asset):
            payload["asset"] = asset
        evidence_ids = []
        raw_evidences = row.get("evidences") or []
        if isinstance(raw_evidences, str):
            raw_evidences = [raw_evidences]
        for item in raw_evidences:
            text = str(item or "").strip()
            if text and _is_uuid(text):
                evidence_ids.append(text)
        if evidence_ids:
            payload["evidences"] = evidence_ids
        body = json.dumps(payload).encode("utf-8")
        try:
            result = send(root + "/findings/", data=body, headers=headers, timeout=10)
        except urllib.error.HTTPError as exc:
            if exc.code in {400, 409}:
                continue
            raise
        posted += 1
        found = _posted_id(result)
        if found:
            finding_ids.append(found)
            posted_rows.append(
                {
                    "id": found,
                    "name": name,
                    "asset": str(payload.get("asset") or ""),
                    "evidences": list(payload.get("evidences") or []),
                    "recommendation": str(payload.get("recommendation") or ""),
                    "observation": str(payload.get("observation") or ""),
                }
            )
    return {
        "posted": posted,
        "http": True,
        "paths": ["/api/findings/"],
        "finding_ids": finding_ids,
        "posted_rows": posted_rows,
    }


def ciso_finding_asset_id(body: dict[str, Any] | None) -> str:
    """FindingReadSerializer returns asset as {id, str}. Write path is a UUID string."""
    if not isinstance(body, dict):
        return ""
    asset = body.get("asset")
    if isinstance(asset, dict):
        text = str(asset.get("id") or "").strip()
    else:
        text = str(asset or "").strip()
    return text if text and _is_uuid(text) else ""


def ciso_finding_evidence_ids(body: dict[str, Any] | None) -> list[str]:
    """FindingReadSerializer returns evidences as [{id, str}, ...]. Write path is UUID strings."""
    if not isinstance(body, dict):
        return []
    raw = body.get("evidences")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            text = str(item.get("id") or "").strip()
        else:
            text = str(item or "").strip()
        if text and _is_uuid(text) and text not in out:
            out.append(text)
    return out


def fetch_ciso_finding(
    finding_id: str,
    *,
    cwd: Path | None = None,
    push_dir: Path | None = None,
    getter: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """GET /api/findings/{id}/ after dual-gate. No /api/risks. No invented ids."""
    require_ciso_gate(cwd=cwd, push_dir=push_dir)
    text = str(finding_id or "").strip()
    if not _is_uuid(text):
        raise GateError(
            "CISO finding read-back refused: id is not a UUID. No socket."
        )
    root = _ciso_root()
    token = os.environ["CISO_TOKEN"]
    headers = {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
    }
    get = getter or _default_getter
    body = get(f"{root}/findings/{text}/", headers=headers, timeout=10)
    if not isinstance(body, dict) or str(body.get("id") or "") != text:
        raise GateError(
            "CISO finding read-back failed: tenant did not return this finding id."
        )
    return body


def _probo_posted_id(result: object) -> str | None:
    if not isinstance(result, dict):
        return None
    body = result.get("body") if "body" in result else result
    if not isinstance(body, dict):
        return None
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    if not isinstance(data, dict):
        return None
    edge = data.get("createFinding")
    if not isinstance(edge, dict):
        return None
    node = (edge.get("findingEdge") or {}).get("node") if isinstance(edge.get("findingEdge"), dict) else None
    if not isinstance(node, dict):
        return None
    text = str(node.get("id") or "").strip()
    return text or None


def push_probo_findings(
    *,
    findings: list[dict[str, Any]],
    cwd: Path | None = None,
    push_dir: Path | None = None,
    poster: Poster | None = None,
) -> dict[str, Any]:
    """POST GraphQL createFinding. Dual-gate. No createRisk. No office LAN default."""
    require_probo_gate(cwd=cwd, push_dir=push_dir)
    send = poster or _default_poster
    token = os.environ["PROBO_TOKEN"]
    organization = os.environ["PROBO_ORGANIZATION"]
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    posted = 0
    finding_ids: list[str] = []
    posted_rows: list[dict[str, Any]] = []
    query = (
        "mutation CreateFinding($input: CreateFindingInput!) { "
        "createFinding(input: $input) { findingEdge { node { id } } } }"
    )
    url = _probo_graphql_url()
    for row in findings:
        description = _probo_description(row)
        if not description:
            continue
        assets = row.get("assets") or []
        if any(_probo_refused(str(item)) for item in assets):
            continue
        payload = {
            "query": query,
            "variables": {
                "input": {
                    "organizationId": organization,
                    "kind": "OBSERVATION",
                    "description": description,
                    "status": "OPEN",
                    "priority": _probo_priority(row.get("priority") or row.get("severity")),
                    "source": "evergreen-covey",
                }
            },
        }
        result = send(url, data=json.dumps(payload).encode("utf-8"), headers=headers, timeout=10)
        body = result.get("body") if isinstance(result, dict) and "body" in result else result
        if isinstance(body, dict) and body.get("errors"):
            raise GateError("Probo createFinding failed: GraphQL errors. No claim.")
        posted += 1
        found = _probo_posted_id(result)
        if found:
            finding_ids.append(found)
            posted_rows.append({"id": found, "description": description})
    return {
        "posted": posted,
        "http": True,
        "operation": "createFinding",
        "finding_ids": finding_ids,
        "posted_rows": posted_rows,
    }


def _probo_graphql_url() -> str:
    tenant = os.environ["PROBO_TENANT"].rstrip("/")
    if "graphql" in tenant.lower():
        return tenant
    return tenant + "/api/console/v1/graphql"


def _probo_node(result: object) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None
    body = result.get("body") if "body" in result else result
    if not isinstance(body, dict):
        return None
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    if not isinstance(data, dict):
        return None
    node = data.get("node")
    return node if isinstance(node, dict) else None


def fetch_probo_finding(
    finding_id: str,
    *,
    cwd: Path | None = None,
    push_dir: Path | None = None,
    poster: Poster | None = None,
) -> dict[str, Any]:
    """GraphQL Query.node ... on Finding after dual-gate. No createRisk."""
    require_probo_gate(cwd=cwd, push_dir=push_dir)
    text = str(finding_id or "").strip()
    if not text:
        raise GateError("Probo finding read-back refused: empty id. No socket.")
    url = _probo_graphql_url()
    token = os.environ["PROBO_TOKEN"]
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    query = (
        "query Finding($id: ID!) { node(id: $id) { "
        "... on Finding { id description source kind status priority } } }"
    )
    payload = {"query": query, "variables": {"id": text}}
    send = poster or _default_poster
    result = send(url, data=json.dumps(payload).encode("utf-8"), headers=headers, timeout=10)
    body = result.get("body") if isinstance(result, dict) and "body" in result else result
    if isinstance(body, dict) and body.get("errors"):
        raise GateError("Probo finding read-back failed: GraphQL errors. No claim.")
    node = _probo_node(result)
    if not isinstance(node, dict) or str(node.get("id") or "").strip() != text:
        raise GateError(
            "Probo finding read-back failed: tenant did not return this finding id."
        )
    return node
