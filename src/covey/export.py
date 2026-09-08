"""Export Covey run artifacts into a collector pack_drop (file_drop only)."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from covey import __version__
from covey.adapters.common import parse_masscan_json, unique_ipv4s
from covey.adapters.nmap import (
    parse_gnmap_live_hosts,
    parse_gnmap_services,
    parse_nmap_xml_live_hosts,
    parse_nmap_xml_meta,
    parse_nmap_xml_services,
)
from covey.adapters.registry import adapter_for
from covey.errors import ExportError

PACK_DIR_NAME = "pack_drop"
SCHEMA_ID = "evergreen.pack_drop.v1"
HONESTY_LINE = (
    "surface map ≠ honeypot validated ≠ control operating effectiveness"
)
DEFAULT_MAX_EVIDENCE_BYTES = 256 * 1024
EVIDENCE_NAMES = ("scan.xml", "scan.gnmap", "scan.json")
POINTER_ONLY_NAMES = ("scan.nmap", "stdout.log", "stderr.log")

HONESTY = {
    "surface_map": True,
    "honeypot_validated": False,
    "control_operating_effectiveness": False,
    "note": HONESTY_LINE,
}

NOT_CLAIMED = (
    "control_failure",
    "control_operating_effectiveness",
    "honeypot_validated",
    "vulnerability",
    "riskready_post",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ExportError(f"unreadable JSON {path}: {exc}") from exc
    return loaded if isinstance(loaded, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_versions(cwd: Path) -> dict[str, Any]:
    versions: dict[str, Any] = {}
    git = shutil.which("git")
    if not git:
        return versions
    try:
        commit = subprocess.run(
            [git, "rev-parse", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if commit.returncode == 0 and commit.stdout.strip():
            versions["commit"] = commit.stdout.strip()
        dirty = subprocess.run(
            [git, "status", "--porcelain"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if dirty.returncode == 0:
            versions["dirty"] = bool(dirty.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return versions
    return versions


def resolve_paths(out: Path | str) -> tuple[Path, Path]:
    """``--out`` is the prove/run root; pack lands in ``<out>/pack_drop/``.

    If ``--out`` is already named ``pack_drop``, write there and treat the
    parent as the run root.
    """
    raw = Path(out)
    if raw.name == PACK_DIR_NAME:
        return raw.parent, raw
    return raw, raw / PACK_DIR_NAME


def _shard_dirs(run_root: Path, report: dict[str, Any]) -> list[Path]:
    dirs: list[Path] = []
    seen: set[Path] = set()
    for stage in ("pass1", "pass2"):
        for item in report.get(stage) or []:
            if not isinstance(item, dict):
                continue
            raw = item.get("artifact_dir")
            if not raw:
                continue
            path = Path(str(raw))
            if not path.is_absolute():
                path = run_root / path
            if path.is_dir() and path not in seen:
                seen.add(path)
                dirs.append(path)
    shards = run_root / "shards"
    if shards.is_dir():
        for path in sorted(p for p in shards.iterdir() if p.is_dir()):
            if path not in seen:
                seen.add(path)
                dirs.append(path)
    return dirs


def _parse_hosts(directory: Path, adapter_name: str) -> list[str]:
    xml_path = directory / "scan.xml"
    if xml_path.is_file():
        try:
            return parse_nmap_xml_live_hosts(xml_path)
        except Exception:
            pass
    gnmap_path = directory / "scan.gnmap"
    if gnmap_path.is_file():
        return parse_gnmap_live_hosts(gnmap_path)
    json_path = directory / "scan.json"
    if json_path.is_file():
        text = json_path.read_text(encoding="utf-8", errors="replace")
        return parse_masscan_json(text) or unique_ipv4s(text)
    live_path = directory / "live_hosts.json"
    if live_path.is_file():
        try:
            loaded = json.loads(live_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, list):
            return [str(item) for item in loaded if item]
    try:
        plugin = adapter_for(adapter_name)
    except Exception:
        return []
    try:
        return list(plugin.parse_live_hosts(directory))
    except Exception:
        return []


def _parse_services(directory: Path) -> list[dict[str, str]]:
    xml_path = directory / "scan.xml"
    if xml_path.is_file():
        try:
            found = parse_nmap_xml_services(xml_path)
            if found:
                return found
        except Exception:
            pass
    gnmap_path = directory / "scan.gnmap"
    if gnmap_path.is_file():
        return parse_gnmap_services(gnmap_path)
    json_path = directory / "scan.json"
    if not json_path.is_file():
        return []
    try:
        blob = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(blob, list):
        return []
    services: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in blob:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not isinstance(ip, str) or not ip:
            continue
        for port in item.get("ports") or []:
            if not isinstance(port, dict):
                continue
            status = str(port.get("status") or "").lower()
            if status not in {"open", "open|filtered"}:
                continue
            if status != "open":
                continue
            portid = str(port.get("port") or "").strip()
            protocol = str(port.get("proto") or port.get("protocol") or "tcp").lower()
            if not portid:
                continue
            key = (ip, protocol, portid)
            if key in seen:
                continue
            seen.add(key)
            services.append(
                {
                    "address": ip,
                    "protocol": protocol,
                    "port": portid,
                    "state": "open",
                    "service": str(port.get("service") or ""),
                }
            )
    return services


def _tool_version(shard_dirs: list[Path], report: dict[str, Any]) -> str:
    for directory in shard_dirs:
        xml_path = directory / "scan.xml"
        if not xml_path.is_file():
            continue
        meta = parse_nmap_xml_meta(xml_path)
        scanner = meta.get("scanner") or "nmap"
        version = meta.get("version")
        if version:
            return f"{scanner} {version}"
        if scanner:
            return scanner
    return str(report.get("exec") or "")


def _run_id(plan: dict[str, Any], prove: dict[str, Any]) -> str:
    material = json.dumps(
        {
            "adapter": plan.get("adapter") or prove.get("exec"),
            "created_at": plan.get("created_at"),
            "signer": plan.get("signer"),
            "shards": plan.get("shards") or prove.get("shards"),
        },
        sort_keys=True,
        default=str,
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    adapter = str(plan.get("adapter") or "covey")
    return f"{adapter}-{digest}"


def _build_assets(
    *,
    hosts: list[str],
    services: list[dict[str, str]],
    adapter: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    for host in hosts:
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        rows.append(
            {
                "kind": "host",
                "address": host,
                "state": "up",
                "source": "parse_live_hosts",
                "adapter": adapter,
            }
        )
    seen_svc: set[tuple[str, str, str]] = set()
    for item in services:
        key = (item["address"], item["protocol"], item["port"])
        if key in seen_svc:
            continue
        seen_svc.add(key)
        if item["address"] not in seen_hosts:
            seen_hosts.add(item["address"])
            rows.append(
                {
                    "kind": "host",
                    "address": item["address"],
                    "state": "up",
                    "source": "pass2",
                    "adapter": adapter,
                }
            )
        row = {
            "kind": "service",
            "address": item["address"],
            "port": int(item["port"]) if item["port"].isdigit() else item["port"],
            "protocol": item["protocol"],
            "state": "open",
            "source": "pass2",
            "adapter": adapter,
        }
        if item.get("service"):
            row["service"] = item["service"]
        if item.get("product"):
            row["product"] = item["product"]
        rows.append(row)
    return rows


def _build_findings(
    services: list[dict[str, str]], *, adapter: str
) -> list[dict[str, Any]]:
    """Conservative observations only. Never a control-failure claim."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in services:
        if item.get("state") != "open":
            continue
        key = (item["address"], item["protocol"], item["port"])
        if key in seen:
            continue
        seen.add(key)
        title = f"Open {item['protocol'].upper()}/{item['port']} observed"
        if item.get("service"):
            title = f"Open {item['service']} on {item['protocol']}/{item['port']} observed"
        findings.append(
            {
                "kind": "observation",
                "title": title,
                "severity": "info",
                "claim": "open_port_observed",
                "address": item["address"],
                "port": int(item["port"]) if item["port"].isdigit() else item["port"],
                "protocol": item["protocol"],
                "service": item.get("service") or "",
                "adapter": adapter,
                "honesty": HONESTY_LINE,
                "not_claimed": list(NOT_CLAIMED),
            }
        )
    return findings


def _copy_or_pointer(
    src: Path,
    dest_dir: Path,
    *,
    rel_name: str,
    max_bytes: int,
) -> dict[str, Any]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    size = src.stat().st_size
    record = {
        "src": src.name,
        "bytes": size,
        "sha256": _sha256(src),
        "worker": src.parent.name,
    }
    if size <= max_bytes:
        dest = dest_dir / rel_name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        record["path"] = str(Path(dest_dir.name) / rel_name)
        record["copied"] = True
        return record
    record["path"] = None
    record["copied"] = False
    record["pointer"] = True
    record["reason"] = f"skipped; {size} bytes > {max_bytes} cap"
    return record


def _collect_evidence(
    shard_dirs: list[Path],
    pack: Path,
    *,
    adapter: str,
    max_bytes: int,
) -> list[dict[str, Any]]:
    evidence_dir = pack / "evidence"
    ingest_dir = pack / "in" / ("nmap" if adapter == "nmap" else adapter)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ingest_dir.mkdir(parents=True, exist_ok=True)
    # Mirror-friendly nmap folder always exists for pack ingest.
    (pack / "in" / "nmap").mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    for directory in shard_dirs:
        worker = directory.name
        for name in EVIDENCE_NAMES:
            src = directory / name
            if not src.is_file():
                continue
            rel = f"{worker}{src.suffix}"
            record = _copy_or_pointer(
                src, evidence_dir, rel_name=rel, max_bytes=max_bytes
            )
            if record.get("copied"):
                ingest_name = f"{worker}{src.suffix}"
                shutil.copy2(src, ingest_dir / ingest_name)
                if adapter != "nmap" and src.suffix in {".xml", ".gnmap"}:
                    shutil.copy2(src, pack / "in" / "nmap" / ingest_name)
            records.append(record)
        for name in POINTER_ONLY_NAMES:
            src = directory / name
            if not src.is_file():
                continue
            size = src.stat().st_size
            records.append(
                {
                    "src": src.name,
                    "bytes": size,
                    "sha256": _sha256(src),
                    "worker": worker,
                    "path": None,
                    "copied": False,
                    "pointer": True,
                    "reason": "noise log not copied by default",
                }
            )
    (evidence_dir / "index.json").write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8"
    )
    return records


def _readme(*, adapter: str, run_id: str) -> str:
    return f"""# Covey pack export — CISO Assistant leave-behind

This directory is a **file_drop** for the assessment MCP / `grc-collector-pack`.
It is Seen evidence from a SCOPE-gated Covey run (`{run_id}`, adapter `{adapter}`).

## Honesty (read this first)

**{HONESTY_LINE}**

| This drop is | This drop is not |
| --- | --- |
| A **surface map** of hosts/services Covey observed | Honeypot / fleet-sensor **validated** traffic |
| Conservative **open-port observations** when XML/gnmap/json shows `open` | A control **operating-effectiveness** test |
| SoR-ready assets / findings / evidence pointers | A RiskReady wrap, POST, or API push |

Nmap (or any other BYO scanner) proving a port is open does **not** mean a
control failed. Do not file POAMs that claim MFA, EDR, backup, or IR failure
from this pack alone.

## Layout

| Path | SoR object |
| --- | --- |
| `meta.json` | run envelope: signer/purpose (no secrets), versions, honesty flags |
| `assets.jsonl` | one host or service asset per line |
| `findings.jsonl` | `claim=open_port_observed` only when evidence shows an open port |
| `evidence/` | small copies (or pointers) of shard `scan.xml` / `scan.gnmap` / `scan.json` |
| `in/nmap/` | mirror-friendly ingest folder for nmap-family artifacts |
| `README_EXPORT.md` | this file |

Honeypot / fleet-sensor events belong in `in/honeypot/` under the
`honeypot_event.v1` / `session_summary.v1` contract — **not** this exporter.
See `docs/honeypot_pack_drop.md`.

## CISO Assistant / pack ingest

1. Drop this folder (or a zip of it) where the collector pack `file_drop` reads.
2. Map `assets.jsonl` → assets, `findings.jsonl` → findings (info/observation),
   `evidence/` → evidence attachments, `meta.json` → assessment run metadata.
3. **Do not POST to RiskReady.** LICENSE-LOCK forbids RiskReady wrappers.
4. Downstream SoRs (CISO Assistant, Probo, OpenGRC) may attach these objects
   to an assessment. They must preserve the honesty flags in `meta.json`.

## What was deliberately omitted

- SCOPE HMAC material and `signature`
- Scanner binaries
- Multi-megabyte `.nmap` / stdout / stderr dumps (see `evidence/index.json`)
- Any claim that a GRC control is operating (or failing)
"""


def export_pack(
    out: Path | str,
    *,
    max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
    created_at: str | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Write ``pack_drop/`` from a `prove` / `run` artifact tree."""
    run_root, pack = resolve_paths(out)
    if not run_root.is_dir():
        raise ExportError(f"run out dir missing: {run_root}")
    report = _read_json(run_root / "run_report.json")
    plan = _read_json(run_root / "plan.json")
    prove = _read_json(run_root / "prove.json")
    shard_dirs = _shard_dirs(run_root, report)
    if not report and not plan and not shard_dirs:
        raise ExportError(
            f"no Covey run artifacts under {run_root} "
            "(need run_report.json, plan.json, or shards/)"
        )

    adapter = str(plan.get("adapter") or "nmap")
    hosts: list[str] = []
    seen_hosts: set[str] = set()
    for item in report.get("pass1") or []:
        if not isinstance(item, dict):
            continue
        for host in item.get("live_hosts") or []:
            if host and host not in seen_hosts:
                seen_hosts.add(str(host))
                hosts.append(str(host))
    services: list[dict[str, str]] = []
    seen_svc: set[tuple[str, str, str]] = set()
    for directory in shard_dirs:
        for host in _parse_hosts(directory, adapter):
            if host not in seen_hosts:
                seen_hosts.add(host)
                hosts.append(host)
        for service in _parse_services(directory):
            key = (service["address"], service["protocol"], service["port"])
            if key in seen_svc:
                continue
            seen_svc.add(key)
            services.append(service)

    assets = _build_assets(hosts=hosts, services=services, adapter=adapter)
    findings = _build_findings(services, adapter=adapter)
    run_id = _run_id(plan, prove)
    stamp = created_at or _utc_now()
    deepen = plan.get("deepen") if isinstance(plan.get("deepen"), dict) else {}

    pack.mkdir(parents=True, exist_ok=True)
    evidence = _collect_evidence(
        shard_dirs, pack, adapter=adapter, max_bytes=max_evidence_bytes
    )

    meta = {
        "schema": SCHEMA_ID,
        "run_id": run_id,
        "adapter": adapter,
        "scope": {
            "signer": plan.get("signer") or "",
            "purpose": plan.get("purpose") or "",
        },
        "deepen": deepen,
        "honesty": HONESTY,
        "ingest": {
            "mode": "file_drop",
            "riskready_post": False,
            "ciso_assistant": "leave-behind file_drop only",
        },
        "versions": {
            "covey": __version__,
            "git": _git_versions(cwd or Path.cwd()),
            "tool": _tool_version(shard_dirs, report),
        },
        "created_at": stamp,
        "source_out": str(run_root),
        "counts": {
            "assets": len(assets),
            "findings": len(findings),
            "evidence": len(evidence),
            "hosts": sum(1 for row in assets if row.get("kind") == "host"),
            "services": sum(1 for row in assets if row.get("kind") == "service"),
        },
    }
    _write_json(pack / "meta.json", meta)
    _write_jsonl(pack / "assets.jsonl", assets)
    _write_jsonl(pack / "findings.jsonl", findings)
    (pack / "README_EXPORT.md").write_text(_readme(adapter=adapter, run_id=run_id), encoding="utf-8")
    return {
        "ok": True,
        "pack": str(pack),
        "run_id": run_id,
        "assets": len(assets),
        "findings": len(findings),
        "meta": meta,
    }
