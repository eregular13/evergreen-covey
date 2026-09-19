"""Export Covey run artifacts into a collector pack_drop (file_drop only)."""

from __future__ import annotations

import hashlib
import json
import os
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
from covey.adapters.registry import (
    E2E_PROVEN_ADAPTERS,
    LIVE_ADAPTER_IDS,
    UNPROVEN_ADAPTERS,
    adapter_for,
)
from covey.errors import ExportError, GateError
from covey.findings import (
    findings_from_file_drop,
    findings_from_httpx_jsonl,
    findings_from_httpx_lines,
    findings_from_nmap_services,
    findings_from_sslscan,
    findings_from_tlsx,
    findings_from_whatweb,
)
from covey.grc import (
    ciso_finding_asset_id,
    ciso_finding_evidence_ids,
    fetch_ciso_finding,
    fetch_probo_finding,
    push_ciso_assets_evidences,
    push_ciso_findings,
    push_probo_findings,
    refuse_opengrc_live,
    refuse_riskready,
    require_ciso_gate,
    require_probo_gate,
    write_ciso,
    write_opengrc,
    write_probo,
)

PACK_DIR_NAME = "pack_drop"
# Canonical write schema. Collector ingest still accepts evergreen.pack_drop.v1.
SCHEMA_ID = "covey.pack_drop.v1"
PACK_SOURCE = "evergreen-covey"
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
    "riskready_post": False,
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


def _stamp_pack_schema(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Canonical row schema beside adapter. Do not rewrite provenance source."""
    for row in rows:
        row["schema"] = SCHEMA_ID
    return rows


def _demo_flag(*blobs: dict[str, Any]) -> bool:
    """True for lab/demo. False only when SCOPE/plan is explicitly non-demo."""
    for blob in blobs:
        if not isinstance(blob, dict) or "demo" not in blob:
            continue
        value = blob.get("demo")
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)
    return True


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


def _looks_like_nmap_xml(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False
    return "<nmaprun" in head


def _shard_tool(directory: Path, fallback: str) -> str:
    argv_path = directory / "argv.json"
    if argv_path.is_file():
        try:
            loaded = json.loads(argv_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, list) and loaded:
            name = Path(str(loaded[0])).name.lower().replace("_", "-")
            compact = name.replace("-", "")
            for tool in sorted(LIVE_ADAPTER_IDS, key=len, reverse=True):
                if tool in name or tool.replace("-", "") in compact:
                    return tool
    if (directory / "scan.xml").is_file() and _looks_like_nmap_xml(directory / "scan.xml"):
        return "nmap"
    return fallback


def _add_hosts(hosts: list[str], seen: set[str], found: list[str]) -> None:
    for host in found:
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)


def _add_services(
    services: list[dict[str, str]],
    seen: set[tuple[str, str, str]],
    found: list[dict[str, str]],
) -> None:
    for item in found:
        key = (item["address"], item["protocol"], item["port"])
        if key in seen:
            continue
        seen.add(key)
        services.append(item)


def _parse_hosts(directory: Path, adapter_name: str) -> list[str]:
    """Adapter-aware hosts from nmap XML/gnmap, live_hosts.json, or stdout.log."""
    hosts: list[str] = []
    seen: set[str] = set()
    xml_path = directory / "scan.xml"
    if xml_path.is_file() and (adapter_name == "nmap" or _looks_like_nmap_xml(xml_path)):
        try:
            _add_hosts(hosts, seen, parse_nmap_xml_live_hosts(xml_path))
        except Exception:
            pass
    gnmap_path = directory / "scan.gnmap"
    if gnmap_path.is_file() and (adapter_name == "nmap" or not hosts):
        try:
            _add_hosts(hosts, seen, parse_gnmap_live_hosts(gnmap_path))
        except Exception:
            pass
    json_path = directory / "scan.json"
    if json_path.is_file() and adapter_name in {"masscan", "nmap"}:
        text = json_path.read_text(encoding="utf-8", errors="replace")
        _add_hosts(hosts, seen, parse_masscan_json(text) or unique_ipv4s(text))
    live_path = directory / "live_hosts.json"
    if live_path.is_file():
        try:
            loaded = json.loads(live_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, list):
            _add_hosts(hosts, seen, [str(item) for item in loaded if item])
    try:
        plugin = adapter_for(adapter_name)
    except Exception:
        return hosts
    try:
        _add_hosts(hosts, seen, list(plugin.parse_live_hosts(directory)))
    except Exception:
        pass
    return hosts


def _parse_masscan_json_services(directory: Path) -> list[dict[str, str]]:
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


def _parse_services(directory: Path, adapter_name: str) -> list[dict[str, str]]:
    """Open ports from nmap XML/gnmap, masscan JSON, or adapter stdout.log."""
    services: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    xml_path = directory / "scan.xml"
    if xml_path.is_file() and (adapter_name == "nmap" or _looks_like_nmap_xml(xml_path)):
        try:
            _add_services(services, seen, parse_nmap_xml_services(xml_path))
        except Exception:
            pass
    gnmap_path = directory / "scan.gnmap"
    if gnmap_path.is_file() and (adapter_name == "nmap" or not services):
        try:
            _add_services(services, seen, parse_gnmap_services(gnmap_path))
        except Exception:
            pass
    if adapter_name in {"masscan", "nmap"}:
        _add_services(services, seen, _parse_masscan_json_services(directory))
    try:
        plugin = adapter_for(adapter_name)
    except Exception:
        return services
    parse = getattr(plugin, "parse_services", None)
    if not callable(parse):
        return services
    try:
        _add_services(services, seen, list(parse(directory)))
    except Exception:
        pass
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


def _assets_from_ingested_findings(
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    adapter: str,
) -> list[dict[str, Any]]:
    """Host assets from file_drop CVE pairing so CISO live can attach FindingWrite.asset."""
    seen = {
        str(row.get("address") or "").strip()
        for row in assets
        if row.get("kind") == "host"
    }
    extra: list[dict[str, Any]] = []
    for row in findings:
        if row.get("claim") != "vuln_ingested":
            continue
        address = str(row.get("address") or "").strip()
        if not address or address.lower() in {"file_drop", "unknown-host"}:
            continue
        if address in seen:
            continue
        seen.add(address)
        extra.append(
            {
                "kind": "host",
                "address": address,
                "state": "up",
                "source": "file_drop",
                "adapter": adapter,
            }
        )
    return extra


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


def _misconfig_findings(
    shard_dirs: list[Path],
    services: list[dict[str, str]],
    *,
    adapter: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(findings_from_nmap_services(services, adapter=adapter))
    from covey.adapters.common import read_artifact_blob

    for directory in shard_dirs:
        blob = read_artifact_blob(directory)
        tool = _shard_tool(directory, adapter)
        if tool in {"httpx", "whatweb"}:
            rows.extend(findings_from_httpx_jsonl(blob, adapter=tool))
        rows.extend(findings_from_httpx_lines(blob, adapter=tool))
        host = ""
        for line in blob.splitlines():
            if line.lower().startswith("connected to "):
                host = line.split()[-1].strip()
                break
        if tool in {"sslscan", "tlsx"} and (
            "connected to " in blob.lower()
            or "sslv" in blob.lower()
            or "<ssltest" in blob.lower()
            or "self signed" in blob.lower()
        ):
            rows.extend(
                findings_from_sslscan(blob, host=host or "unknown-host", adapter=tool)
            )
        if tool == "tlsx":
            rows.extend(findings_from_tlsx(blob, adapter=tool))
        if tool == "whatweb":
            rows.extend(findings_from_whatweb(blob, adapter=tool))
        rows.extend(findings_from_file_drop(blob, adapter="openvas"))
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = (str(row.get("address") or ""), str(row.get("name") or row.get("title") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


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
    # Mirror-friendly ingest folders for grc-collector-pack.
    (pack / "in" / "nmap").mkdir(parents=True, exist_ok=True)
    (pack / "in" / "easm").mkdir(parents=True, exist_ok=True)
    (pack / "in" / "vuln").mkdir(parents=True, exist_ok=True)

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
        stdout = directory / "stdout.log"
        if stdout.is_file():
            if adapter in {"httpx", "whatweb"}:
                shutil.copy2(stdout, pack / "in" / "easm" / f"{worker}.txt")
            if adapter in {"sslscan", "tlsx"}:
                shutil.copy2(stdout, pack / "in" / "vuln" / f"{worker}.txt")
        for jsonl in directory.glob("*.jsonl"):
            if adapter == "httpx":
                shutil.copy2(jsonl, pack / "in" / "easm" / jsonl.name)
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
| `findings.jsonl` | `open_port_observed` when evidence shows open; `misconfig_observed` when httpx/sslscan/whatweb/nmap evidence supports it; `vuln_ingested` only from OpenVAS/Nessus **file_drop** CVE pairing — never invented |
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
    target: str = "pack_drop",
    live: bool = False,
) -> dict[str, Any]:
    """Write ``pack_drop/`` from a `prove` / `run` artifact tree."""
    wanted = (target or "pack_drop").lower()
    if wanted == "riskready":
        refuse_riskready()
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
    e2e_proven = adapter in E2E_PROVEN_ADAPTERS
    unproven = adapter in UNPROVEN_ADAPTERS
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
        tool = _shard_tool(directory, adapter)
        for host in _parse_hosts(directory, tool):
            if host not in seen_hosts:
                seen_hosts.add(host)
                hosts.append(host)
        for service in _parse_services(directory, tool):
            key = (service["address"], service["protocol"], service["port"])
            if key in seen_svc:
                continue
            seen_svc.add(key)
            services.append(service)

    assets = _stamp_pack_schema(
        _build_assets(hosts=hosts, services=services, adapter=adapter)
    )
    findings = _stamp_pack_schema(_build_findings(services, adapter=adapter))
    findings.extend(
        _stamp_pack_schema(_misconfig_findings(shard_dirs, services, adapter=adapter))
    )
    assets.extend(
        _stamp_pack_schema(
            _assets_from_ingested_findings(assets, findings, adapter=adapter)
        )
    )
    run_id = _run_id(plan, prove)
    stamp = created_at or _utc_now()
    deepen = plan.get("deepen") if isinstance(plan.get("deepen"), dict) else {}
    demo = _demo_flag(plan, prove)

    pack.mkdir(parents=True, exist_ok=True)
    evidence = _collect_evidence(
        shard_dirs, pack, adapter=adapter, max_bytes=max_evidence_bytes
    )

    meta = {
        "schema": SCHEMA_ID,
        "source": PACK_SOURCE,
        "run_id": run_id,
        "adapter": adapter,
        "demo": demo,
        "scope": {
            "signer": plan.get("signer") or "",
            "purpose": plan.get("purpose") or "",
        },
        "deepen": deepen,
        "honesty": HONESTY,
        "e2e_proven": e2e_proven,
        "unproven": unproven,
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
    extra: dict[str, Any] = {}
    if wanted in {"all", "ciso"}:
        extra["ciso"] = write_ciso(
            pack / "ciso-assistant",
            assets=assets,
            findings=findings,
            evidence=evidence,
        )
    if wanted in {"all", "opengrc"}:
        extra["opengrc"] = write_opengrc(
            pack / "opengrc", assets=assets, findings=findings
        )
    if wanted in {"all", "probo"}:
        extra["probo"] = write_probo(pack / "probo", findings=findings)
    if wanted not in {"pack_drop", "all", "ciso", "opengrc", "probo"}:
        raise ExportError(f"unknown export target {target!r}")
    result = {
        "ok": True,
        "pack": str(pack),
        "run_id": run_id,
        "assets": len(assets),
        "findings": len(findings),
        "meta": meta,
        "target": wanted,
        "http": False,
    }
    result.update(extra)
    if live:
        if wanted == "opengrc":
            refuse_opengrc_live()
        if wanted in {"ciso", "all"}:
            require_ciso_gate(cwd=cwd)
        if wanted in {"probo", "all"}:
            require_probo_gate(cwd=cwd)
        if wanted in {"ciso", "all"}:
            ciso_info = extra.get("ciso") or {}
            push = push_ciso_assets_evidences(
                assets=list(ciso_info.get("asset_rows") or []),
                evidences=list(ciso_info.get("evidence_rows") or []),
                cwd=cwd,
            )
            result["http"] = bool(push.get("http"))
            result["ciso_asset_ids"] = [str(item) for item in (push.get("asset_ids") or [])]
            if os.environ.get("CISO_FINDINGS_ASSESSMENT", "").strip():
                name_to_id: dict[str, str] = {}
                fallback: dict[str, str] = {}
                posted_assets = [
                    row
                    for row in list(push.get("posted_assets") or [])
                    if isinstance(row, dict)
                    and str(row.get("name") or "").strip()
                    and str(row.get("id") or "").strip()
                ]
                pairs = posted_assets or [
                    {"name": row.get("name"), "id": aid, "type": row.get("type")}
                    for row, aid in zip(
                        list(ciso_info.get("asset_rows") or []),
                        list(push.get("asset_ids") or []),
                    )
                ]
                for row in pairs:
                    name = str(row.get("name") or "").strip()
                    aid = str(row.get("id") or "").strip()
                    if not (name and aid):
                        continue
                    if str(row.get("type") or "") == "PR":
                        name_to_id[name] = aid
                    else:
                        fallback.setdefault(name, aid)
                for name, aid in fallback.items():
                    name_to_id.setdefault(name, aid)
                evidence_ids = [
                    str(item)
                    for item in (push.get("evidence_ids") or [])
                    if str(item).strip()
                ]
                wired = []
                for row in list(ciso_info.get("finding_rows") or []):
                    item = dict(row)
                    addr = str(item.get("address") or "").strip()
                    if addr and addr in name_to_id:
                        item["asset"] = name_to_id[addr]
                    if evidence_ids:
                        item["evidences"] = list(evidence_ids)
                    wired.append(item)
                findings_push = push_ciso_findings(
                    findings=wired,
                    cwd=cwd,
                )
                result["http"] = result["http"] or bool(findings_push.get("http"))
                result["ciso_findings_posted"] = findings_push.get("posted")
                ids = [str(item) for item in (findings_push.get("finding_ids") or [])]
                result["ciso_finding_ids"] = ids
                named = [
                    row
                    for row in wired
                    if str(row.get("name") or row.get("title") or "").strip()
                ]
                posted_rows = [
                    row
                    for row in list(findings_push.get("posted_rows") or [])
                    if isinstance(row, dict) and str(row.get("id") or "").strip()
                ]
                pairs: list[tuple[str, dict[str, Any]]] = []
                if posted_rows:
                    for row in posted_rows:
                        pairs.append((str(row.get("id") or "").strip(), row))
                else:
                    for index, fid in enumerate(ids):
                        expected_row = named[index] if index < len(named) else {}
                        pairs.append((fid, expected_row))
                read_back: list[str] = []
                read_back_assets: list[str] = []
                read_back_evidences: list[str] = []
                for fid, expected_row in pairs:
                    body = fetch_ciso_finding(fid, cwd=cwd)
                    expected = str(expected_row.get("asset") or "").strip()
                    got = ciso_finding_asset_id(body)
                    if expected and ciso_finding_asset_id({"asset": expected}) and got != expected:
                        raise GateError(
                            "CISO finding read-back failed: GET asset id missing or mismatched. No claim."
                        )
                    expected_ev: list[str] = []
                    raw_ev = expected_row.get("evidences") or []
                    if isinstance(raw_ev, str):
                        raw_ev = [raw_ev]
                    for item in raw_ev:
                        text = str(item or "").strip()
                        if text and ciso_finding_evidence_ids({"evidences": [text]}):
                            expected_ev.append(text)
                    got_ev = ciso_finding_evidence_ids(body)
                    if expected_ev and set(expected_ev) - set(got_ev):
                        raise GateError(
                            "CISO finding read-back failed: GET evidences missing or mismatched. No claim."
                        )
                    expected_rec = ""
                    if posted_rows:
                        expected_rec = str(
                            expected_row.get("recommendation") or ""
                        ).strip()
                    got_rec = str(body.get("recommendation") or "").strip()
                    if expected_rec and got_rec != expected_rec:
                        raise GateError(
                            "CISO finding read-back failed: GET recommendation missing or mismatched. No claim."
                        )
                    expected_obs = ""
                    if posted_rows:
                        expected_obs = str(
                            expected_row.get("observation") or ""
                        ).strip()
                    got_obs = str(body.get("observation") or "").strip()
                    if expected_obs and got_obs != expected_obs:
                        raise GateError(
                            "CISO finding read-back failed: GET observation missing or mismatched. No claim."
                        )
                    read_back.append(str(body.get("id") or fid))
                    if got:
                        read_back_assets.append(got)
                    for eid in ciso_finding_evidence_ids(body):
                        if eid not in read_back_evidences:
                            read_back_evidences.append(eid)
                result["ciso_findings_read_back"] = read_back
                result["ciso_findings_read_back_assets"] = read_back_assets
                result["ciso_findings_read_back_evidences"] = read_back_evidences
        if wanted in {"probo", "all"}:
            probo_info = extra.get("probo") or {}
            probo_push = push_probo_findings(
                findings=list(probo_info.get("items") or []),
                cwd=cwd,
            )
            result["http"] = bool(result.get("http")) or bool(probo_push.get("http"))
            result["probo_posted"] = probo_push.get("posted")
            ids = [
                str(item)
                for item in (probo_push.get("finding_ids") or [])
                if str(item).strip()
            ]
            result["probo_finding_ids"] = ids
            posted_rows = [
                row
                for row in list(probo_push.get("posted_rows") or [])
                if isinstance(row, dict) and str(row.get("id") or "").strip()
            ]
            pairs: list[tuple[str, dict[str, Any]]] = []
            if posted_rows:
                for row in posted_rows:
                    pairs.append((str(row.get("id") or "").strip(), row))
            else:
                for fid in ids:
                    pairs.append((fid, {}))
            read_back: list[str] = []
            for fid, expected_row in pairs:
                body = fetch_probo_finding(fid, cwd=cwd)
                expected_desc = ""
                if posted_rows:
                    expected_desc = str(expected_row.get("description") or "").strip()
                got_desc = str(body.get("description") or "").strip()
                if expected_desc and got_desc != expected_desc:
                    raise GateError(
                        "Probo finding read-back failed: description missing or mismatched. No claim."
                    )
                read_back.append(str(body.get("id") or fid))
            result["probo_findings_read_back"] = read_back
    return result
