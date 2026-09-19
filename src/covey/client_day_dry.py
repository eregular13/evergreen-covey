"""SAMPLE client-day dry: sign → ready --strict-e2e → plan. No live scan.

LICENSE-LOCK: never apt-install, never vendor Nmap / masscan / etc.
SAMPLE ≠ client. Do not claim the unproven four live. No RiskReady.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import yaml

from covey.errors import ExportError, RunnerError
from covey.export import export_pack
from covey.plan import build_plan
from covey.ready import HONESTY_LINE, check_ready, write_ready
from covey.scope import HMAC_ENV, load, sign_file

SAMPLE_SIGNER = "client-day-dry"
SAMPLE_PURPOSE = "SAMPLE client-day dry (not a client estate)"
SAMPLE_WINDOW = {
    "start": "2026-01-01T00:00:00Z",
    "end": "2029-12-31T23:59:59Z",
}
DEFAULT_SCOPE = Path("examples/scope.client.example.yaml")
DEFAULT_WORK = Path("out/client_day_dry")
UNPROVEN_FOUR = ("masscan", "arp-scan", "netdiscover", "zmap")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@contextmanager
def lab_hmac_only() -> Iterator[None]:
    """Force the well-known demo HMAC. Production keys stay off this SAMPLE."""
    saved = os.environ.pop(HMAC_ENV, None)
    try:
        yield
    finally:
        if saved is not None:
            os.environ[HMAC_ENV] = saved


def stage_sample_scope(src: Path, dest: Path) -> Path:
    """Copy a SCOPE template into work/. Force demo + durable SAMPLE window.

    Never mutates the source. Adapter and targets stay as written so a
    masscan template still hits ready --strict-e2e.
    """
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RunnerError(f"client-day-dry: SCOPE is not a mapping: {src}")
    data["demo"] = True
    data.pop("signature", None)
    consent = data.get("consent")
    if not isinstance(consent, dict):
        consent = {}
        data["consent"] = consent
    consent["signed"] = True
    consent["signer"] = SAMPLE_SIGNER
    consent["purpose"] = SAMPLE_PURPOSE
    data["window"] = dict(SAMPLE_WINDOW)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        yaml.safe_dump(data, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    return dest


def seed_sample_run(dest: Path, *, fixtures: Path) -> Path:
    """Land a SAMPLE nmap out/ from committed fixtures. No scanner spawn."""
    shards = dest / "shards"
    p1 = shards / "p1-s00"
    p2 = shards / "p2-s00"
    p1.mkdir(parents=True, exist_ok=True)
    p2.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(fixtures / "scan_up.xml", p1 / "scan.xml")
    (p1 / "live_hosts.json").write_text(
        json.dumps(["127.0.0.1", "127.0.0.3"]) + "\n", encoding="utf-8"
    )
    shutil.copyfile(fixtures / "scan_open.xml", p2 / "scan.xml")
    shutil.copyfile(fixtures / "scan_open.gnmap", p2 / "scan.gnmap")
    (dest / "plan.json").write_text(
        json.dumps(
            {
                "adapter": "nmap",
                "created_at": "2026-09-19T00:00:00+00:00",
                "signer": SAMPLE_SIGNER,
                "purpose": SAMPLE_PURPOSE,
                "demo": True,
                "deepen": {"ports": "22,80,443"},
                "shards": ["10.42.0.0/28"],
                "workers": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (dest / "run_report.json").write_text(
        json.dumps(
            {
                "ok": True,
                "exec": "SAMPLE fixture (no live spawn)",
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
    return dest


def _fixture_root(repo: Path) -> Path:
    return repo / "tests" / "fixtures"


def _export_possible(export_from: Path | None, fixtures: Path) -> bool:
    if export_from is not None:
        return export_from.is_dir()
    return (
        (fixtures / "scan_up.xml").is_file()
        and (fixtures / "scan_open.xml").is_file()
        and (fixtures / "scan_open.gnmap").is_file()
    )


def run_dry(
    *,
    work: Path | str | None = None,
    scope_src: Path | str | None = None,
    export_from: Path | str | None = None,
    no_export: bool = False,
    repo: Path | str | None = None,
) -> dict[str, Any]:
    """sign (lab HMAC) → ready --strict-e2e → plan. Optional fixture export.

    Never installs. Never spawns. Missing BYO is a printed miss list, not
    an apt-get. Unproven four fail closed on ready --strict-e2e.
    """
    started = time.perf_counter()
    root = Path(repo) if repo is not None else repo_root()
    dest = Path(work) if work is not None else root / DEFAULT_WORK
    dest.mkdir(parents=True, exist_ok=True)
    src = Path(scope_src) if scope_src is not None else root / DEFAULT_SCOPE
    if not src.is_file():
        raise RunnerError(f"client-day-dry: SCOPE missing: {src}")

    fixtures = _fixture_root(root)
    export_src = Path(export_from) if export_from is not None else None

    with lab_hmac_only():
        staged = stage_sample_scope(src, dest / "scope.yaml")
        signed = sign_file(staged, in_place=True, demo=True)
        ready = check_ready(staged, require_binary=False, strict_e2e=True)
        write_ready(ready, dest / "ready.json")
        scope = load(staged)
        plan = build_plan(scope, out_root=dest)
        plan_path = dest / "plan.json"
        plan_path.write_text(
            json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8"
        )

    missing = list(ready.get("missing") or [])
    pack_path: str | None = None
    export_note = "skipped"
    if no_export:
        export_note = "disabled (--no-export)"
    elif _export_possible(export_src, fixtures):
        run_root = export_src if export_src is not None else dest / "sample_run"
        if export_src is None:
            seed_sample_run(run_root, fixtures=fixtures)
        try:
            summary = export_pack(run_root, target="pack_drop")
            pack_path = str(summary["pack"])
            export_note = (
                "SAMPLE fixture export (not a live scan)"
                if export_src is None
                else f"export from {export_src}"
            )
        except ExportError as exc:
            export_note = f"export refused: {exc}"
    else:
        export_note = "no SAMPLE fixture run; assess skipped (BYO required, no apt-install)"

    elapsed = round(time.perf_counter() - started, 3)
    return {
        "ok": True,
        "scope": str(staged),
        "demo": True,
        "signature": str(signed.get("signature") or ""),
        "adapter": scope.adapter,
        "ready": str(dest / "ready.json"),
        "plan": str(plan_path),
        "shards": list(plan.shards),
        "pass1_workers": len(plan.pass1_workers),
        "missing": missing,
        "unproven": list(ready.get("unproven") or []),
        "pack_drop": pack_path,
        "export": export_note,
        "install": False,
        "spawn": False,
        "elapsed_s": elapsed,
        "honesty": HONESTY_LINE,
        "sample": True,
    }


def format_dry(summary: dict[str, Any]) -> str:
    lines = [
        "Evergreen Covey client-day dry (SAMPLE, no live scan)",
        f"  scope     {summary['scope']}",
        f"  demo      {summary['demo']} (lab HMAC only)",
        f"  adapter   {summary['adapter']}",
        f"  ready     {summary['ready']}",
        f"  plan      {summary['plan']} ({len(summary['shards'])} shards, "
        f"{summary['pass1_workers']} pass1 workers)",
    ]
    if summary["missing"]:
        lines.append(
            f"  BYO miss  {', '.join(summary['missing'])} "
            "(assess skipped; fail closed, no apt-install)"
        )
    else:
        lines.append("  BYO       present on PATH (dry still does not spawn)")
    if summary["unproven"]:
        lines.append(
            f"  unproven  {', '.join(summary['unproven'])} (argv+unit only)"
        )
    if summary.get("pack_drop"):
        lines.append(f"  pack_drop {summary['pack_drop']}")
    else:
        lines.append("  pack_drop (none)")
    lines.append(f"  export    {summary['export']}")
    lines.append(f"  elapsed   {summary['elapsed_s']}s")
    lines.append("  install   false (LICENSE-LOCK; BYO only)")
    lines.append("  spawn     false (dry never invokes a scanner)")
    lines.append("  SAMPLE ≠ client. Do not claim masscan/arp-scan/netdiscover/zmap live.")
    lines.append(f"  honesty   {summary['honesty']}")
    return "\n".join(lines) + "\n"
