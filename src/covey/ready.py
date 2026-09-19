"""Client-day preflight: signed SCOPE + BYO binaries. Never installs. Never spawns."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from covey.adapters.registry import (
    E2E_PROVEN_ADAPTERS,
    FILE_DROP_IDS,
    UNPROVEN_ADAPTERS,
    host_need,
    normalize_adapter_name,
)
from covey.errors import RunnerError
from covey.runner import resolve_exec
from covey.scope import Scope, load

HONESTY_LINE = (
    "surface map ≠ honeypot validated ≠ control operating effectiveness"
)


def _adapter_names(scope: Scope) -> list[str]:
    names = list(scope.pipeline) if scope.pipeline else [scope.adapter]
    if not names:
        names = [scope.adapter]
    return names


def _is_file_drop_only(scope: Scope) -> bool:
    kinds = {getattr(target, "kind", "cidr") for target in scope.targets}
    return kinds == {"file_drop"}


def check_ready(
    scope_path: Path | str,
    *,
    require_binary: bool = True,
    strict_e2e: bool = False,
) -> dict[str, Any]:
    """Load SCOPE, report BYO + DESKTOP/host needs. Never apt-install. Never spawn."""
    path = Path(scope_path)
    scope = load(path)
    names = _adapter_names(scope)
    file_drop = _is_file_drop_only(scope)
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    unproven: list[str] = []
    desktop: list[str] = []

    for name in names:
        key = normalize_adapter_name(name)
        if file_drop or key in FILE_DROP_IDS:
            rows.append(
                {
                    "adapter": key if key in FILE_DROP_IDS else name,
                    "e2e_proven": False,
                    "desktop_or_host": False,
                    "reason": "file_drop ingest only; Covey will not spawn OpenVAS",
                    "needs": ("operator-dropped XML under a relative file_drop path",),
                    "binary_ok": True,
                    "binary": "file_drop (no live spawn)",
                }
            )
            continue
        proven = name in E2E_PROVEN_ADAPTERS
        if name in UNPROVEN_ADAPTERS:
            unproven.append(name)
        need = host_need(name)
        if need.get("desktop_or_host"):
            desktop.append(name)
        row: dict[str, Any] = {
            "adapter": name,
            "e2e_proven": proven,
            "desktop_or_host": bool(need.get("desktop_or_host")),
            "reason": str(need.get("reason") or ""),
            "needs": list(need.get("needs") or ()),
            "binary_ok": False,
            "binary": None,
        }
        try:
            spec = resolve_exec(name)
            row["binary_ok"] = True
            row["binary"] = spec.display
        except RunnerError as exc:
            row["binary"] = str(exc)
            missing.append(name)
        rows.append(row)

    if strict_e2e and unproven:
        raise RunnerError(
            "ready --strict-e2e: prove is e2e-live only for "
            + ", ".join(E2E_PROVEN_ADAPTERS)
            + f"; {', '.join(unproven)} remain argv+unit only"
        )

    ok = not missing if require_binary else True
    summary: dict[str, Any] = {
        "ok": ok,
        "scope": str(path),
        "demo": scope.demo,
        "signer": scope.signer,
        "purpose": scope.purpose,
        "adapter": scope.adapter,
        "pipeline": names,
        "file_drop": file_drop,
        "adapters": rows,
        "missing": missing,
        "unproven": unproven,
        "desktop_or_host": desktop,
        "install": False,
        "spawn": False,
        "honesty": HONESTY_LINE,
    }
    return summary


def format_ready(summary: dict[str, Any]) -> str:
    lines = [
        "Evergreen Covey ready",
        f"  scope     {summary['scope']}",
        f"  demo      {summary['demo']}",
        f"  signer    {summary['signer']}",
        f"  purpose   {summary['purpose']}",
        f"  adapter   {summary['adapter']}",
        f"  pipeline  {', '.join(summary['pipeline'])}",
        f"  file_drop {summary['file_drop']}",
    ]
    for row in summary["adapters"]:
        proven = "e2e_proven" if row["e2e_proven"] else "argv+unit only"
        desktop = "desktop/host" if row["desktop_or_host"] else "farm-runnable"
        status = "ok" if row["binary_ok"] else "MISSING BYO"
        lines.append(
            f"  tool      {row['adapter']}  {proven}  {desktop}  binary={status}"
        )
        if row.get("binary"):
            lines.append(f"            {row['binary']}")
        if row.get("reason"):
            lines.append(f"            {row['reason']}")
        for need in row.get("needs") or []:
            lines.append(f"            need: {need}")
    if summary["missing"]:
        lines.append(f"  missing   {', '.join(summary['missing'])}")
    if summary["unproven"]:
        lines.append(
            f"  unproven  {', '.join(summary['unproven'])} (prove fails closed)"
        )
    if summary["desktop_or_host"]:
        lines.append(f"  desktop   {', '.join(summary['desktop_or_host'])}")
    lines.append("  install   false (LICENSE-LOCK; BYO only)")
    lines.append("  spawn     false (ready never invokes a scanner)")
    lines.append(f"  honesty   {summary['honesty']}")
    return "\n".join(lines) + "\n"


def write_ready(summary: dict[str, Any], dest: Path | str) -> Path:
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return path
