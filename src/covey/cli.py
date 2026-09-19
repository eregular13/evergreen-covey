"""CLI: python -m covey plan|run|prove|export|sign|ready|assess|client-day-dry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from covey import __version__
from covey.errors import CoveyError, ExportError, GateError
from covey.client_day_dry import format_dry, run_dry
from covey.export import export_pack
from covey.plan import build_plan
from covey.prove import run_prove
from covey.ready import check_ready, format_ready, write_ready
from covey.runner import resolve_exec, run_plan
from covey.scope import load, sign_file


def _cmd_plan(args: argparse.Namespace) -> int:
    scope = load(Path(args.scope))
    plan = build_plan(scope, out_root=Path(args.out_root))
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {dest} ({len(plan.shards)} shards, {len(plan.pass1_workers)} pass1 workers)")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    scope = load(Path(args.scope))
    out_root = Path(args.out)
    plan = build_plan(scope, out_root=out_root)
    (out_root / "plan.json").parent.mkdir(parents=True, exist_ok=True)
    (out_root / "plan.json").write_text(
        json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    if plan.ingest_workers and not plan.pass1_workers:
        report = run_plan(plan, out_root=out_root)
    else:
        spec = resolve_exec(plan.adapter)
        report = run_plan(plan, out_root=out_root, spec=spec)
    print(f"run {'ok' if report.ok else 'failed'} via {report.exec}")
    print(f"  pass1 live hosts: {', '.join(report.all_pass1_hosts()) or '(none)'}")
    return 0 if report.ok else 1


def _cmd_prove(args: argparse.Namespace) -> int:
    summary = run_prove(
        out_root=Path(args.out),
        scope_path=Path(args.scope) if args.scope else None,
        adapter=args.adapter,
        install_if_missing=not args.no_install,
    )
    print("Evergreen Covey prove: OK")
    print(f"  adapter     {summary.get('adapter', 'nmap')}")
    print(f"  exec        {summary['exec']}")
    print(f"  shards      {len(summary['shards'])} ({', '.join(summary['shards'])})")
    print(f"  pass1       {summary['pass1_workers']} workers")
    print(f"  pass2 ran   {summary['pass2_ran']}")
    print(f"  live hosts  {', '.join(summary['live_hosts'])}")
    print(f"  artifacts   {summary['out']}/shards/")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    if args.target == "riskready":
        print("WRAP_DEAD: RiskReady stay-out. No HTTP. File drop only.", file=sys.stderr)
        return 2
    summary = export_pack(Path(args.out), target=args.target, live=bool(args.live))
    print(f"wrote {summary['pack']} (run_id={summary['run_id']})")
    print(f"  target    {summary.get('target')}")
    print(f"  assets    {summary['assets']}")
    print(f"  findings  {summary['findings']}")
    print("  ingest    file_drop; live CISO assets/evidences + findings if gated; no RiskReady POST")
    print("  honesty   surface map ≠ honeypot validated ≠ control operating effectiveness")
    return 0


def _cmd_ready(args: argparse.Namespace) -> int:
    """Signed SCOPE preflight. BYO resolve only — never install, never spawn."""
    summary = check_ready(
        Path(args.scope),
        require_binary=not args.plan_only,
        strict_e2e=args.strict_e2e,
    )
    if args.out:
        write_ready(summary, Path(args.out))
        print(f"wrote {args.out}")
    print(format_ready(summary), end="")
    if not summary["ok"]:
        return 1
    return 0


def _cmd_assess(args: argparse.Namespace) -> int:
    """Unattended within a signed SCOPE: ready, run, then export. Live still dual-gated."""
    summary = check_ready(Path(args.scope), require_binary=True)
    print(format_ready(summary), end="")
    if not summary["ok"]:
        return 1
    rc = _cmd_run(args)
    if rc != 0:
        return rc
    return _cmd_export(args)


def _cmd_client_day_dry(args: argparse.Namespace) -> int:
    """SAMPLE client-day rails. Never install. Never spawn. Lab HMAC only."""
    summary = run_dry(
        work=Path(args.work) if args.work else None,
        scope_src=Path(args.scope) if args.scope else None,
        export_from=Path(args.export_from) if args.export_from else None,
        no_export=bool(args.no_export),
    )
    print(format_dry(summary), end="")
    return 0 if summary["ok"] else 1


def _cmd_sign(args: argparse.Namespace) -> int:
    path = Path(args.scope)
    signed = sign_file(path, in_place=True, demo=True if args.demo else None)
    print(f"signed {path} ({signed['signature'][:16]}…)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="covey",
        description="Evergreen Covey — SCOPE-gated sharded BYO scanner orchestration",
    )
    parser.add_argument("--version", action="version", version=f"evergreen-covey {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    plan = sub.add_parser("plan", help="build worker plan JSON without invoking scanners")
    plan.add_argument("--scope", required=True, help="signed SCOPE YAML")
    plan.add_argument("--out", default="out/plan.json")
    plan.add_argument("--out-root", default="out", help="artifact root baked into argv paths")
    plan.set_defaults(func=_cmd_plan)

    run = sub.add_parser("run", help="execute a plan (requires the SCOPE adapter binary)")
    run.add_argument("--scope", required=True, help="signed SCOPE YAML")
    run.add_argument("--out", default="out")
    run.set_defaults(func=_cmd_run)

    prove = sub.add_parser("prove", help="signed loopback lab: shard, run, assert artifacts")
    prove.add_argument("--scope", default=None, help="override lab SCOPE (default examples/scope.lab.yaml)")
    prove.add_argument(
        "--adapter",
        default=None,
        help="e2e-proven adapter: nmap (default), rustscan, fping, naabu, nping, httpx, sslscan, tlsx, whatweb, hping3, onesixtyone, nbtscan, braa, ike-scan, svmap, or unicornscan",
    )
    prove.add_argument("--out", default="out")
    prove.add_argument(
        "--no-install",
        action="store_true",
        help="do not install a missing BYO binary (nmap/nping/fping/sslscan/whatweb/hping3/onesixtyone/nbtscan/braa/ike-scan/sipvicious via apt, rustscan/naabu/httpx/tlsx/unicornscan via GitHub release)",
    )
    prove.set_defaults(func=_cmd_prove)

    export = sub.add_parser(
        "export",
        help="write SoR-ready pack_drop from a prove/run out/ (file_drop only)",
    )
    export.add_argument(
        "--out",
        default="out",
        help="prove/run artifact root; writes <out>/pack_drop/",
    )
    export.add_argument(
        "--target",
        choices=("pack_drop", "ciso", "opengrc", "probo", "all", "riskready"),
        default="pack_drop",
        help="pack_drop JSONL (default); ciso/opengrc/probo file imports; riskready WRAP_DEAD",
    )
    export.add_argument(
        "--live",
        action="store_true",
        help="dual-gate live push. CISO: assets+evidences; findings only with CISO_FINDINGS_ASSESSMENT UUID. Probo: createFinding. OpenGRC refused. RiskReady WRAP_DEAD.",
    )
    export.set_defaults(func=_cmd_export)

    sign = sub.add_parser(
        "sign",
        help="HMAC-sign a SCOPE in place (production key if COVEY_SCOPE_HMAC_KEY is set)",
    )
    sign.add_argument("--scope", required=True)
    sign.add_argument(
        "--demo",
        action="store_true",
        help="force demo: true (well-known key unless COVEY_SCOPE_HMAC_KEY is set)",
    )
    sign.set_defaults(func=_cmd_sign)

    ready = sub.add_parser(
        "ready",
        help="client-day preflight: signed SCOPE + BYO binaries (no install, no spawn)",
    )
    ready.add_argument("--scope", required=True, help="signed SCOPE YAML")
    ready.add_argument(
        "--out",
        default=None,
        help="optional ready.json path",
    )
    ready.add_argument(
        "--plan-only",
        action="store_true",
        help="do not fail when a BYO binary is missing (still report it)",
    )
    ready.add_argument(
        "--strict-e2e",
        action="store_true",
        help="fail closed if SCOPE uses an argv+unit-only adapter (masscan/arp-scan/netdiscover/zmap)",
    )
    ready.set_defaults(func=_cmd_ready)

    assess = sub.add_parser(
        "assess",
        help="client-day: ready + run + GRC export (unattended within SCOPE; live still dual-gated)",
    )
    assess.add_argument("--scope", required=True, help="signed SCOPE YAML")
    assess.add_argument("--out", default="out")
    assess.add_argument(
        "--target",
        choices=("pack_drop", "ciso", "opengrc", "probo", "all", "riskready"),
        default="all",
    )
    assess.add_argument(
        "--live",
        action="store_true",
        help="dual-gate live push after export. Default dry-run files only.",
    )
    assess.set_defaults(func=_cmd_assess)

    dry = sub.add_parser(
        "client-day-dry",
        help="SAMPLE DESKTOP/host dry: sign (lab HMAC) → ready --strict-e2e → plan (no spawn)",
    )
    dry.add_argument(
        "--scope",
        default=None,
        help="unsigned SCOPE template (default examples/scope.client.example.yaml)",
    )
    dry.add_argument(
        "--work",
        default=None,
        help="work dir (default out/client_day_dry)",
    )
    dry.add_argument(
        "--export-from",
        default=None,
        dest="export_from",
        help="existing prove/run out/ to export; default seeds SAMPLE fixtures",
    )
    dry.add_argument(
        "--no-export",
        action="store_true",
        help="skip pack_drop (still sign / ready --strict-e2e / plan)",
    )
    dry.set_defaults(func=_cmd_client_day_dry)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ExportError, GateError) as exc:
        print(f"covey: {exc}", file=sys.stderr)
        return 2
    except CoveyError as exc:
        print(f"covey: {exc}", file=sys.stderr)
        return 1
