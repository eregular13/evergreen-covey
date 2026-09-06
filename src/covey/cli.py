"""CLI: python -m covey plan|run|prove|sign."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from covey import __version__
from covey.errors import CoveyError
from covey.plan import build_plan
from covey.prove import run_prove
from covey.runner import resolve_nmap, run_plan
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
    spec = resolve_nmap()
    report = run_plan(plan, out_root=out_root, spec=spec)
    print(f"run {'ok' if report.ok else 'failed'} via {report.exec}")
    print(f"  pass1 live hosts: {', '.join(report.all_pass1_hosts()) or '(none)'}")
    return 0 if report.ok else 1


def _cmd_prove(args: argparse.Namespace) -> int:
    summary = run_prove(
        out_root=Path(args.out),
        scope_path=Path(args.scope) if args.scope else None,
        install_if_missing=not args.no_install,
    )
    print("Evergreen Covey prove: OK")
    print(f"  exec        {summary['exec']}")
    print(f"  shards      {len(summary['shards'])} ({', '.join(summary['shards'])})")
    print(f"  pass1       {summary['pass1_workers']} workers")
    print(f"  pass2 ran   {summary['pass2_ran']}")
    print(f"  live hosts  {', '.join(summary['live_hosts'])}")
    print(f"  artifacts   {summary['out']}/shards/")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    path = Path(args.scope)
    signed = sign_file(path, in_place=True)
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

    run = sub.add_parser("run", help="execute a plan (requires BYO nmap)")
    run.add_argument("--scope", required=True, help="signed SCOPE YAML")
    run.add_argument("--out", default="out")
    run.set_defaults(func=_cmd_run)

    prove = sub.add_parser("prove", help="signed loopback lab: shard, run, assert artifacts")
    prove.add_argument("--scope", default=None, help="override lab SCOPE (default examples/scope.lab.yaml)")
    prove.add_argument("--out", default="out")
    prove.add_argument(
        "--no-install",
        action="store_true",
        help="do not apt-get install nmap if missing (fail instead)",
    )
    prove.set_defaults(func=_cmd_prove)

    sign = sub.add_parser("sign", help="HMAC-sign a demo SCOPE in place")
    sign.add_argument("--scope", required=True)
    sign.set_defaults(func=_cmd_sign)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CoveyError as exc:
        print(f"covey: {exc}", file=sys.stderr)
        return 1
