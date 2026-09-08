"""End-to-end prove: BYO nmap, sharded loopback, multi-pass artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from covey.adapters.registry import adapter_for
from covey.errors import CoveyError, RunnerError
from covey.plan import build_plan
from covey.runner import ensure_nmap, run_plan
from covey.scope import load

LAB_SCOPE = Path("examples/scope.lab.yaml")


def _artifact_ok(directory: Path) -> bool:
    return (directory / "scan.xml").is_file() or (directory / "scan.gnmap").is_file()


def assert_report(plan, report, out_root: Path) -> None:
    if len(plan.shards) < 2 and len(plan.pass1_workers) < 2:
        raise RunnerError("prove requires ≥2 shards or ≥2 pass1 workers")
    if not report.pass1:
        raise RunnerError("prove: no pass1 workers ran")
    failed = [r for r in report.pass1 if not r.ok]
    if failed:
        raise RunnerError(
            "prove: pass1 workers failed: "
            + ", ".join(f"{r.id}={r.exit_code}" for r in failed)
        )

    landed = 0
    for result in report.pass1:
        artifact_dir = Path(result.artifact_dir)
        if _artifact_ok(artifact_dir):
            landed += 1
        else:
            raise RunnerError(f"prove: missing XML/gnmap under {artifact_dir}")

    live = report.all_pass1_hosts()
    if not live:
        raise RunnerError("prove: pass1 found no live hosts on the loopback lab")

    ran_pass2 = [r for r in report.pass2 if not r.skipped]
    if not ran_pass2:
        raise RunnerError("prove: pass2 did not run against any live hosts")

    allowed = set(live)
    for result in ran_pass2:
        if not _artifact_ok(Path(result.artifact_dir)):
            raise RunnerError(f"prove: missing pass2 artifacts under {result.artifact_dir}")
        targeted = [h for h in result.target.split(",") if h]
        extra = [h for h in targeted if h not in allowed]
        if extra:
            raise RunnerError(
                f"prove: pass2 {result.id} targeted hosts not in pass1: {extra}"
            )
        if not targeted:
            raise RunnerError(f"prove: pass2 {result.id} had no targets")
        if not result.ok:
            raise RunnerError(f"prove: pass2 {result.id} failed ({result.exit_code})")

    if not (out_root / "run_report.json").is_file():
        raise RunnerError("prove: run_report.json missing")
    if not report.ok:
        raise RunnerError("prove: runner report is not ok")
    if landed < 2:
        raise RunnerError("prove: expected artifacts for at least two shards")


def run_prove(
    *,
    out_root: Path | str = "out",
    scope_path: Path | str | None = None,
    install_if_missing: bool = True,
) -> dict:
    out = Path(out_root)
    out.mkdir(parents=True, exist_ok=True)
    path = Path(scope_path) if scope_path else LAB_SCOPE
    if not path.is_file():
        raise RunnerError(f"prove SCOPE not found: {path}")

    spec = ensure_nmap(install_if_missing=install_if_missing)
    scope = load(path)
    adapter = adapter_for(scope.adapter, deepen=scope.deepen)
    plan = build_plan(scope, out_root=out, adapter=adapter)
    plan_path = out / "plan.json"
    plan_path.write_text(json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")

    report = run_plan(plan, out_root=out, spec=spec, adapter=adapter)
    assert_report(plan, report, out)
    summary = {
        "ok": True,
        "exec": spec.display,
        "shards": plan.shards,
        "pass1_workers": len(plan.pass1_workers),
        "pass2_ran": sum(1 for r in report.pass2 if not r.skipped),
        "live_hosts": report.all_pass1_hosts(),
        "out": str(out),
    }
    (out / "prove.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    del argv
    try:
        summary = run_prove()
    except CoveyError as exc:
        print(f"prove failed: {exc}")
        return 1
    print("Evergreen Covey prove: OK")
    print(f"  exec        {summary['exec']}")
    print(f"  shards      {len(summary['shards'])} ({', '.join(summary['shards'])})")
    print(f"  pass1       {summary['pass1_workers']} workers")
    print(f"  pass2 ran   {summary['pass2_ran']}")
    print(f"  live hosts  {', '.join(summary['live_hosts'])}")
    print(f"  artifacts   {summary['out']}/shards/")
    return 0
