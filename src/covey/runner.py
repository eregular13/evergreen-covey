"""Execute plan workers via local subprocess or docker run."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from covey.adapters import BINARY_ALIASES, adapter_for, tool_env_var
from covey.adapters.base import Adapter, materialize_template
from covey.errors import RunnerError
from covey.plan import Plan, Worker

NMAP_ENV = "COVEY_NMAP"
NMAP_IMAGE_ENV = "COVEY_NMAP_IMAGE"
BIN_ENV = "COVEY_BIN"
ENTRYPOINT_ENV = "COVEY_ENTRYPOINT"
DEFAULT_DOCKER_IMAGE = "instrumentisto/nmap"
DEFAULT_TIMEOUT_SEC = 120
RUSTSCAN_RELEASE = "2.4.1"
RUSTSCAN_LINUX_X64_URL = (
    "https://github.com/bee-san/RustScan/releases/download/"
    f"{RUSTSCAN_RELEASE}/x86_64-linux-rustscan.tar.gz.zip"
)


@dataclass
class ExecSpec:
    kind: str  # "local" | "docker"
    binary: str = ""  # local path/name or docker image
    display: str = ""
    entrypoint: str = ""
    nmap: str = ""  # backward-compat alias of binary

    def __post_init__(self) -> None:
        if not self.binary and self.nmap:
            self.binary = self.nmap
        elif not self.nmap and self.binary:
            self.nmap = self.binary
        if not self.entrypoint:
            raw = Path(self.binary).name if self.binary else "nmap"
            self.entrypoint = raw.split(":")[0] or "nmap"

    def wrap(self, argv: list[str], *, cwd: Path) -> list[str]:
        if not argv:
            raise RunnerError("empty argv")
        if self.kind == "local":
            wrapped = list(argv)
            wrapped[0] = self.binary
            return wrapped
        if self.kind == "docker":
            # Force entrypoint so images that already wrap the tool stay predictable.
            rest = argv[1:] if argv[0] == self.entrypoint else argv
            return [
                "docker",
                "run",
                "--rm",
                "--network",
                "host",
                "-v",
                f"{cwd.resolve()}:/work",
                "-w",
                "/work",
                "--entrypoint",
                self.entrypoint,
                self.binary,
                *rest,
            ]
        raise RunnerError(f"unknown exec kind {self.kind}")


@dataclass
class WorkerResult:
    id: str
    shard_id: str
    stage: str
    target: str
    argv: list[str]
    exit_code: int
    artifact_dir: str
    live_hosts: list[str] = field(default_factory=list)
    skipped: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.skipped or self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunReport:
    ok: bool
    exec: str
    max_workers: int
    pass1: list[WorkerResult]
    pass2: list[WorkerResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "exec": self.exec,
            "max_workers": self.max_workers,
            "pass1": [r.to_dict() for r in self.pass1],
            "pass2": [r.to_dict() for r in self.pass2],
        }

    def all_pass1_hosts(self) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for result in self.pass1:
            for host in result.live_hosts:
                if host not in seen:
                    seen.add(host)
                    hosts.append(host)
        return hosts


def _looks_like_docker_ref(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("docker://") or lowered.startswith("docker:")


def _strip_docker_prefix(value: str) -> str:
    if value.lower().startswith("docker://"):
        return value[len("docker://") :]
    if value.lower().startswith("docker:"):
        return value[len("docker:") :]
    return value


def _entrypoint_for(tool: str, *, image: str = "") -> str:
    specific = os.environ.get(f"{tool_env_var(tool)}_ENTRYPOINT", "").strip()
    generic = os.environ.get(ENTRYPOINT_ENV, "").strip()
    if specific:
        return specific
    if generic:
        return generic
    if image:
        name = Path(image).name.split(":")[0]
        if name:
            return name
    return tool


def _which_tool(tool: str) -> str | None:
    for candidate in BINARY_ALIASES.get(tool, (tool,)):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _spec_from_explicit(tool: str, explicit: str, *, env_name: str) -> ExecSpec:
    if _looks_like_docker_ref(explicit):
        image = _strip_docker_prefix(explicit).strip()
        if not image:
            raise RunnerError(f"{env_name} docker ref is empty")
        if not shutil.which("docker"):
            raise RunnerError(f"{env_name} is a docker ref but docker is not on PATH")
        return ExecSpec(
            kind="docker",
            binary=image,
            display=f"docker://{image}",
            entrypoint=_entrypoint_for(tool, image=image),
        )
    path = Path(explicit)
    if path.is_file():
        return ExecSpec(
            kind="local",
            binary=str(path),
            display=str(path),
            entrypoint=tool,
        )
    found = shutil.which(explicit)
    if found:
        return ExecSpec(kind="local", binary=found, display=found, entrypoint=tool)
    raise RunnerError(f"{env_name}={explicit!r} is not an executable or docker ref")


def resolve_exec(tool: str = "nmap", *, allow_missing: bool = False) -> ExecSpec:
    """Resolve a BYO binary: COVEY_<TOOL>, COVEY_BIN, PATH, optional docker://."""
    name = (tool or "nmap").strip().lower() or "nmap"
    env_name = tool_env_var(name)
    explicit = os.environ.get(env_name, "").strip()
    if explicit:
        return _spec_from_explicit(name, explicit, env_name=env_name)

    generic = os.environ.get(BIN_ENV, "").strip()
    if generic:
        return _spec_from_explicit(name, generic, env_name=BIN_ENV)

    found = _which_tool(name)
    if found:
        return ExecSpec(kind="local", binary=found, display=found, entrypoint=name)

    image_env = f"{env_name}_IMAGE"
    image = os.environ.get(image_env, "").strip()
    if not image and name == "nmap":
        image = os.environ.get(NMAP_IMAGE_ENV, "").strip()
    if image:
        if not shutil.which("docker"):
            raise RunnerError(f"{image_env} set but docker is not on PATH")
        return ExecSpec(
            kind="docker",
            binary=image,
            display=f"docker://{image}",
            entrypoint=_entrypoint_for(name, image=image),
        )

    if name == "nmap" and shutil.which("docker"):
        return ExecSpec(
            kind="docker",
            binary=DEFAULT_DOCKER_IMAGE,
            display=f"docker://{DEFAULT_DOCKER_IMAGE}",
            entrypoint="nmap",
        )

    if allow_missing:
        raise RunnerError(f"{name} not found")
    raise RunnerError(
        f"{name} not found on PATH. This is BYO: install {name}, set {env_name} "
        f"or {BIN_ENV}, or point {env_name} at docker://<image-that-has-{name}>"
    )


def resolve_nmap(*, allow_missing: bool = False) -> ExecSpec:
    return resolve_exec("nmap", allow_missing=allow_missing)


def _prepend_path(directory: Path) -> None:
    current = os.environ.get("PATH", "")
    prefix = str(directory)
    parts = [p for p in current.split(os.pathsep) if p]
    if prefix not in parts:
        os.environ["PATH"] = prefix + os.pathsep + current if current else prefix


def _install_rustscan_release() -> Path:
    """Download the official rustscan release onto this VM. Never into git."""
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64"}:
        raise RunnerError(
            f"no rustscan GitHub release mapping for machine={machine!r}; "
            "install rustscan yourself and set COVEY_RUSTSCAN"
        )
    dest_dir = Path.home() / ".local" / "bin"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "rustscan"
    try:
        with tempfile.TemporaryDirectory(prefix="covey-rustscan-") as tmp:
            work = Path(tmp)
            archive = work / "rustscan.tar.gz.zip"
            urllib.request.urlretrieve(RUSTSCAN_LINUX_X64_URL, archive)
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(work)
            tarballs = list(work.glob("*.tar.gz")) + list(work.glob("*.tgz"))
            if not tarballs:
                raise RunnerError("rustscan release zip did not contain a tarball")
            with tarfile.open(tarballs[0], "r:gz") as tf:
                tf.extractall(work)
            found = None
            for path in work.rglob("rustscan"):
                if path.is_file() and os.access(path, os.X_OK):
                    found = path
                    break
            if found is None:
                raise RunnerError("rustscan binary missing from extracted release")
            dest.write_bytes(found.read_bytes())
            dest.chmod(0o755)
    except urllib.error.URLError as exc:
        raise RunnerError(f"download rustscan {RUSTSCAN_RELEASE} failed: {exc}") from exc
    except RunnerError:
        raise
    except Exception as exc:
        raise RunnerError(f"unpack rustscan {RUSTSCAN_RELEASE} failed: {exc}") from exc
    if not dest.is_file():
        raise RunnerError("rustscan download finished but binary is missing")
    _prepend_path(dest_dir)
    return dest


def _cargo_install_rustscan() -> Path:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise RunnerError("cargo not on PATH; cannot cargo-install rustscan")
    root = Path.home() / ".local"
    completed = subprocess.run(
        [cargo, "install", "rustscan", "--locked", "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RunnerError(
            "cargo install rustscan failed: " + (completed.stderr or completed.stdout)[-400:]
        )
    dest = root / "bin" / "rustscan"
    if not dest.is_file():
        raise RunnerError("cargo install rustscan finished but binary is missing")
    _prepend_path(dest.parent)
    return dest


def ensure_rustscan(*, install_if_missing: bool = False) -> ExecSpec:
    """Resolve BYO rustscan. Optionally fetch a release onto this VM only."""
    try:
        return resolve_exec("rustscan")
    except RunnerError as missing:
        if not install_if_missing:
            raise
        last = missing
    errors: list[str] = [str(last)]
    try:
        path = _install_rustscan_release()
        return ExecSpec(
            kind="local",
            binary=str(path),
            display=str(path),
            entrypoint="rustscan",
        )
    except RunnerError as exc:
        errors.append(str(exc))
    try:
        path = _cargo_install_rustscan()
        return ExecSpec(
            kind="local",
            binary=str(path),
            display=str(path),
            entrypoint="rustscan",
        )
    except RunnerError as exc:
        errors.append(str(exc))
    raise RunnerError(
        "rustscan not available and prove-install failed (binary stays off git). "
        + " | ".join(errors)
    )


def ensure_nmap(*, install_if_missing: bool = False) -> ExecSpec:
    try:
        return resolve_nmap()
    except RunnerError:
        if not install_if_missing:
            raise
    if shutil.which("apt-get") is None:
        raise RunnerError("cannot prove-install nmap: apt-get not available")
    update = subprocess.run(
        ["sudo", "apt-get", "update"],
        check=False,
        capture_output=True,
        text=True,
    )
    if update.returncode != 0:
        raise RunnerError(f"apt-get update failed: {update.stderr[-400:]}")
    install = subprocess.run(
        ["sudo", "apt-get", "install", "-y", "nmap"],
        check=False,
        capture_output=True,
        text=True,
    )
    if install.returncode != 0:
        raise RunnerError(f"apt-get install nmap failed: {install.stderr[-400:]}")
    found = shutil.which("nmap")
    if not found:
        raise RunnerError("nmap installed but still not on PATH")
    return ExecSpec(kind="local", binary=found, display=found, entrypoint="nmap")


def ensure_fping(*, install_if_missing: bool = False) -> ExecSpec:
    """Resolve BYO fping. Optionally apt-install onto this VM only."""
    try:
        return resolve_exec("fping")
    except RunnerError:
        if not install_if_missing:
            raise
    if shutil.which("apt-get") is None:
        raise RunnerError("cannot prove-install fping: apt-get not available")
    update = subprocess.run(
        ["sudo", "apt-get", "update"],
        check=False,
        capture_output=True,
        text=True,
    )
    if update.returncode != 0:
        raise RunnerError(f"apt-get update failed: {update.stderr[-400:]}")
    install = subprocess.run(
        ["sudo", "apt-get", "install", "-y", "fping"],
        check=False,
        capture_output=True,
        text=True,
    )
    if install.returncode != 0:
        raise RunnerError(f"apt-get install fping failed: {install.stderr[-400:]}")
    found = shutil.which("fping")
    if not found:
        raise RunnerError("fping installed but still not on PATH")
    return ExecSpec(kind="local", binary=found, display=found, entrypoint="fping")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _scan_prefix(worker_id: str) -> str:
    return str(Path("shards") / worker_id / "scan")


def _write_stage_files(
    adapter: Adapter,
    worker: Worker,
    *,
    cwd: Path,
) -> None:
    prepare = getattr(adapter, "stage_files", None)
    if prepare is None:
        return
    files = prepare(worker.stage, worker.target, _scan_prefix(worker.id))
    if not files:
        return
    for rel, content in files.items():
        dest = Path(rel)
        if not dest.is_absolute():
            dest = cwd / dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def _run_one(
    worker: Worker,
    spec: ExecSpec,
    *,
    cwd: Path,
    timeout: int,
    adapter: Adapter,
) -> WorkerResult:
    if not worker.argv:
        raise RunnerError(f"worker {worker.id} has no concrete argv")
    artifact_dir = cwd / "shards" / worker.id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    _write_stage_files(adapter, worker, cwd=cwd)
    executed = spec.wrap(worker.argv, cwd=cwd)
    _write_text(artifact_dir / "argv.json", json.dumps(executed, indent=2) + "\n")
    _write_text(artifact_dir / "target.txt", worker.target + "\n")
    try:
        completed = subprocess.run(
            executed,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        _write_text(artifact_dir / "stdout.log", exc.stdout or "")
        _write_text(artifact_dir / "stderr.log", exc.stderr or "")
        _write_text(artifact_dir / "exit_code", "timeout\n")
        return WorkerResult(
            id=worker.id,
            shard_id=worker.shard_id,
            stage=worker.stage,
            target=worker.target,
            argv=executed,
            exit_code=124,
            artifact_dir=str(artifact_dir),
            error=f"timeout after {timeout}s",
        )

    _write_text(artifact_dir / "stdout.log", completed.stdout or "")
    _write_text(artifact_dir / "stderr.log", completed.stderr or "")
    _write_text(artifact_dir / "exit_code", f"{completed.returncode}\n")

    live: list[str] = []
    if worker.stage == "pass1":
        live = adapter.parse_live_hosts(artifact_dir)
        _write_text(
            artifact_dir / "live_hosts.json", json.dumps(live, indent=2) + "\n"
        )

    return WorkerResult(
        id=worker.id,
        shard_id=worker.shard_id,
        stage=worker.stage,
        target=worker.target,
        argv=executed,
        exit_code=completed.returncode,
        artifact_dir=str(artifact_dir),
        live_hosts=live,
    )


def _run_stage(
    workers: list[Worker],
    spec: ExecSpec,
    *,
    cwd: Path,
    max_workers: int,
    timeout: int,
    adapter: Adapter,
) -> list[WorkerResult]:
    if not workers:
        return []
    pool = max(1, min(max_workers, len(workers)))
    results: list[WorkerResult] = []
    with ThreadPoolExecutor(max_workers=pool) as executor:
        futures = {
            executor.submit(
                _run_one, worker, spec, cwd=cwd, timeout=timeout, adapter=adapter
            ): worker
            for worker in workers
        }
        for future in as_completed(futures):
            results.append(future.result())
    order = {worker.id: index for index, worker in enumerate(workers)}
    results.sort(key=lambda item: order.get(item.id, 0))
    return results


def _out_prefix_from_template(template: list[str]) -> str:
    for flag in ("-oA", "-oJ", "-oX", "-oL", "-oG", "-oN", "-o"):
        if flag in template:
            idx = template.index(flag)
            if idx + 1 < len(template):
                return _strip_out_suffix(template[idx + 1])
    for token in template:
        for prefix in (
            "--xml=",
            "--log-brief=",
            "--output=",
            "--output-file=",
        ):
            if token.startswith(prefix):
                return _strip_out_suffix(token[len(prefix) :])
    return "scan"


def _strip_out_suffix(path: str) -> str:
    text = path
    for suffix in (".json", ".xml", ".txt", ".gnmap", ".nmap", ".list"):
        if text.endswith(suffix):
            return text[: -len(suffix)]
    return text


def _materialize_pass2(
    plan: Plan,
    pass1: list[WorkerResult],
    adapter: Adapter,
) -> list[Worker]:
    live_by_shard = {result.shard_id: result.live_hosts for result in pass1}
    ready: list[Worker] = []
    for worker in plan.pass2_workers:
        hosts = [h for h in live_by_shard.get(worker.shard_id, []) if h]
        if not hosts:
            continue
        template = worker.argv_template or []
        prefix = _out_prefix_from_template(template)
        if prefix == "scan":
            prefix = _scan_prefix(worker.id)
        argv = adapter.pass2_argv(hosts, prefix)
        if not argv and template:
            argv = materialize_template(template, hosts)
        ready.append(
            Worker(
                id=worker.id,
                shard_id=worker.shard_id,
                target=",".join(hosts),
                stage="pass2",
                argv=argv,
            )
        )
    return ready


def run_plan(
    plan: Plan,
    *,
    out_root: Path | str = "out",
    spec: ExecSpec | None = None,
    adapter: Adapter | None = None,
    timeout: int = DEFAULT_TIMEOUT_SEC,
) -> RunReport:
    cwd = Path(out_root)
    cwd.mkdir(parents=True, exist_ok=True)
    plugin = adapter or adapter_for(plan.adapter)
    resolved = spec or resolve_exec(plugin.name)
    max_workers = max(1, min(plan.max_workers, 4))

    pass1 = _run_stage(
        plan.pass1_workers,
        resolved,
        cwd=cwd,
        max_workers=max_workers,
        timeout=timeout,
        adapter=plugin,
    )
    pass2_workers = _materialize_pass2(plan, pass1, plugin)
    pass2 = _run_stage(
        pass2_workers,
        resolved,
        cwd=cwd,
        max_workers=max_workers,
        timeout=timeout,
        adapter=plugin,
    )
    # Record skipped pass2 workers (no live hosts) so the report is complete.
    ran_ids = {item.id for item in pass2}
    for worker in plan.pass2_workers:
        if worker.id in ran_ids:
            continue
        artifact_dir = cwd / "shards" / worker.id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        _write_text(artifact_dir / "skipped.txt", "no live hosts from pass1\n")
        pass2.append(
            WorkerResult(
                id=worker.id,
                shard_id=worker.shard_id,
                stage="pass2",
                target="",
                argv=[],
                exit_code=0,
                artifact_dir=str(artifact_dir),
                skipped=True,
            )
        )
    pass2.sort(key=lambda item: item.id)

    for result in pass2:
        if result.skipped:
            continue
        allowed = set()
        for p1 in pass1:
            if p1.shard_id == result.shard_id:
                allowed.update(p1.live_hosts)
        targeted = [h for h in result.target.split(",") if h]
        extra = [h for h in targeted if h not in allowed]
        if extra:
            result.error = f"pass2 targeted hosts not in pass1: {extra}"
            result.exit_code = result.exit_code or 2

    ok = all(item.ok and not item.error for item in pass1 + pass2)
    report = RunReport(
        ok=ok,
        exec=resolved.display,
        max_workers=max_workers,
        pass1=pass1,
        pass2=pass2,
    )
    (cwd / "run_report.json").write_text(
        json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    return report
