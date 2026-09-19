"""Build a worker plan JSON without invoking scanners."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from covey.adapters.base import Adapter
from covey.adapters.registry import adapter_for
from covey.errors import AdapterError, ShardError
from covey.scope import Scope
from covey.shard import expand_network, parse_v4_network


@dataclass
class Worker:
    id: str
    shard_id: str
    target: str
    stage: str
    argv: list[str] | None = None
    argv_template: list[str] | None = None
    tool: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}


@dataclass
class Plan:
    adapter: str
    max_workers: int
    shards: list[str]
    workers: list[Worker]
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    signer: str = ""
    purpose: str = ""
    demo: bool = True
    deepen_ports: str | None = None
    deepen_host_timeout: str | None = None
    pipeline: list[str] = field(default_factory=list)

    @property
    def pass1_workers(self) -> list[Worker]:
        return [w for w in self.workers if w.stage == "pass1"]

    @property
    def pass2_workers(self) -> list[Worker]:
        return [w for w in self.workers if w.stage == "pass2"]

    @property
    def pipe_workers(self) -> list[Worker]:
        return [w for w in self.workers if w.stage.startswith("pipe:")]

    @property
    def ingest_workers(self) -> list[Worker]:
        return [w for w in self.workers if w.stage == "ingest"]

    def to_dict(self) -> dict[str, Any]:
        pipe = list(self.pipeline) if self.pipeline else [self.adapter]
        return {
            "adapter": self.adapter,
            "pipeline": pipe,
            "created_at": self.created_at,
            "signer": self.signer,
            "purpose": self.purpose,
            "demo": bool(self.demo),
            "deepen": {
                k: v
                for k, v in {
                    "ports": self.deepen_ports,
                    "host_timeout": self.deepen_host_timeout,
                }.items()
                if v
            },
            "max_workers": self.max_workers,
            "shards": list(self.shards),
            "workers": [w.to_dict() for w in self.workers],
        }


def _shard_id(index: int) -> str:
    return f"s{index:02d}"


def _scan_prefix(worker_id: str) -> str:
    # Relative to the runner cwd (the artifact root), so local + docker agree.
    return str(Path("shards") / worker_id / "scan")


def expand_scope_tiles(scope: Scope) -> list[str]:
    tiles: list[str] = []
    kinds = {getattr(target, "kind", "cidr") for target in scope.targets}
    if "file_drop" in kinds and kinds != {"file_drop"}:
        raise ShardError("file_drop cannot mix with live targets")
    for target in scope.targets:
        kind = getattr(target, "kind", "cidr") or "cidr"
        if kind == "file_drop":
            tiles.append(target.value)
            continue
        if kind in {"host", "url", "domain"}:
            tiles.append(target.value)
            continue
        net = parse_v4_network(target.cidr)
        for tile in expand_network(
            net, default_tile=scope.default_tile, small_tile=scope.small_tile
        ):
            tiles.append(str(tile))
    if not tiles:
        raise ShardError("SCOPE expanded to zero shards")
    if len(tiles) > scope.max_shards:
        raise ShardError(
            f"plan has {len(tiles)} shards; SCOPE max_shards={scope.max_shards}"
        )
    return tiles


def _ingest_plan(scope: Scope) -> Plan:
    """file_drop-only SCOPE: stage operator XML. Never spawn."""
    tiles = expand_scope_tiles(scope)
    workers: list[Worker] = []
    for index, tile in enumerate(tiles):
        shard_id = _shard_id(index)
        workers.append(
            Worker(
                id=f"drop-{shard_id}",
                shard_id=shard_id,
                target=tile,
                stage="ingest",
                tool="openvas",
            )
        )
    return Plan(
        adapter="openvas",
        pipeline=["openvas"],
        max_workers=min(scope.max_workers, 4),
        shards=tiles,
        workers=workers,
        signer=scope.signer,
        purpose=scope.purpose,
        demo=scope.demo,
        deepen_ports=scope.deepen.ports,
        deepen_host_timeout=scope.deepen.host_timeout,
    )


def build_plan(
    scope: Scope,
    *,
    out_root: Path | str = "out",
    adapter: Adapter | None = None,
) -> Plan:
    kinds = {getattr(target, "kind", "cidr") for target in scope.targets}
    if kinds == {"file_drop"}:
        return _ingest_plan(scope)

    pipeline = list(scope.pipeline) if scope.pipeline else [scope.adapter]
    if not pipeline:
        pipeline = [scope.adapter]
    plugin = adapter or adapter_for(pipeline[0], deepen=scope.deepen)
    if adapter is not None and hasattr(plugin, "apply_deepen"):
        plugin.apply_deepen(scope.deepen)
    if getattr(plugin, "file_drop_only", False):
        raise AdapterError(f"{plugin.name} is file_drop only")

    _ = out_root  # argv prefixes are cwd-relative; runner chdirs to the artifact root
    tiles = expand_scope_tiles(scope)
    chained = len(pipeline) > 1
    workers: list[Worker] = []
    for index, tile in enumerate(tiles):
        shard_id = _shard_id(index)
        p1_id = f"p1-{shard_id}"
        workers.append(
            Worker(
                id=p1_id,
                shard_id=shard_id,
                target=tile,
                stage="pass1",
                argv=plugin.pass1_argv(tile, _scan_prefix(p1_id)),
                tool=plugin.name,
            )
        )
        if chained:
            for step, name in enumerate(pipeline[1:], start=1):
                follow = adapter_for(name, deepen=scope.deepen)
                pipe_id = f"pipe{step:02d}-{shard_id}"
                workers.append(
                    Worker(
                        id=pipe_id,
                        shard_id=shard_id,
                        target=tile,
                        stage=f"pipe:{follow.name}",
                        argv_template=follow.pass2_argv_template(_scan_prefix(pipe_id)),
                        tool=follow.name,
                    )
                )
            continue
        p2_id = f"p2-{shard_id}"
        workers.append(
            Worker(
                id=p2_id,
                shard_id=shard_id,
                target=tile,
                stage="pass2",
                argv_template=plugin.pass2_argv_template(_scan_prefix(p2_id)),
                tool=plugin.name,
            )
        )

    return Plan(
        adapter=plugin.name,
        pipeline=pipeline,
        max_workers=scope.max_workers,
        shards=tiles,
        workers=workers,
        signer=scope.signer,
        purpose=scope.purpose,
        demo=scope.demo,
        deepen_ports=scope.deepen.ports,
        deepen_host_timeout=scope.deepen.host_timeout,
    )
