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
    deepen_ports: str | None = None
    deepen_host_timeout: str | None = None

    @property
    def pass1_workers(self) -> list[Worker]:
        return [w for w in self.workers if w.stage == "pass1"]

    @property
    def pass2_workers(self) -> list[Worker]:
        return [w for w in self.workers if w.stage == "pass2"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "created_at": self.created_at,
            "signer": self.signer,
            "purpose": self.purpose,
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
    for target in scope.targets:
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


def build_plan(
    scope: Scope,
    *,
    out_root: Path | str = "out",
    adapter: Adapter | None = None,
) -> Plan:
    plugin = adapter or adapter_for(scope.adapter, deepen=scope.deepen)
    if adapter is not None and hasattr(plugin, "apply_deepen"):
        plugin.apply_deepen(scope.deepen)
    if getattr(plugin, "file_drop_only", False):
        raise AdapterError(f"{plugin.name} is file_drop only")

    _ = out_root  # argv prefixes are cwd-relative; runner chdirs to the artifact root
    tiles = expand_scope_tiles(scope)
    workers: list[Worker] = []
    for index, tile in enumerate(tiles):
        shard_id = _shard_id(index)
        p1_id = f"p1-{shard_id}"
        p2_id = f"p2-{shard_id}"
        workers.append(
            Worker(
                id=p1_id,
                shard_id=shard_id,
                target=tile,
                stage="pass1",
                argv=plugin.pass1_argv(tile, _scan_prefix(p1_id)),
            )
        )
        workers.append(
            Worker(
                id=p2_id,
                shard_id=shard_id,
                target=tile,
                stage="pass2",
                argv_template=plugin.pass2_argv_template(_scan_prefix(p2_id)),
            )
        )

    return Plan(
        adapter=plugin.name,
        max_workers=scope.max_workers,
        shards=tiles,
        workers=workers,
        signer=scope.signer,
        purpose=scope.purpose,
        deepen_ports=scope.deepen.ports,
        deepen_host_timeout=scope.deepen.host_timeout,
    )
