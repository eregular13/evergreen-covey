"""Reusable adapter protocol. Later BYO tools plug in here."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class Adapter(Protocol):
    """Shard/stage kit every live adapter must implement.

    OpenVAS-class tools are **not** live adapters. They may only ingest
    operator-dropped files (see adapters/README.md). ``file_drop_only``
    adapters must raise if asked for argv.
    """

    name: str
    file_drop_only: bool

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        """Discover argv for one shard. Must not invoke the scanner."""
        ...

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        """Deepen argv template. Use the token ``{hosts}`` for live hosts."""
        ...

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        """Concrete pass2 argv against hosts found live in pass1."""
        ...

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        """Read pass1 artifacts and return live IPv4 hosts."""
        ...


def materialize_template(template: list[str], hosts: list[str]) -> list[str]:
    """Replace a ``{hosts}`` token with one argv entry per host."""
    if not hosts:
        raise ValueError("pass2 refuses an empty host list")
    out: list[str] = []
    replaced = False
    for token in template:
        if token == "{hosts}":
            out.extend(hosts)
            replaced = True
        else:
            out.append(token)
    if not replaced:
        out.extend(hosts)
    return out
