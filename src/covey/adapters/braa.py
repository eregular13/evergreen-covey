"""BYO braa argv + OID-line parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix, tile_range
from covey.errors import AdapterError

SYS_DESCR = ".1.3.6.1.2.1.1.1.0"
SYS_NAME = ".1.3.6.1.2.1.1.5.0"


class BraaAdapter(LiveAdapter):
    name = "braa"
    binary = "braa"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        start, last = tile_range(target)
        return ["braa", f"public@{start}-{last}:{SYS_DESCR}"]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["braa", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("braa pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        queries: list[str] = []
        for host in hosts:
            queries.append(f"public@{host}:{SYS_DESCR}")
            queries.append(f"public@{host}:{SYS_NAME}")
        return ["braa", *queries]


def get_adapter() -> BraaAdapter:
    return BraaAdapter()
