"""BYO iputils ping argv + ICMP-reply parse. Never locates or ships the binary."""

from __future__ import annotations

from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    first_host,
    read_artifact_blob,
    require_target_prefix,
    tile_broadcast,
    unique_ipv4s,
)
from covey.errors import AdapterError


class PingAdapter(LiveAdapter):
    """Broadcast ICMP discover, then unicast ping of the first live host.

    iputils ``ping`` is one destination per invocation. pass1 uses ``-b``
    against the tile broadcast so replies can name live hosts. pass2
    unicast-pings the first live host (remaining hosts appended).
    """

    name = "ping"
    binary = "ping"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return ["ping", "-c", "2", "-n", "-b", tile_broadcast(target)]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["ping", "-c", "3", "-n", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("ping pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return ["ping", "-c", "3", "-n", first_host(hosts[0]), *hosts[1:]]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        blob = read_artifact_blob(artifact_dir)
        replies = "\n".join(
            line for line in blob.splitlines() if " bytes from " in line.lower()
        )
        return unique_ipv4s(replies) or unique_ipv4s(blob)


def get_adapter() -> PingAdapter:
    return PingAdapter()
