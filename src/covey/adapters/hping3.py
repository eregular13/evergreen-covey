"""BYO hping3 argv + ip= parse. Never locates or ships the binary."""

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


class Hping3Adapter(LiveAdapter):
    """ICMP to the tile broadcast, then SYN deepen on one host.

    hping3 takes a single destination. pass1 pings the tile broadcast so
    replies can name individual live hosts. pass2 SYN-probes the first
    live host (remaining hosts are appended for plan visibility; the
    binary uses the first).
    """

    name = "hping3"
    binary = "hping3"
    default_pass2_ports = "80"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return ["hping3", "--icmp", "-c", "3", tile_broadcast(target)]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["hping3", "--syn", "-p", self.pass2_port_first, "-c", "2", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("hping3 pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return ["hping3", "--syn", "-p", self.pass2_port_first, "-c", "2", first_host(hosts[0]), *hosts[1:]]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        blob = read_artifact_blob(artifact_dir)
        replies = "\n".join(line for line in blob.splitlines() if "ip=" in line)
        return unique_ipv4s(replies) or unique_ipv4s(blob)


def get_adapter() -> Hping3Adapter:
    return Hping3Adapter()
