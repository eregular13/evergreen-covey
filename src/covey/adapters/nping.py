"""BYO nping argv + RCVD-host parse. Never locates or ships the binary."""

from __future__ import annotations

from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    read_artifact_blob,
    require_target_prefix,
    tile_hosts,
    unique_ipv4s,
)


class NpingAdapter(LiveAdapter):
    name = "nping"
    binary = "nping"
    default_pass2_ports = "80"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        hosts = tile_hosts(target)
        return ["nping", "--icmp", "-c", "1", "--delay", "200ms", *hosts]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["nping", "--tcp", "-p", self.pass2_port_first, "-c", "1", "--delay", "200ms", "{hosts}"]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        blob = read_artifact_blob(artifact_dir)
        replies = "\n".join(line for line in blob.splitlines() if "RCVD" in line)
        return unique_ipv4s(replies) or unique_ipv4s(blob)


def get_adapter() -> NpingAdapter:
    return NpingAdapter()
