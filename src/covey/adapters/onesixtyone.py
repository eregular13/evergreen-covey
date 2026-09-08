"""BYO onesixtyone argv + community parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import (
    LiveAdapter,
    comm_file_path,
    hosts_file_path,
    require_target_prefix,
    tile_hosts,
)
from covey.errors import AdapterError


class OnesixtyoneAdapter(LiveAdapter):
    """SNMP community sweeper. Hosts/communities land as runner sidecars."""

    name = "onesixtyone"
    binary = "onesixtyone"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "onesixtyone",
            "-c",
            comm_file_path(out_prefix),
            "-i",
            hosts_file_path(out_prefix),
            "-o",
            f"{out_prefix}.txt",
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "onesixtyone",
            "-c",
            comm_file_path(out_prefix),
            "-i",
            hosts_file_path(out_prefix),
            "-o",
            f"{out_prefix}.txt",
        ]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("onesixtyone pass2 deepen refuses empty live-host list")
        return self.pass2_argv_template(out_prefix)

    def stage_files(self, stage: str, target: str, out_prefix: str) -> dict[str, str]:
        if stage == "pass2":
            hosts = [part.strip() for part in target.split(",") if part.strip()]
            communities = "public\nprivate\ncommunity\n"
        else:
            hosts = tile_hosts(target)
            communities = "public\nprivate\n"
        return {
            hosts_file_path(out_prefix): "".join(f"{host}\n" for host in hosts),
            comm_file_path(out_prefix): communities,
        }


def get_adapter() -> OnesixtyoneAdapter:
    return OnesixtyoneAdapter()
