"""BYO httpx argv + URL parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import (
    LiveAdapter,
    hosts_file_path,
    require_target_prefix,
    tile_hosts,
)
from covey.errors import AdapterError


class HttpxAdapter(LiveAdapter):
    """HTTP banner deepener. pass1 probes every usable host of the tile via -l."""

    name = "httpx"
    binary = "httpx"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "httpx",
            "-silent",
            "-l",
            hosts_file_path(out_prefix),
            "-o",
            f"{out_prefix}.txt",
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "httpx",
            "-silent",
            "-title",
            "-status-code",
            "-tech-detect",
            "-l",
            hosts_file_path(out_prefix),
            "-o",
            f"{out_prefix}.txt",
        ]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("httpx pass2 deepen refuses empty live-host list")
        return self.pass2_argv_template(out_prefix)

    def stage_files(self, stage: str, target: str, out_prefix: str) -> dict[str, str]:
        if stage == "pass2":
            hosts = [part.strip() for part in target.split(",") if part.strip()]
        else:
            hosts = tile_hosts(target)
        return {hosts_file_path(out_prefix): "".join(f"{host}\n" for host in hosts)}


def get_adapter() -> HttpxAdapter:
    return HttpxAdapter()
