"""BYO rustscan argv + greppable parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix
from covey.errors import AdapterError


class RustscanAdapter(LiveAdapter):
    """Port discover on a tile; deepen is rustscan-only (no nmap passthrough)."""

    name = "rustscan"
    binary = "rustscan"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "rustscan",
            "-a",
            target,
            "--ulimit",
            "5000",
            "-g",
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "rustscan",
            "-a",
            "{hosts}",
            "--ulimit",
            "5000",
            "-g",
            "-p",
            "22,80,443,3389,8080",
        ]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("rustscan pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "rustscan",
            "-a",
            ",".join(hosts),
            "--ulimit",
            "5000",
            "-g",
            "-p",
            "22,80,443,3389,8080",
        ]


def get_adapter() -> RustscanAdapter:
    return RustscanAdapter()
