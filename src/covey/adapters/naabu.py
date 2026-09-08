"""BYO naabu argv + ip:port parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix
from covey.errors import AdapterError


class NaabuAdapter(LiveAdapter):
    name = "naabu"
    binary = "naabu"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "naabu",
            "-host",
            target,
            "-silent",
            "-top-ports",
            "100",
            "-o",
            f"{out_prefix}.txt",
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "naabu",
            "-host",
            "{hosts}",
            "-silent",
            "-p",
            "22,80,443,3389,8080",
            "-o",
            f"{out_prefix}.txt",
        ]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("naabu pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "naabu",
            "-host",
            ",".join(hosts),
            "-silent",
            "-p",
            "22,80,443,3389,8080",
            "-o",
            f"{out_prefix}.txt",
        ]


def get_adapter() -> NaabuAdapter:
    return NaabuAdapter()
