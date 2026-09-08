"""BYO netdiscover argv + ARP table parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, as_host32, require_target_prefix
from covey.errors import AdapterError


class NetdiscoverAdapter(LiveAdapter):
    name = "netdiscover"
    binary = "netdiscover"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return ["netdiscover", "-P", "-N", "-r", target]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["netdiscover", "-P", "-N", "-r", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("netdiscover pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        argv = ["netdiscover", "-P", "-N"]
        for host in hosts:
            argv.extend(["-r", as_host32(host)])
        return argv


def get_adapter() -> NetdiscoverAdapter:
    return NetdiscoverAdapter()
