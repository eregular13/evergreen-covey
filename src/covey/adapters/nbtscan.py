"""BYO nbtscan argv + NetBIOS table parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix


class NbtscanAdapter(LiveAdapter):
    name = "nbtscan"
    binary = "nbtscan"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return ["nbtscan", "-s", ":", "-t", "500", target]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["nbtscan", "-v", "-s", ":", "{hosts}"]


def get_adapter() -> NbtscanAdapter:
    return NbtscanAdapter()
