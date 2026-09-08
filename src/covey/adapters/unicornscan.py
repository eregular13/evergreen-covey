"""BYO unicornscan argv + TCP-open parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix
from covey.errors import AdapterError


class UnicornscanAdapter(LiveAdapter):
    name = "unicornscan"
    binary = "unicornscan"
    default_pass2_ports = "22,80,443,3389"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return ["unicornscan", "-mT", f"{target}:80,443"]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["unicornscan", "-mT", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("unicornscan pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return ["unicornscan", "-mT", *[f"{host}:{self.pass2_ports}" for host in hosts]]


def get_adapter() -> UnicornscanAdapter:
    return UnicornscanAdapter()
