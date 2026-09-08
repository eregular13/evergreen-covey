"""BYO zmap argv + one-IP-per-line parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, as_host32, require_target_prefix
from covey.errors import AdapterError


class ZmapAdapter(LiveAdapter):
    """Internet-scale SYN sweeper reused as a SCOPE-tiled probe.

    ``-B /dev/null`` disables the default public-blocklist so RFC1918 lab
    tiles are actually scanned. That is BYO/operator policy, not a spray.
    """

    name = "zmap"
    binary = "zmap"
    default_pass2_ports = "443"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "zmap",
            "-p",
            "80",
            "-o",
            f"{out_prefix}.txt",
            "-B",
            "/dev/null",
            "--verbosity=0",
            target,
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "zmap",
            "-p",
            self.pass2_port_first,
            "-o",
            f"{out_prefix}.txt",
            "-B",
            "/dev/null",
            "--verbosity=0",
            "{hosts}",
        ]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("zmap pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "zmap",
            "-p",
            self.pass2_port_first,
            "-o",
            f"{out_prefix}.txt",
            "-B",
            "/dev/null",
            "--verbosity=0",
            *[as_host32(host) for host in hosts],
        ]


def get_adapter() -> ZmapAdapter:
    return ZmapAdapter()
