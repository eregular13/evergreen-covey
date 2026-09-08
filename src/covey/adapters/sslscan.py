"""BYO sslscan argv + TLS-host parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, first_host, require_target_prefix
from covey.errors import AdapterError


class SslscanAdapter(LiveAdapter):
    """Host-oriented TLS probe. pass1 scans the first usable host of the tile.

    sslscan takes one target per invocation. Remaining pass2 hosts are
    appended for plan visibility; the binary uses the first.
    """

    name = "sslscan"
    binary = "sslscan"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "sslscan",
            f"--xml={out_prefix}.xml",
            "--no-colour",
            first_host(target),
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "sslscan",
            f"--xml={out_prefix}.xml",
            "--show-certificate",
            "--no-colour",
            "{hosts}",
        ]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("sslscan pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "sslscan",
            f"--xml={out_prefix}.xml",
            "--show-certificate",
            "--no-colour",
            hosts[0],
            *hosts[1:],
        ]


def get_adapter() -> SslscanAdapter:
    return SslscanAdapter()
