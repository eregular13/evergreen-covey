"""BYO naabu argv + ip:port parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import LiveAdapter, read_artifact_blob, require_target_prefix
from covey.errors import AdapterError

# Silent/file lines: "127.0.0.1:18080"
_IP_PORT = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*$",
)


def parse_naabu_live_hosts(text: str) -> list[str]:
    """Hosts naabu reported with at least one open port. Banner IPs are ignored."""
    hosts: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        match = _IP_PORT.match(line.strip())
        if not match:
            continue
        ip = match.group(1)
        if ip in seen:
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class NaabuAdapter(LiveAdapter):
    """Port discover on a tile; deepen is naabu-only (connect scan)."""

    name = "naabu"
    binary = "naabu"

    def _argv(self, address: str, out_prefix: str) -> list[str]:
        return [
            "naabu",
            "-host",
            address,
            "-silent",
            "-p",
            self.pass2_ports,
            "-scan-type",
            "connect",
            "-o",
            f"{out_prefix}.txt",
        ]

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return self._argv(target, out_prefix)

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv("{hosts}", out_prefix)

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("naabu pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv(",".join(hosts), out_prefix)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_naabu_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> NaabuAdapter:
    return NaabuAdapter()
