"""BYO rustscan argv + greppable parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import LiveAdapter, read_artifact_blob, require_target_prefix
from covey.errors import AdapterError

# Greppable: "127.0.0.1 -> [80,443]"  Accessible: "Open 127.0.0.1:80"
_GREPPABLE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+->\s+\[",
)
_OPEN = re.compile(
    r"(?i)\bOpen\s+(\d{1,3}(?:\.\d{1,3}){3}):\d+",
)


def parse_rustscan_live_hosts(text: str) -> list[str]:
    """Hosts rustscan reported with at least one open port. Banner IPs are ignored."""
    hosts: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        match = _GREPPABLE.match(line.strip()) or _OPEN.search(line)
        if not match:
            continue
        ip = match.group(1)
        if ip in seen:
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class RustscanAdapter(LiveAdapter):
    """Port discover on a tile; deepen is rustscan-only (no nmap passthrough)."""

    name = "rustscan"
    binary = "rustscan"

    def _argv(self, address: str) -> list[str]:
        return [
            "rustscan",
            "-a",
            address,
            "-p",
            self.pass2_ports,
            "--ulimit",
            "5000",
            "-g",
            "--no-banner",
            "--scripts",
            "none",
            "-n",
        ]

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return self._argv(target)

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        argv = self._argv("{hosts}")
        return argv

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("rustscan pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv(",".join(hosts))

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_rustscan_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> RustscanAdapter:
    return RustscanAdapter()
