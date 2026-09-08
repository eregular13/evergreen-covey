"""BYO whatweb argv + URL-host parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    is_skipped_ip,
    read_artifact_blob,
    require_target_prefix,
    tile_hosts,
)
from covey.errors import AdapterError

# Brief log: "http://10.9.8.7 [200 OK]" / "http://127.0.0.1:18080 [200 OK] ..."
# Leading URL host is the live signal. Plugin/banner IPs are ignored.
_URL_HOST = re.compile(
    r"^https?://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\b",
    re.IGNORECASE,
)


def parse_whatweb_live_hosts(text: str) -> list[str]:
    """Hosts whatweb printed as live HTTP(S) URLs. Banner IPs are ignored."""
    hosts: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        match = _URL_HOST.match(line.strip())
        if not match:
            continue
        ip = match.group(1)
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class WhatwebAdapter(LiveAdapter):
    """HTTP fingerprint. pass1 expands the tile in Python and shells only whatweb."""

    name = "whatweb"
    binary = "whatweb"
    default_pass2_ports = "80"

    def _url(self, host: str) -> str:
        return f"http://{host}:{self.pass2_port_first}"

    def _argv(self, out_prefix: str, aggression: str, targets: list[str]) -> list[str]:
        return [
            "whatweb",
            f"--log-brief={out_prefix}.txt",
            "--no-errors",
            "--colour=never",
            "-a",
            aggression,
            *targets,
        ]

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return self._argv(out_prefix, "1", [self._url(host) for host in tile_hosts(target)])

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv(out_prefix, "3", ["{hosts}"])

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("whatweb pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv(out_prefix, "3", [self._url(host) for host in hosts])

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_whatweb_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> WhatwebAdapter:
    return WhatwebAdapter()
