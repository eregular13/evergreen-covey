"""BYO whatweb argv + URL-host parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from ipaddress import IPv4Address
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    is_skipped_ip,
    open_port_row,
    read_artifact_blob,
    require_target_prefix,
    tile_hosts,
    unique_services,
)
from covey.errors import AdapterError

# Brief log: "http://10.9.8.7 [200 OK]" / "http://honeypot:8081 [200 OK] ..."
# Leading URL host is the live signal. Plugin/banner IPs are ignored.
_URL_HOST = re.compile(
    r"^(https?)://([A-Za-z0-9._-]+)(?::(\d+))?\b",
    re.IGNORECASE,
)


def _skip_whatweb_host(host: str) -> bool:
    """Drop 0.0.0.0-class IPs. Hostnames from URL targets are live."""
    try:
        IPv4Address(host)
    except ValueError:
        return not host
    return is_skipped_ip(host)


def parse_whatweb_live_hosts(text: str) -> list[str]:
    """Hosts whatweb printed as live HTTP(S) URLs. Banner IPs are ignored."""
    hosts: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        match = _URL_HOST.match(line.strip())
        if not match:
            continue
        host = match.group(2)
        if host in seen or _skip_whatweb_host(host):
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def parse_whatweb_services(text: str) -> list[dict[str, str]]:
    """HTTP(S) URLs whatweb printed as live. Scheme default ports when omitted."""
    services: list[dict[str, str]] = []
    for line in (text or "").splitlines():
        match = _URL_HOST.match(line.strip())
        if not match:
            continue
        scheme = match.group(1).lower()
        host = match.group(2)
        if _skip_whatweb_host(host):
            continue
        port = match.group(3) or ("443" if scheme == "https" else "80")
        services.append(open_port_row(host, port, service=scheme))
    return unique_services(services)


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

    def parse_services(self, artifact_dir: Path) -> list[dict[str, str]]:
        return parse_whatweb_services(read_artifact_blob(artifact_dir))


def get_adapter() -> WhatwebAdapter:
    return WhatwebAdapter()
