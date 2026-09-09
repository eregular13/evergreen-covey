"""BYO sslscan argv + TLS-host parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    first_host,
    is_skipped_ip,
    open_port_row,
    read_artifact_blob,
    require_target_prefix,
    unique_services,
)
from covey.errors import AdapterError

# Success line: "Connected to 10.9.8.7" — ERROR lines also name the IP.
_CONNECTED = re.compile(
    r"^Connected to (\d{1,3}(?:\.\d{1,3}){3})\s*$",
    re.MULTILINE,
)
# Successful XML: <ssltest host="10.9.8.7" sniname="…" port="443">
_XML_HOST = re.compile(
    r'<ssltest\b[^>]*\bhost="(\d{1,3}(?:\.\d{1,3}){3})"',
)
_TESTING_PORT = re.compile(
    r"^Testing SSL server (\d{1,3}(?:\.\d{1,3}){3}) on port (\d+)\s*$",
    re.MULTILINE,
)
_XML_HOST_PORT = re.compile(
    r'<ssltest\b[^>]*\bhost="(\d{1,3}(?:\.\d{1,3}){3})"[^>]*\bport="(\d+)"',
)


def parse_sslscan_live_hosts(text: str) -> list[str]:
    """Hosts sslscan connected to. Connection-refused ERROR IPs are ignored."""
    hosts: list[str] = []
    seen: set[str] = set()
    for match in _CONNECTED.finditer(text or ""):
        ip = match.group(1)
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    for match in _XML_HOST.finditer(text or ""):
        ip = match.group(1)
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


def parse_sslscan_services(text: str) -> list[dict[str, str]]:
    """TLS ports sslscan connected to. Connection-refused ERROR IPs are ignored."""
    services: list[dict[str, str]] = []
    for match in _TESTING_PORT.finditer(text or ""):
        ip, port = match.group(1), match.group(2)
        if is_skipped_ip(ip):
            continue
        services.append(open_port_row(ip, port, service="tls"))
    for match in _XML_HOST_PORT.finditer(text or ""):
        ip, port = match.group(1), match.group(2)
        if is_skipped_ip(ip):
            continue
        services.append(open_port_row(ip, port, service="tls"))
    return unique_services(services)


class SslscanAdapter(LiveAdapter):
    """Host-oriented TLS probe. pass1 scans the first usable host of the tile.

    sslscan takes one target per invocation. Remaining pass2 hosts are
    appended for plan visibility; the binary uses the first.
    """

    name = "sslscan"
    binary = "sslscan"
    default_pass2_ports = "443"

    def _target(self, host: str) -> str:
        return f"{host}:{self.pass2_port_first}"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "sslscan",
            f"--xml={out_prefix}.xml",
            "--no-colour",
            self._target(first_host(target)),
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
            self._target(hosts[0]),
            *hosts[1:],
        ]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_sslscan_live_hosts(read_artifact_blob(artifact_dir))

    def parse_services(self, artifact_dir: Path) -> list[dict[str, str]]:
        return parse_sslscan_services(read_artifact_blob(artifact_dir))


def get_adapter() -> SslscanAdapter:
    return SslscanAdapter()
