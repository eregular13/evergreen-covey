"""BYO unicornscan argv + TCP-open parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    is_skipped_ip,
    open_port_row,
    read_artifact_blob,
    require_target_prefix,
    unique_services,
)
from covey.errors import AdapterError

# Immediate: "TCP open 10.9.8.7:80  ttl 64"
# Default report: "TCP open         unknown[18080]		from 127.0.0.1  ttl 127"
# "TCP closed" names the IP but is not a live host.
_OPEN_IP_PORT = re.compile(
    r"(?i)^TCP open\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\b"
)
_OPEN_FROM = re.compile(
    r"(?i)^TCP open\b.*\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b"
)
_OPEN_FROM_PORT = re.compile(
    r"(?i)^TCP open\b.*\[(\d+)\].*\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b"
)

# Source outside the signed 127.0.0.0/28 lab so a tile that contains
# 127.0.0.1 is not a self-scan (that finds 0). lo owns 127/8.
LOOPBACK_SOURCE = "127.0.0.254"


def parse_unicornscan_live_hosts(text: str) -> list[str]:
    """Hosts unicornscan printed as ``TCP open``. Closed/RST IPs are ignored."""
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.lower().startswith("tcp open"):
            continue
        match = _OPEN_IP_PORT.match(line) or _OPEN_FROM.match(line)
        if not match:
            continue
        ip = match.group(1)
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


def parse_unicornscan_services(text: str) -> list[dict[str, str]]:
    """TCP-open ports unicornscan printed. ``TCP closed`` is ignored."""
    services: list[dict[str, str]] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.lower().startswith("tcp open"):
            continue
        direct = _OPEN_IP_PORT.match(line)
        if direct:
            ip, port = direct.group(1), direct.group(2)
            if not is_skipped_ip(ip):
                services.append(open_port_row(ip, port))
            continue
        reported = _OPEN_FROM_PORT.match(line)
        if reported:
            port, ip = reported.group(1), reported.group(2)
            if not is_skipped_ip(ip):
                services.append(open_port_row(ip, port))
    return unique_services(services)


def _is_loopback_token(token: str) -> bool:
    text = (token or "").strip()
    if not text:
        return False
    if "/" in text:
        try:
            net = ip_network(text, strict=False)
        except ValueError:
            return False
        return isinstance(net, IPv4Network) and net.network_address.is_loopback
    try:
        addr = ip_address(text)
    except ValueError:
        return False
    return isinstance(addr, IPv4Address) and addr.is_loopback


class UnicornscanAdapter(LiveAdapter):
    """TCP SYN sweeper. pass2 re-scans pass1-live hosts.

    Loopback tiles need ``-i lo`` (default iface is the gateway NIC) and a
    source IP that is not in the tile. A same-IP self-scan on lo finds 0.
    That is lab-enabling argv, not a forged result — unicornscan itself
    must still print ``TCP open``.

    Two unicornscan processes on the same UID collide on
    ``/tmp/unicornscan-<uid>/{send,listen}``. The lab SCOPE uses
    ``max_workers: 1`` so tiles run sequentially.
    """

    name = "unicornscan"
    binary = "unicornscan"
    default_pass2_ports = "22,80,443,3389"

    def _loopback_flags(self, *tokens: str) -> list[str]:
        if any(_is_loopback_token(token.split(":", 1)[0]) for token in tokens if token):
            return ["-i", "lo", "-s", LOOPBACK_SOURCE]
        return []

    def _flags(self, *tokens: str) -> list[str]:
        return ["unicornscan", "-mT", *self._loopback_flags(*tokens)]

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [*self._flags(target), f"{target}:{self.pass2_ports}"]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["unicornscan", "-mT", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("unicornscan pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            *self._flags(*hosts),
            *[f"{host}:{self.pass2_ports}" for host in hosts],
        ]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_unicornscan_live_hosts(read_artifact_blob(artifact_dir))

    def parse_services(self, artifact_dir: Path) -> list[dict[str, str]]:
        return parse_unicornscan_services(read_artifact_blob(artifact_dir))


def get_adapter() -> UnicornscanAdapter:
    return UnicornscanAdapter()
