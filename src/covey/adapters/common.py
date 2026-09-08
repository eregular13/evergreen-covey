"""Shared BYO adapter helpers. No scanner binaries, no spawn."""

from __future__ import annotations

import json
import re
from ipaddress import IPv4Address, IPv4Network, ip_network
from pathlib import Path

from covey.adapters.base import materialize_template
from covey.errors import AdapterError

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Skip addresses that show up in banners/flags but are never "live hosts".
_SKIP_IPS = frozenset(
    {
        "0.0.0.0",
        "255.255.255.255",
    }
)

ARTIFACT_CANDIDATES = (
    "scan.xml",
    "scan.gnmap",
    "scan.json",
    "scan.txt",
    "scan.list",
    "scan.out",
    "stdout.log",
    "stderr.log",
)

HOST_CAP = 256


def require_target_prefix(target: str, out_prefix: str, *, name: str) -> None:
    if not target or not out_prefix:
        raise AdapterError(f"{name} requires target and out_prefix")


def parse_tile_network(target: str) -> IPv4Network | None:
    token = (target or "").strip()
    if not token:
        return None
    if "," in token or " " in token:
        return None
    try:
        net = ip_network(token, strict=False)
    except ValueError:
        return None
    if not isinstance(net, IPv4Network):
        raise AdapterError(f"IPv6 targets are not accepted: {token}")
    return net


def tile_hosts(target: str, *, cap: int = HOST_CAP) -> list[str]:
    """Expand a CIDR/host token to IPv4 strings for host-oriented tools.

    Covey already tiles SCOPE; a /30 is two hosts. A /24 is capped at 256.
    """
    net = parse_tile_network(target)
    if net is None:
        hosts = [part.strip() for part in re.split(r"[\s,]+", target or "") if part.strip()]
        return hosts[:cap]
    usable = [str(ip) for ip in net.hosts()]
    if not usable:
        return [str(net.network_address)]
    return usable[:cap]


def first_host(target: str) -> str:
    hosts = tile_hosts(target, cap=1)
    if not hosts:
        raise AdapterError(f"cannot expand {target!r} to a host")
    return hosts[0]


def tile_broadcast(target: str) -> str:
    net = parse_tile_network(target)
    if net is None:
        return first_host(target)
    return str(net.broadcast_address)


def tile_range(target: str) -> tuple[str, str]:
    """Inclusive first-last IPv4 pair for range-oriented CLIs (braa)."""
    net = parse_tile_network(target)
    if net is None:
        host = first_host(target)
        return host, host
    return str(net.network_address), str(net.broadcast_address)


def as_host32(host: str) -> str:
    text = host.strip()
    if "/" in text:
        return text
    return f"{text}/32"


def hosts_file_path(out_prefix: str) -> str:
    return f"{out_prefix}.hosts"


def comm_file_path(out_prefix: str) -> str:
    return f"{out_prefix}.comm"


def is_skipped_ip(ip: str) -> bool:
    if ip in _SKIP_IPS:
        return True
    try:
        addr = IPv4Address(ip)
    except ValueError:
        return True
    return addr.is_multicast or addr.is_unspecified


def unique_ipv4s(text: str) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for match in IPV4_RE.finditer(text or ""):
        ip = match.group(0)
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


def read_artifact_blob(artifact_dir: Path) -> str:
    chunks: list[str] = []
    seen: set[Path] = set()
    for name in ARTIFACT_CANDIDATES:
        path = artifact_dir / name
        if path.is_file() and path not in seen:
            seen.add(path)
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    if artifact_dir.is_dir():
        for path in sorted(artifact_dir.glob("scan.*")):
            if path.is_file() and path not in seen:
                seen.add(path)
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def parse_masscan_json(text: str) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    blob = (text or "").strip()
    if blob.startswith("["):
        try:
            records = json.loads(blob)
        except json.JSONDecodeError:
            records = None
        if isinstance(records, list):
            for item in records:
                ip = _masscan_record_ip(item)
                if ip and ip not in seen:
                    seen.add(ip)
                    hosts.append(ip)
            return hosts
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line in {"[", "]", ","}:
            continue
        if line.endswith(","):
            line = line[:-1]
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = _masscan_record_ip(item)
        if ip and ip not in seen:
            seen.add(ip)
            hosts.append(ip)
    return hosts


def _masscan_record_ip(item: object) -> str | None:
    if not isinstance(item, dict):
        return None
    ip = item.get("ip")
    if not isinstance(ip, str) or is_skipped_ip(ip):
        return None
    ports = item.get("ports")
    if isinstance(ports, list) and ports:
        openish = False
        for port in ports:
            if not isinstance(port, dict):
                continue
            status = str(port.get("status") or "open").lower()
            if status in {"open", "open|filtered"}:
                openish = True
                break
        if not openish:
            return None
    return ip


def first_port(spec: str) -> str:
    """First scalar port from a SCOPE/nmap-style list (``22,80`` / ``T:22``)."""
    token = (spec or "").split(",")[0].strip()
    token = token.split("-")[0].strip()
    if ":" in token:
        token = token.rsplit(":", 1)[-1].strip()
    return token


class LiveAdapter:
    """Tiny base so each BYO tool only fills argv + parse notes."""

    name: str = ""
    file_drop_only: bool = False
    binary: str = ""
    default_pass2_ports: str = "22,80,443,3389,8080"

    def __init__(self) -> None:
        self.pass2_ports = self.default_pass2_ports
        self.host_timeout: str | None = None

    def apply_deepen(self, deepen: object) -> None:
        """Honor SCOPE pass2/deepen ports. Adapter defaults stay if omitted."""
        ports = getattr(deepen, "ports", None)
        if ports:
            self.pass2_ports = str(ports)
        timeout = getattr(deepen, "host_timeout", None)
        if timeout:
            self.host_timeout = str(timeout)

    @property
    def pass2_port_first(self) -> str:
        return first_port(self.pass2_ports) or first_port(self.default_pass2_ports)

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        raise NotImplementedError

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        raise NotImplementedError

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError(f"{self.name} pass2 deepen refuses empty live-host list")
        return materialize_template(self.pass2_argv_template(out_prefix), hosts)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return unique_ipv4s(read_artifact_blob(artifact_dir))

    def stage_files(self, stage: str, target: str, out_prefix: str) -> dict[str, str]:
        del stage, target, out_prefix
        return {}
