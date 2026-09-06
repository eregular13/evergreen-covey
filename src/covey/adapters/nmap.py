"""BYO Nmap argv builders. Never locates or ships an Nmap binary."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from covey.adapters.base import Adapter, materialize_template
from covey.errors import AdapterError

PASS1_DISCOVER_FLAGS = ("-sn",)
PASS2_DEEPEN_FLAGS = ("-sV",)
DEFAULT_PASS2_PORTS = "22"


class NmapAdapter:
    """First proven live adapter. Operator provides Nmap."""

    name = "nmap"
    file_drop_only = False

    def __init__(
        self,
        *,
        pass2_ports: str = DEFAULT_PASS2_PORTS,
        host_timeout_pass1: str = "8s",
        host_timeout_pass2: str = "8s",
    ) -> None:
        self.pass2_ports = pass2_ports
        self.host_timeout_pass1 = host_timeout_pass1
        self.host_timeout_pass2 = host_timeout_pass2

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        if not target or not out_prefix:
            raise AdapterError("pass1 requires target and out_prefix")
        return [
            "nmap",
            "-sn",
            "-n",
            "--max-retries",
            "1",
            "--host-timeout",
            self.host_timeout_pass1,
            "-oA",
            out_prefix,
            target,
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        if not out_prefix:
            raise AdapterError("pass2 requires out_prefix")
        return [
            "nmap",
            "-sV",
            "-n",
            "--version-intensity",
            "0",
            "-p",
            self.pass2_ports,
            "--max-retries",
            "1",
            "--host-timeout",
            self.host_timeout_pass2,
            "-oA",
            out_prefix,
            "{hosts}",
        ]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("pass2 deepen refuses empty live-host list")
        return materialize_template(self.pass2_argv_template(out_prefix), hosts)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        xml_path = artifact_dir / "scan.xml"
        if xml_path.is_file():
            return parse_nmap_xml_live_hosts(xml_path)
        gnmap_path = artifact_dir / "scan.gnmap"
        if gnmap_path.is_file():
            return parse_gnmap_live_hosts(gnmap_path)
        return []


def parse_nmap_xml_live_hosts(path: Path) -> list[str]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise AdapterError(f"unreadable nmap XML {path}: {exc}") from exc
    hosts: list[str] = []
    seen: set[str] = set()
    for host in tree.getroot().findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        for addr in host.findall("address"):
            if addr.get("addrtype") != "ipv4":
                continue
            ip = addr.get("addr")
            if ip and ip not in seen:
                seen.add(ip)
                hosts.append(ip)
    return hosts


def parse_gnmap_live_hosts(path: Path) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("Host:"):
            continue
        if "Status: Up" not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[1]
        if ip not in seen:
            seen.add(ip)
            hosts.append(ip)
    return hosts


def get_adapter() -> Adapter:
    return NmapAdapter()
