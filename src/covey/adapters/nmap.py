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

    def apply_deepen(self, deepen: object) -> None:
        """Honor SCOPE pass2/deepen ports (Palisade P0)."""
        ports = getattr(deepen, "ports", None)
        if ports:
            self.pass2_ports = str(ports)
        timeout = getattr(deepen, "host_timeout", None)
        if timeout:
            self.host_timeout_pass2 = str(timeout)

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


def parse_nmap_xml_meta(path: Path) -> dict[str, str]:
    """Scanner/version attributes from ``<nmaprun>``. Empty on parse failure."""
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return {}
    root = tree.getroot()
    meta = {
        "scanner": (root.get("scanner") or "").strip(),
        "version": (root.get("version") or "").strip(),
        "args": (root.get("args") or "").strip(),
    }
    return {k: v for k, v in meta.items() if v}


def parse_nmap_xml_services(path: Path) -> list[dict[str, str]]:
    """Observed open ports/services from nmap XML. Closed/filtered are ignored."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise AdapterError(f"unreadable nmap XML {path}: {exc}") from exc
    services: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for host in tree.getroot().findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in {None, "up"}:
            continue
        ips: list[str] = []
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4" and addr.get("addr"):
                ips.append(str(addr.get("addr")))
        if not ips:
            continue
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or (state.get("state") or "").lower() != "open":
                continue
            protocol = (port.get("protocol") or "tcp").lower()
            portid = (port.get("portid") or "").strip()
            if not portid:
                continue
            service_el = port.find("service")
            name = (service_el.get("name") if service_el is not None else "") or ""
            product = (service_el.get("product") if service_el is not None else "") or ""
            for ip in ips:
                key = (ip, protocol, portid)
                if key in seen:
                    continue
                seen.add(key)
                row = {
                    "address": ip,
                    "protocol": protocol,
                    "port": portid,
                    "state": "open",
                    "service": name,
                }
                if product:
                    row["product"] = product
                services.append(row)
    return services


def parse_gnmap_services(path: Path) -> list[dict[str, str]]:
    """Observed open ports from greppable nmap. Closed/filtered are ignored."""
    services: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("Host:"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[1]
        marker = "Ports:"
        if marker not in line:
            continue
        ports_blob = line.split(marker, 1)[1]
        if "Ignored" in ports_blob:
            ports_blob = ports_blob.split("Ignored", 1)[0]
        for raw in ports_blob.split(","):
            token = raw.strip()
            if not token:
                continue
            fields = token.split("/")
            if len(fields) < 3:
                continue
            portid, state, protocol = fields[0], fields[1].lower(), fields[2].lower()
            if state != "open" or not portid:
                continue
            service = fields[4] if len(fields) > 4 else ""
            key = (ip, protocol, portid)
            if key in seen:
                continue
            seen.add(key)
            services.append(
                {
                    "address": ip,
                    "protocol": protocol,
                    "port": portid,
                    "state": "open",
                    "service": service,
                }
            )
    return services


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
