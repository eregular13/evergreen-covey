"""BYO httpx argv + URL parse. Never locates or ships the binary."""

from __future__ import annotations

import json
import re
from ipaddress import IPv4Address
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    hosts_file_path,
    is_skipped_ip,
    open_port_row,
    read_artifact_blob,
    require_target_prefix,
    tile_hosts,
    unique_services,
)
from covey.errors import AdapterError

# Silent/file lines: "http://10.9.8.7" / "https://honeypot:8081 [200]"
_URL_HOST = re.compile(
    r"(https?)://([A-Za-z0-9._-]+)(?::(\d+))?",
    re.IGNORECASE,
)

# Browser-like GET so DataTrap (and similar) classify the request as a document.
_HTTPX_JSON_FLAGS = [
    "-json",
    "-include-response-header",
    "-title",
    "-H",
    "Accept: text/html,application/xhtml+xml",
]


def _skip_httpx_host(host: str) -> bool:
    """Drop 0.0.0.0-class IPs. Hostnames from URL targets are live."""
    try:
        IPv4Address(host)
    except ValueError:
        return not host
    return is_skipped_ip(host)


def _probe_line(host: str, ports: str) -> str:
    """Bare hostname + one SCOPE port becomes an http(s) URL so httpx -l probes."""
    text = (host or "").strip()
    if not text:
        return ""
    if text.lower().startswith("http://") or text.lower().startswith("https://"):
        return text
    port_list = [part.strip() for part in str(ports or "").split(",") if part.strip()]
    try:
        IPv4Address(text.split("/")[0])
        return text
    except ValueError:
        pass
    if len(port_list) != 1:
        return text
    port = port_list[0]
    scheme = "https" if port in {"443", "8443"} else "http"
    return f"{scheme}://{text}:{port}"


def parse_httpx_live_hosts(text: str) -> list[str]:
    """Hosts httpx printed as live HTTP(S) URLs. Banner IPs are ignored."""
    hosts: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        stripped = line.strip()
        url = ""
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                url = str(obj.get("url") or "")
                host = str(obj.get("host") or "")
                if host and host not in seen and not _skip_httpx_host(host):
                    seen.add(host)
                    hosts.append(host)
                    continue
        match = _URL_HOST.search(url or stripped)
        if not match:
            continue
        ip = match.group(2)
        if ip in seen or _skip_httpx_host(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


def parse_httpx_services(text: str) -> list[dict[str, str]]:
    """HTTP(S) URLs httpx printed as live. Scheme default ports when omitted."""
    services: list[dict[str, str]] = []
    for line in (text or "").splitlines():
        match = _URL_HOST.search(line)
        if not match:
            continue
        scheme = match.group(1).lower()
        ip = match.group(2)
        if _skip_httpx_host(ip):
            continue
        port = match.group(3) or ("443" if scheme == "https" else "80")
        services.append(open_port_row(ip, port, service=scheme))
    return unique_services(services)


class HttpxAdapter(LiveAdapter):
    """HTTP banner deepener. pass1 probes every usable host of the tile via -l."""

    name = "httpx"
    binary = "httpx"
    default_pass2_ports = "80,443"

    def _argv(self, out_prefix: str, extra: list[str] | None = None) -> list[str]:
        argv = [
            "httpx",
            "-silent",
            *(extra or []),
            "-l",
            hosts_file_path(out_prefix),
            "-p",
            self.pass2_ports,
            "-o",
            f"{out_prefix}.txt",
        ]
        return argv

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return self._argv(out_prefix, extra=list(_HTTPX_JSON_FLAGS))

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv(
            out_prefix,
            extra=list(_HTTPX_JSON_FLAGS),
        )

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("httpx pass2 deepen refuses empty live-host list")
        return self.pass2_argv_template(out_prefix)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_httpx_live_hosts(read_artifact_blob(artifact_dir))

    def parse_services(self, artifact_dir: Path) -> list[dict[str, str]]:
        return parse_httpx_services(read_artifact_blob(artifact_dir))

    def stage_files(self, stage: str, target: str, out_prefix: str) -> dict[str, str]:
        if stage == "pass2":
            hosts = [part.strip() for part in target.split(",") if part.strip()]
        else:
            hosts = tile_hosts(target)
        lines = [_probe_line(host, self.pass2_ports) for host in hosts]
        lines = [line for line in lines if line]
        return {hosts_file_path(out_prefix): "".join(f"{line}\n" for line in lines)}


def get_adapter() -> HttpxAdapter:
    return HttpxAdapter()
