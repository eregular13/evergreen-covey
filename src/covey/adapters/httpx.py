"""BYO httpx argv + URL parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    hosts_file_path,
    is_skipped_ip,
    read_artifact_blob,
    require_target_prefix,
    tile_hosts,
)
from covey.errors import AdapterError

# Silent/file lines: "http://10.9.8.7" / "https://127.0.0.1:18080 [200]"
_URL_HOST = re.compile(
    r"https?://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?",
    re.IGNORECASE,
)


def parse_httpx_live_hosts(text: str) -> list[str]:
    """Hosts httpx printed as live HTTP(S) URLs. Banner IPs are ignored."""
    hosts: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        match = _URL_HOST.search(line)
        if not match:
            continue
        ip = match.group(1)
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


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
        return self._argv(out_prefix)

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv(
            out_prefix,
            extra=["-title", "-status-code", "-tech-detect"],
        )

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("httpx pass2 deepen refuses empty live-host list")
        return self.pass2_argv_template(out_prefix)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_httpx_live_hosts(read_artifact_blob(artifact_dir))

    def stage_files(self, stage: str, target: str, out_prefix: str) -> dict[str, str]:
        if stage == "pass2":
            hosts = [part.strip() for part in target.split(",") if part.strip()]
        else:
            hosts = tile_hosts(target)
        return {hosts_file_path(out_prefix): "".join(f"{host}\n" for host in hosts)}


def get_adapter() -> HttpxAdapter:
    return HttpxAdapter()
