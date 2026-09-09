"""BYO nbtscan argv + NetBIOS table parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    is_skipped_ip,
    read_artifact_blob,
    require_target_prefix,
)

# Script-friendly (-s :): "10.9.8.7:SERVER:00:UNIQUE" / "127.0.0.1:COVEYLAB:00U"
# Default columns: "10.9.8.7        SERVER"
# nbtscan prints the UDP source IP on any datagram. A UDP echo yields
# "ip:<unknown>" — that is not a live host. The MAC sidecar line and
# the scan banner are not live hosts either.
_SEP_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})[:\t ]+(\S.*)$")
_REJECT_NAMES = frozenset(
    {
        "<unknown>",
        "mac",
        "unknown",
    }
)


def parse_nbtscan_live_hosts(text: str) -> list[str]:
    """Hosts nbtscan printed with a real NetBIOS name.

    A UDP echo is not a live host. The IP is printed before decode;
    only a name-table entry (not ``<unknown>`` / MAC) counts.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("doing nbt"):
            continue
        match = _SEP_LINE.match(line)
        if not match:
            continue
        ip = match.group(1)
        rest = match.group(2).strip()
        token = rest.split(":")[0].split()[0].strip()
        if not token or token.lower() in _REJECT_NAMES:
            continue
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class NbtscanAdapter(LiveAdapter):
    name = "nbtscan"
    binary = "nbtscan"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return ["nbtscan", "-s", ":", "-t", "500", target]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["nbtscan", "-v", "-s", ":", "{hosts}"]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_nbtscan_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> NbtscanAdapter:
    return NbtscanAdapter()
