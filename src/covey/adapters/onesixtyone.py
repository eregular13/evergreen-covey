"""BYO onesixtyone argv + community parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    comm_file_path,
    hosts_file_path,
    is_skipped_ip,
    read_artifact_blob,
    require_target_prefix,
    tile_hosts,
)
from covey.errors import AdapterError

# Success line: "10.9.8.7 [public] Linux"
# onesixtyone prints the UDP source IP on any datagram. Decode-error
# lines ("Unable to decode…") and the hosts sidecar are not live.
_COMMUNITY_LINE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\[([^\]]+)\]\s+(\S.*)$"
)
_REJECT_VALUE_PREFIXES = (
    "Unable to decode",
    "Host responded with error",
)


def parse_onesixtyone_live_hosts(text: str) -> list[str]:
    """Hosts onesixtyone printed as ``ip [community] sysDescr``.

    A UDP echo is not a live host. The IP is printed before decode;
    only a community + sysDescr value after a GetResponse counts.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        match = _COMMUNITY_LINE.match(raw.strip())
        if not match:
            continue
        ip = match.group(1)
        value = match.group(3).strip()
        if any(value.startswith(prefix) for prefix in _REJECT_VALUE_PREFIXES):
            continue
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class OnesixtyoneAdapter(LiveAdapter):
    """SNMP community sweeper. Hosts/communities land as runner sidecars."""

    name = "onesixtyone"
    binary = "onesixtyone"
    default_pass2_ports = "161"

    def _argv(self, out_prefix: str) -> list[str]:
        return [
            "onesixtyone",
            "-c",
            comm_file_path(out_prefix),
            "-i",
            hosts_file_path(out_prefix),
            "-o",
            f"{out_prefix}.txt",
            "-p",
            self.pass2_port_first,
        ]

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return self._argv(out_prefix)

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv(out_prefix)

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("onesixtyone pass2 deepen refuses empty live-host list")
        return self.pass2_argv_template(out_prefix)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_onesixtyone_live_hosts(read_artifact_blob(artifact_dir))

    def stage_files(self, stage: str, target: str, out_prefix: str) -> dict[str, str]:
        if stage == "pass2":
            hosts = [part.strip() for part in target.split(",") if part.strip()]
            communities = "public\nprivate\ncommunity\n"
        else:
            hosts = tile_hosts(target)
            communities = "public\nprivate\n"
        return {
            hosts_file_path(out_prefix): "".join(f"{host}\n" for host in hosts),
            comm_file_path(out_prefix): communities,
        }


def get_adapter() -> OnesixtyoneAdapter:
    return OnesixtyoneAdapter()
