"""BYO braa argv + OID-line parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    is_skipped_ip,
    read_artifact_blob,
    require_target_prefix,
    tile_hosts,
)
from covey.errors import AdapterError

SYS_DESCR = ".1.3.6.1.2.1.1.1.0"
SYS_NAME = ".1.3.6.1.2.1.1.5.0"

# Fixture: "10.9.8.7:.1.3.6.1.2.1.1.1.0:Linux"
# Real braa 0.82: "127.0.0.1:20ms:.0:covey-snmp-lab"
# Dispatch errors print "ip: Message cannot be dispatched!" — not live.
# Timeouts print nothing.
_OID_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\S+):(\S.*)$")
_REJECT_VALUE_NEEDLES = (
    "cannot be dispatched",
    "error",
    "timeout",
)


def parse_braa_live_hosts(text: str) -> list[str]:
    """Hosts braa printed as ``ip:oid:value`` (or ``ip:rtt:id:value``).

    A missing GetResponse is not a live host. braa prints nothing on
    timeout and only an error sentence when the PDU cannot be dispatched.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        match = _OID_LINE.match(raw.strip())
        if not match:
            continue
        ip = match.group(1)
        value = match.group(3).strip()
        lowered = value.lower()
        if any(needle in lowered for needle in _REJECT_VALUE_NEEDLES):
            continue
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class BraaAdapter(LiveAdapter):
    """SNMP GET sweeper. pass1 is one query per usable tile host."""

    name = "braa"
    binary = "braa"
    default_pass2_ports = "161"

    def _query(self, host: str, oid: str) -> str:
        return f"public@{host}:{self.pass2_port_first}:{oid}"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        hosts = tile_hosts(target)
        if not hosts:
            raise AdapterError("braa pass1 refuses an empty tile")
        # Per-host queries, not first-last ranges. braa 0.82 rejects some
        # loopback ranges (inet_aton end < start) and network/broadcast
        # addresses are not SNMP speakers. Do not append /id — braa 0.82
        # prefixes that label and the live signal is still ip:rtt:oid:value.
        return ["braa", *[self._query(host, SYS_DESCR) for host in hosts]]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["braa", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("braa pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        queries: list[str] = []
        for host in hosts:
            queries.append(self._query(host, SYS_DESCR))
            queries.append(self._query(host, SYS_NAME))
        return ["braa", *queries]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_braa_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> BraaAdapter:
    return BraaAdapter()
