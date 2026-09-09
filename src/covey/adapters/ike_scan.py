"""BYO ike-scan argv + handshake parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    is_skipped_ip,
    read_artifact_blob,
    require_target_prefix,
)
from covey.errors import AdapterError

# Success: "10.9.8.7\tMain Mode Handshake returned HDR=(CKY-R=434f5645594c4142)"
# Fixture: "10.9.8.7\tMain Mode Handshake returned (HDR: (CKY-I=...))"
# Self-echo / UDP echo of the initiator packet: CKY-R=0000000000000000
# Notify / malformed lines name the IP but are not live hosts.
_HANDSHAKE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\S.*Handshake returned"
)
_SELF_ECHO_COOKIE = re.compile(r"CKY-R=0{16}")


def parse_ike_scan_live_hosts(text: str) -> list[str]:
    """Hosts ike-scan printed as a handshake with a nonzero responder cookie.

    A UDP echo is not a live host. ike-scan prints ``Handshake returned``
    on its own initiator packet (CKY-R all zeros) when sport==dport on
    loopback or when the peer reflects the SA unchanged. Notify and
    malformed lines name the IP but are not handshakes.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        match = _HANDSHAKE.match(line)
        if not match:
            continue
        if _SELF_ECHO_COOKIE.search(line):
            continue
        ip = match.group(1)
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class IkeScanAdapter(LiveAdapter):
    """IKE Main Mode sweeper. pass2 is Aggressive Mode on live hosts.

    ``--sport=0`` stays unprivileged and avoids the loopback self-echo
    that happens when sport==dport. ``--dport`` is the SCOPE port
    (default 500).
    """

    name = "ike-scan"
    binary = "ike-scan"
    default_pass2_ports = "500"

    def _flags(self) -> list[str]:
        return [
            "ike-scan",
            "--sport=0",
            f"--dport={self.pass2_port_first}",
            "--timeout=500",
            "--retry=1",
            "--nodns",
        ]

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [*self._flags(), target]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [*self._flags(), "--aggressive", "--id=vpn", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("ike-scan pass2 deepen refuses empty live-host list")
        return super().pass2_argv(hosts, out_prefix)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_ike_scan_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> IkeScanAdapter:
    return IkeScanAdapter()
