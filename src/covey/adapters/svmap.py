"""BYO svmap (sipvicious) argv + SIP-device parse. Never locates or ships the binary."""

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

# Real sipvicious 0.3.3 table (stdout, not -o — that flag does not exist):
#   | 10.9.8.7:5060 | Asterisk PBX  |
#   | 127.0.0.1:18080 | covey-sip-lab |
# Header / separator rows are not devices. UA "unknown" is a non-SIP
# datagram (svmap still prints a table cell). UDP echo of OPTIONS is
# ignored by svmap itself ("found nothing").
_DEVICE = re.compile(
    r"^\|\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*\|\s*(.+?)\s*\|"
)
_REJECT_UA = frozenset({"", "unknown", "user agent", "disabled"})


def parse_svmap_live_hosts(text: str) -> list[str]:
    """Hosts svmap printed as a SIP Device ``ip:port`` table cell.

    A UDP echo is not a live host: svmap ignores its own OPTIONS /
    INVITE / REGISTER packet. A non-SIP datagram can still print
    ``SIP Device`` with User-Agent ``unknown`` — that IP is not live.
    Banner IPs and the table header are ignored.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        match = _DEVICE.match(raw.strip())
        if not match:
            continue
        ip = match.group(1)
        ua = match.group(3).strip().lower()
        if ua in _REJECT_UA:
            continue
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class SvmapAdapter(LiveAdapter):
    """SIP OPTIONS sweeper. pass2 re-scans pass1-live hosts.

    sipvicious 0.3.3 has no ``-o`` and no ``--fp``. Results print as
    an ASCII ``SIP Device | User Agent`` table on stdout. ``-P 0``
    binds an unprivileged source port (default 5060 needs root).
    ``-p`` is the SCOPE port (default 5060).
    """

    name = "svmap"
    binary = "svmap"
    default_pass2_ports = "5060"

    def _flags(self) -> list[str]:
        return ["svmap", "-p", self.pass2_port_first, "-P", "0"]

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [*self._flags(), target]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [*self._flags(), "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("svmap pass2 deepen refuses empty live-host list")
        return super().pass2_argv(hosts, out_prefix)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_svmap_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> SvmapAdapter:
    return SvmapAdapter()
