"""BYO hping3 argv + ip= reply parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    first_host,
    is_skipped_ip,
    read_artifact_blob,
    require_target_prefix,
)
from covey.errors import AdapterError

# Reply line: "len=28 ip=127.0.0.1 ttl=127 id=1 icmp_seq=0 rtt=3.8 ms"
# SYN RST also prints ip= (a reply arrived). The HPING banner names the
# destination even on 100% loss — that is not a live host.
_IP_EQ = re.compile(r"\bip=(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_hping3_live_hosts(text: str) -> list[str]:
    """Hosts that produced an hping3 ``ip=`` reply line.

    The HPING banner names the destination even when 0 packets come
    back. Only ``ip=`` lines are live.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        match = _IP_EQ.search(line)
        if not match:
            continue
        ip = match.group(1)
        if ip in seen or is_skipped_ip(ip):
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class Hping3Adapter(LiveAdapter):
    """ICMP to the first usable tile host, then SYN deepen on one host.

    hping3 takes a single destination and needs a raw socket
    (``CAP_NET_RAW`` / root). pass1 pings the first usable host of the
    already-tiled CIDR. pass2 SYN-probes the first live host (remaining
    hosts are appended for plan visibility; the binary uses the first).
    """

    name = "hping3"
    binary = "hping3"
    default_pass2_ports = "80"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return ["hping3", "--icmp", "-c", "3", first_host(target)]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["hping3", "--syn", "-p", self.pass2_port_first, "-c", "2", "{hosts}"]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("hping3 pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "hping3",
            "--syn",
            "-p",
            self.pass2_port_first,
            "-c",
            "2",
            first_host(hosts[0]),
            *hosts[1:],
        ]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_hping3_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> Hping3Adapter:
    return Hping3Adapter()
