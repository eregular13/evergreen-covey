"""BYO nping argv + handshake/echo-reply parse. Never locates or ships the binary."""

from __future__ import annotations

import re
from pathlib import Path

from covey.adapters.common import LiveAdapter, read_artifact_blob, require_target_prefix, tile_hosts
from covey.errors import AdapterError

# Unprivileged --tcp-connect success: "Handshake with 127.0.0.1:18080 completed"
_HANDSHAKE = re.compile(
    r"Handshake with (\d{1,3}(?:\.\d{1,3}){3}):\d+ completed",
)
# ICMP Echo reply (argv+unit fixture / privileged --icmp): source is first IP.
_ECHO_REPLY = re.compile(
    r"RCVD\b.*ICMP\s+\[(\d{1,3}(?:\.\d{1,3}){3})\s+>.*Echo reply",
)


def parse_nping_live_hosts(text: str) -> list[str]:
    """Hosts nping completed a TCP handshake with (or ICMP echo-replied).

    ``RCVD`` alone is not enough: --tcp-connect also prints RCVD on
    Connection refused / RST. Those hosts are not live.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        match = _HANDSHAKE.search(line) or _ECHO_REPLY.search(line)
        if not match:
            continue
        ip = match.group(1)
        if ip in seen:
            continue
        seen.add(ip)
        hosts.append(ip)
    return hosts


class NpingAdapter(LiveAdapter):
    """TCP-connect probe on tile hosts; deepen is nping-only (--tcp-connect).

    Raw ``--icmp`` / ``--tcp`` need root. The live prove is unprivileged
    ``--tcp-connect`` against SCOPE ports (lab listener class).
    """

    name = "nping"
    binary = "nping"
    default_pass2_ports = "80"

    def _argv(self, hosts: list[str]) -> list[str]:
        return [
            "nping",
            "--tcp-connect",
            "-p",
            self.pass2_port_first,
            "-c",
            "1",
            "--delay",
            "200ms",
            *hosts,
        ]

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return self._argv(tile_hosts(target))

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "nping",
            "--tcp-connect",
            "-p",
            self.pass2_port_first,
            "-c",
            "1",
            "--delay",
            "200ms",
            "{hosts}",
        ]

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        if not hosts:
            raise AdapterError("nping pass2 deepen refuses empty live-host list")
        require_target_prefix(".", out_prefix, name=self.name)
        return self._argv(hosts)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        return parse_nping_live_hosts(read_artifact_blob(artifact_dir))


def get_adapter() -> NpingAdapter:
    return NpingAdapter()
