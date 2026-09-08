"""BYO ike-scan argv + handshake parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix


class IkeScanAdapter(LiveAdapter):
    name = "ike-scan"
    binary = "ike-scan"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return ["ike-scan", "--timeout=2", "--retry=1", target]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["ike-scan", "--aggressive", "--id=vpn", "--timeout=2", "{hosts}"]


def get_adapter() -> IkeScanAdapter:
    return IkeScanAdapter()
