"""BYO arp-scan argv + IP/MAC parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix


class ArpScanAdapter(LiveAdapter):
    name = "arp-scan"
    binary = "arp-scan"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "arp-scan",
            "--retry=2",
            "--timeout=200",
            "--ignoredups",
            target,
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "arp-scan",
            "--retry=4",
            "--timeout=500",
            "--ignoredups",
            "{hosts}",
        ]


def get_adapter() -> ArpScanAdapter:
    return ArpScanAdapter()
