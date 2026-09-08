"""BYO fping argv + alive-IP parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix, tile_broadcast, tile_range


class FpingAdapter(LiveAdapter):
    name = "fping"
    binary = "fping"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        start, last = tile_range(target)
        # Classic fping -g start finish works across versions; CIDR form is newer.
        del last
        return [
            "fping",
            "-a",
            "-q",
            "-g",
            start,
            tile_broadcast(target),
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return ["fping", "-a", "-c", "3", "{hosts}"]


def get_adapter() -> FpingAdapter:
    return FpingAdapter()
