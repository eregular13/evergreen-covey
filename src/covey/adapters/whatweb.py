"""BYO whatweb argv + URL-host parse. Never locates or ships the binary."""

from __future__ import annotations

from covey.adapters.common import LiveAdapter, require_target_prefix, tile_hosts


class WhatwebAdapter(LiveAdapter):
    """HTTP fingerprint. pass1 expands the tile in Python and shells only whatweb."""

    name = "whatweb"
    binary = "whatweb"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "whatweb",
            f"--log-brief={out_prefix}.txt",
            "--no-errors",
            "-a",
            "1",
            *tile_hosts(target),
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "whatweb",
            f"--log-brief={out_prefix}.txt",
            "--no-errors",
            "-a",
            "3",
            "{hosts}",
        ]


def get_adapter() -> WhatwebAdapter:
    return WhatwebAdapter()
