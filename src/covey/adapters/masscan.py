"""BYO masscan argv + JSON parse. Never locates or ships the binary."""

from __future__ import annotations

from pathlib import Path

from covey.adapters.common import (
    LiveAdapter,
    parse_masscan_json,
    read_artifact_blob,
    require_target_prefix,
    unique_ipv4s,
)
class MasscanAdapter(LiveAdapter):
    name = "masscan"
    binary = "masscan"

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        require_target_prefix(target, out_prefix, name=self.name)
        return [
            "masscan",
            "-p80,443",
            "--rate",
            "500",
            "--wait",
            "0",
            "-oJ",
            f"{out_prefix}.json",
            target,
        ]

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        require_target_prefix(".", out_prefix, name=self.name)
        return [
            "masscan",
            "-p22,80,443,3389,8080",
            "--rate",
            "500",
            "--wait",
            "0",
            "-oJ",
            f"{out_prefix}.json",
            "{hosts}",
        ]

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        blob = read_artifact_blob(artifact_dir)
        hosts = parse_masscan_json(blob)
        return hosts or unique_ipv4s(blob)


def get_adapter() -> MasscanAdapter:
    return MasscanAdapter()
