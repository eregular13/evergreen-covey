"""OpenVAS / Greenbone / GVM — file_drop ingest stub. Never a live spawn."""

from __future__ import annotations

from pathlib import Path

from covey.errors import AdapterError

_REFUSE = (
    "openvas is file_drop only — Covey will not build live spawn argv "
    "(LICENSE-LOCK: OpenVAS-class tools ingest operator-dropped files only)"
)


class OpenVASFileDrop:
    """Ingest stub. argv methods raise. parse_live_hosts is a no-op hook."""

    name = "openvas"
    file_drop_only = True

    def pass1_argv(self, target: str, out_prefix: str) -> list[str]:
        del target, out_prefix
        raise AdapterError(_REFUSE)

    def pass2_argv_template(self, out_prefix: str) -> list[str]:
        del out_prefix
        raise AdapterError(_REFUSE)

    def pass2_argv(self, hosts: list[str], out_prefix: str) -> list[str]:
        del hosts, out_prefix
        raise AdapterError(_REFUSE)

    def parse_live_hosts(self, artifact_dir: Path) -> list[str]:
        del artifact_dir
        return []


def get_adapter() -> OpenVASFileDrop:
    return OpenVASFileDrop()
