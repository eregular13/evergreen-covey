"""adapter_for() registry: 20 live BYO tools, file_drop, LICENSE-LOCK refuse."""

from __future__ import annotations

from covey.adapters.arp_scan import ArpScanAdapter
from covey.adapters.base import Adapter
from covey.adapters.braa import BraaAdapter
from covey.adapters.fping import FpingAdapter
from covey.adapters.hping3 import Hping3Adapter
from covey.adapters.httpx import HttpxAdapter
from covey.adapters.ike_scan import IkeScanAdapter
from covey.adapters.masscan import MasscanAdapter
from covey.adapters.naabu import NaabuAdapter
from covey.adapters.nbtscan import NbtscanAdapter
from covey.adapters.netdiscover import NetdiscoverAdapter
from covey.adapters.nmap import NmapAdapter
from covey.adapters.nping import NpingAdapter
from covey.adapters.onesixtyone import OnesixtyoneAdapter
from covey.adapters.openvas import OpenVASFileDrop
from covey.adapters.ping import PingAdapter
from covey.adapters.rustscan import RustscanAdapter
from covey.adapters.sslscan import SslscanAdapter
from covey.adapters.svmap import SvmapAdapter
from covey.adapters.tlsx import TlsxAdapter
from covey.adapters.unicornscan import UnicornscanAdapter
from covey.adapters.whatweb import WhatwebAdapter
from covey.adapters.zmap import ZmapAdapter
from covey.errors import AdapterError

# End-to-end proven on a real BYO binary + signed loopback lab. Others are
# argv+unit only — do not claim them live. Docs (PROVE.md / README) and
# `python -m covey prove --adapter` must follow this tuple.
E2E_PROVEN_ADAPTERS: tuple[str, ...] = (
    "nmap",
    "rustscan",
    "fping",
    "naabu",
    "nping",
    "httpx",
    "sslscan",
    "tlsx",
    "whatweb",
    "hping3",
    "onesixtyone",
    "nbtscan",
    "braa",
    "ike-scan",
    "svmap",
    "unicornscan",
)

# Authoritative live adapter ids (SCOPE adapter: field). Order is stable.
LIVE_ADAPTER_IDS: tuple[str, ...] = (
    "nmap",
    "masscan",
    "rustscan",
    "naabu",
    "fping",
    "arp-scan",
    "netdiscover",
    "zmap",
    "unicornscan",
    "nping",
    "hping3",
    "ike-scan",
    "nbtscan",
    "onesixtyone",
    "braa",
    "svmap",
    "sslscan",
    "whatweb",
    "httpx",
    "tlsx",
)

# Derived: the 4 that must fail closed on prove. Do not add a seventeenth e2e
# by editing docs — append to E2E_PROVEN_ADAPTERS only after a real prove.
UNPROVEN_ADAPTERS: tuple[str, ...] = tuple(
    name for name in LIVE_ADAPTER_IDS if name not in E2E_PROVEN_ADAPTERS
)

_FACTORIES: dict[str, type] = {
    "nmap": NmapAdapter,
    "masscan": MasscanAdapter,
    "rustscan": RustscanAdapter,
    "naabu": NaabuAdapter,
    "fping": FpingAdapter,
    "arp-scan": ArpScanAdapter,
    "netdiscover": NetdiscoverAdapter,
    "zmap": ZmapAdapter,
    "unicornscan": UnicornscanAdapter,
    "nping": NpingAdapter,
    "hping3": Hping3Adapter,
    "ike-scan": IkeScanAdapter,
    "nbtscan": NbtscanAdapter,
    "onesixtyone": OnesixtyoneAdapter,
    "braa": BraaAdapter,
    "svmap": SvmapAdapter,
    "sslscan": SslscanAdapter,
    "whatweb": WhatwebAdapter,
    "httpx": HttpxAdapter,
    "tlsx": TlsxAdapter,
}

# Aliases normalize to a live id or a refuse class.
_ALIASES: dict[str, str] = {
    "arp_scan": "arp-scan",
    "arpscan": "arp-scan",
    "ike_scan": "ike-scan",
    "ikescan": "ike-scan",
    "sipvicious": "svmap",
    "sipvicious_svmap": "svmap",
    "iputils-ping": "ping",
}

FILE_DROP_IDS = frozenset({"openvas", "greenbone", "gvm"})

FORBIDDEN_LIVE = frozenset(
    {
        "nuclei",
        "wazuh",
        "osquery",
        "bloodhound",
        "pingcastle",
        "riskready",
        "npcap",
        "zenmap",
    }
)

# PATH lookup aliases when resolving the operator binary.
BINARY_ALIASES: dict[str, tuple[str, ...]] = {
    "arp-scan": ("arp-scan",),
    "ike-scan": ("ike-scan",),
    "svmap": ("svmap", "sipvicious_svmap"),
    "ping": ("ping",),
}


def normalize_adapter_name(name: str) -> str:
    return (name or "nmap").strip().lower().replace(" ", "-")


def tool_env_var(name: str) -> str:
    """COVEY_NMAP, COVEY_ARP_SCAN, …"""
    return "COVEY_" + normalize_adapter_name(name).upper().replace("-", "_")


def adapter_for(name: str, *, deepen: object | None = None) -> Adapter:
    key = normalize_adapter_name(name)
    key = _ALIASES.get(key, key)
    if key in FORBIDDEN_LIVE:
        raise AdapterError(
            f"{name} is forbidden by LICENSE-LOCK — Covey will not wrap it"
        )
    if key in FILE_DROP_IDS:
        raise AdapterError(
            f"{name} is file_drop only — Covey will not build a live spawn plan"
        )
    factory = _FACTORIES.get(key)
    if factory is None:
        raise AdapterError(f"unknown adapter {name!r}")
    adapter = factory()
    if deepen is not None and hasattr(adapter, "apply_deepen"):
        adapter.apply_deepen(deepen)
    return adapter


def file_drop_adapter(name: str = "openvas") -> OpenVASFileDrop:
    key = normalize_adapter_name(name)
    if key not in FILE_DROP_IDS:
        raise AdapterError(f"{name} is not an OpenVAS-class file_drop adapter")
    return OpenVASFileDrop()


def list_live_adapters() -> tuple[str, ...]:
    return LIVE_ADAPTER_IDS
