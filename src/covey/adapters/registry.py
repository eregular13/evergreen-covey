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

# Honest DESKTOP/host BYO needs. Source of truth for `covey ready` and
# docs/CLIENT_DAY.md. desktop_or_host=True means the engagement host must
# supply a capability this farm cannot fake (L2, raw SYN, CAP_NET_RAW,
# privileged UDP, or a specific iface). Not a live-e2e claim.
ADAPTER_HOST_NEEDS: dict[str, dict[str, object]] = {
    "nmap": {
        "desktop_or_host": False,
        "reason": "ICMP/TCP discover; loopback e2e-proven",
        "needs": ("BYO nmap on PATH, COVEY_NMAP, or docker://",),
    },
    "rustscan": {
        "desktop_or_host": False,
        "reason": "TCP connect; loopback e2e-proven",
        "needs": ("BYO rustscan on PATH or COVEY_RUSTSCAN",),
    },
    "fping": {
        "desktop_or_host": False,
        "reason": "ICMP host discovery; loopback e2e-proven",
        "needs": ("BYO fping on PATH or COVEY_FPING",),
    },
    "naabu": {
        "desktop_or_host": False,
        "reason": "TCP connect; loopback e2e-proven",
        "needs": ("BYO naabu on PATH or COVEY_NAABU",),
    },
    "nping": {
        "desktop_or_host": False,
        "reason": "unprivileged --tcp-connect; loopback e2e-proven",
        "needs": ("BYO nping (nmap package) on PATH or COVEY_NPING",),
    },
    "httpx": {
        "desktop_or_host": False,
        "reason": "HTTP probe; target must speak HTTP",
        "needs": ("BYO httpx on PATH or COVEY_HTTPX", "HTTP service on SCOPE ports"),
    },
    "sslscan": {
        "desktop_or_host": False,
        "reason": "TLS probe; target must speak TLS",
        "needs": ("BYO sslscan on PATH or COVEY_SSLSCAN", "TLS service on SCOPE ports"),
    },
    "tlsx": {
        "desktop_or_host": False,
        "reason": "TLS probe; target must speak TLS",
        "needs": ("BYO tlsx on PATH or COVEY_TLSX", "TLS service on SCOPE ports"),
    },
    "whatweb": {
        "desktop_or_host": False,
        "reason": "HTTP fingerprint; target must speak HTTP",
        "needs": ("BYO whatweb on PATH or COVEY_WHATWEB", "HTTP service on SCOPE ports"),
    },
    "hping3": {
        "desktop_or_host": True,
        "reason": "raw --icmp/--syn need CAP_NET_RAW (or root)",
        "needs": ("BYO hping3 on PATH or COVEY_HPING3", "CAP_NET_RAW or root"),
    },
    "onesixtyone": {
        "desktop_or_host": False,
        "reason": "SNMP community sweep; target must speak SNMPv1",
        "needs": (
            "BYO onesixtyone on PATH or COVEY_ONESIXTYONE",
            "SNMP on SCOPE port (default 161)",
        ),
    },
    "nbtscan": {
        "desktop_or_host": True,
        "reason": "NetBIOS/137 is often a privileged UDP port on the host",
        "needs": (
            "BYO nbtscan on PATH or COVEY_NBTSCAN",
            "ability to send/receive NetBIOS UDP/137",
        ),
    },
    "braa": {
        "desktop_or_host": False,
        "reason": "SNMP GET sweep; target must speak SNMPv1",
        "needs": (
            "BYO braa on PATH or COVEY_BRAA",
            "SNMP on SCOPE port (default 161)",
        ),
    },
    "ike-scan": {
        "desktop_or_host": False,
        "reason": "IKE handshake; target must speak ISAKMP",
        "needs": (
            "BYO ike-scan on PATH or COVEY_IKE_SCAN",
            "IKE on SCOPE port (default 500)",
        ),
    },
    "svmap": {
        "desktop_or_host": False,
        "reason": "SIP OPTIONS; target must speak SIP",
        "needs": (
            "BYO svmap/sipvicious on PATH or COVEY_SVMAP",
            "SIP on SCOPE port (default 5060)",
        ),
    },
    "unicornscan": {
        "desktop_or_host": True,
        "reason": "needs the correct iface; same-UID /tmp collision; modules.conf 0640",
        "needs": (
            "BYO unicornscan on PATH or COVEY_UNICORNSCAN",
            "non-loopback iface, or -i lo plus a 127/8 source outside the tile",
            "max_workers: 1 on the engagement host",
        ),
    },
    "masscan": {
        "desktop_or_host": True,
        "reason": "raw SYN/pcap; loopback finds 0; argv+unit only",
        "needs": (
            "BYO masscan on PATH or COVEY_MASSCAN",
            "non-loopback tile",
            "CAP_NET_RAW or root + libpcap",
        ),
    },
    "zmap": {
        "desktop_or_host": True,
        "reason": "raw SYN/pcap; loopback finds 0; argv+unit only",
        "needs": (
            "BYO zmap on PATH or COVEY_ZMAP",
            "non-loopback tile",
            "CAP_NET_RAW or root + pcap",
        ),
    },
    "arp-scan": {
        "desktop_or_host": True,
        "reason": "Ethernet L2; loopback has no MAC; argv+unit only",
        "needs": (
            "BYO arp-scan on PATH or COVEY_ARP_SCAN",
            "Ethernet interface (not lo)",
        ),
    },
    "netdiscover": {
        "desktop_or_host": True,
        "reason": "Ethernet L2; loopback is not Ethernet; argv+unit only",
        "needs": (
            "BYO netdiscover on PATH or COVEY_NETDISCOVER",
            "Ethernet interface (not lo)",
        ),
    },
}

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


def host_need(name: str) -> dict[str, object]:
    """Return DESKTOP/host BYO needs for a live adapter id."""
    key = normalize_adapter_name(name)
    key = _ALIASES.get(key, key)
    need = ADAPTER_HOST_NEEDS.get(key)
    if need is None:
        raise AdapterError(f"unknown adapter {name!r}")
    return dict(need)


def desktop_or_host_adapters() -> tuple[str, ...]:
    """Adapters that still need a DESKTOP/host capability beyond PATH."""
    return tuple(
        name
        for name in LIVE_ADAPTER_IDS
        if ADAPTER_HOST_NEEDS[name]["desktop_or_host"]
    )
