"""Load, sign, and validate SCOPE documents. Fail-closed."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from covey.errors import ScopeError
from covey.shard import (
    DEFAULT_SMALL_TILE_PREFIX,
    DEFAULT_TILE_PREFIX,
    is_always_refused_token,
    is_wide_network,
    parse_v4_network,
)

DEMO_HMAC_KEY = b"evergreen-covey-demo"
HMAC_ENV = "COVEY_SCOPE_HMAC_KEY"

_MAX_WORKERS_DEFAULT = 2
_MAX_WORKERS_CEILING = 4
_MAX_SHARDS_DEFAULT = 64

# nmap-ish port lists: 22 / 22,80,443 / 8000-8080 / T:22,U:53
_PORT_SPEC_RE = re.compile(r"^[0-9TU:,-]+$", re.IGNORECASE)
_HOST_TIMEOUT_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?[smh]?$", re.IGNORECASE)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso8601(raw: str, *, field_name: str) -> datetime:
    if not raw or not isinstance(raw, str):
        raise ScopeError(f"SCOPE window.{field_name} missing")
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ScopeError(f"SCOPE window.{field_name} is not ISO-8601: {raw}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def canonical_payload(data: dict[str, Any]) -> bytes:
    body = {k: v for k, v in data.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )


def hmac_key_for(data: dict[str, Any]) -> bytes:
    env_key = os.environ.get(HMAC_ENV, "").strip()
    if env_key:
        return env_key.encode("utf-8")
    if data.get("demo") is True:
        return DEMO_HMAC_KEY
    raise ScopeError(
        f"unsigned key material: set {HMAC_ENV} or mark SCOPE demo: true"
    )


def compute_signature(data: dict[str, Any], *, key: bytes | None = None) -> str:
    material = key if key is not None else hmac_key_for(data)
    digest = hmac.new(material, canonical_payload(data), hashlib.sha256).hexdigest()
    return digest


def verify_signature(data: dict[str, Any]) -> None:
    signature = data.get("signature")
    if signature is None or (isinstance(signature, str) and not signature.strip()):
        raise ScopeError("unsigned SCOPE refused")
    if not isinstance(signature, str):
        raise ScopeError("SCOPE signature must be a hex string")
    expected = compute_signature(data)
    if not hmac.compare_digest(signature.strip().lower(), expected.lower()):
        raise ScopeError("SCOPE signature invalid")


@dataclass
class Target:
    cidr: str
    allow_wide: bool
    listed: str

    def network(self):
        return parse_v4_network(self.cidr)


@dataclass
class Deepen:
    """SCOPE-owned pass2 / deepen parameters (Palisade P0: ports are not silent)."""

    ports: str | None = None
    host_timeout: str | None = None

    def to_dict(self) -> dict[str, str]:
        data: dict[str, str] = {}
        if self.ports:
            data["ports"] = self.ports
        if self.host_timeout:
            data["host_timeout"] = self.host_timeout
        return data


@dataclass
class Scope:
    version: int
    demo: bool
    signer: str
    purpose: str
    window_start: datetime
    window_end: datetime
    targets: list[Target]
    allow_wide: bool
    max_workers: int
    max_shards: int
    adapter: str
    default_tile: int
    small_tile: int
    signature: str
    raw: dict[str, Any] = field(repr=False)
    deepen: Deepen = field(default_factory=Deepen)

    @property
    def listed_cidrs(self) -> set[str]:
        return {t.listed for t in self.targets}


def _as_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _as_int(value: Any, *, default: int, name: str, lo: int, hi: int) -> int:
    if value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ScopeError(f"SCOPE {name} must be an integer") from exc
    if number < lo or number > hi:
        raise ScopeError(f"SCOPE {name} must be in {lo}..{hi}")
    return number


def _load_mapping(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        return dict(source)
    if isinstance(source, Path):
        text = source.read_text(encoding="utf-8")
    else:
        text = source
    if text is None or not str(text).strip():
        raise ScopeError("empty SCOPE refused")
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ScopeError(f"SCOPE YAML is not parseable: {exc}") from exc
    if loaded is None:
        raise ScopeError("empty SCOPE refused")
    if not isinstance(loaded, dict):
        raise ScopeError("SCOPE must be a mapping")
    return loaded


def normalize_port_spec(raw: Any, *, field_name: str) -> str:
    """Fail-closed port list. Empty or injectable strings are refused."""
    if raw is None:
        raise ScopeError(f"SCOPE {field_name} is empty")
    if isinstance(raw, bool):
        raise ScopeError(f"SCOPE {field_name} must be a port list")
    if isinstance(raw, int):
        if raw < 1 or raw > 65535:
            raise ScopeError(f"SCOPE {field_name} port out of range: {raw}")
        return str(raw)
    if isinstance(raw, list):
        if not raw:
            raise ScopeError(f"SCOPE {field_name} is empty")
        parts = [normalize_port_spec(item, field_name=field_name) for item in raw]
        return ",".join(parts)
    if not isinstance(raw, str):
        raise ScopeError(f"SCOPE {field_name} must be a port list")
    text = raw.strip().replace(" ", "")
    if not text:
        raise ScopeError(f"SCOPE {field_name} is empty")
    if not _PORT_SPEC_RE.fullmatch(text):
        raise ScopeError(f"SCOPE {field_name} has invalid characters")
    tokens = [part for part in text.split(",") if part]
    if not tokens:
        raise ScopeError(f"SCOPE {field_name} is empty")
    for token in tokens:
        body = token.split(":", 1)[-1] if token[:1] in "TUtu" and ":" in token else token
        for edge in body.split("-"):
            if not edge.isdigit():
                raise ScopeError(f"SCOPE {field_name} is not a port list: {token}")
            number = int(edge)
            if number < 1 or number > 65535:
                raise ScopeError(f"SCOPE {field_name} port out of range: {number}")
    return text


def normalize_host_timeout(raw: Any, *, field_name: str) -> str:
    if raw is None:
        raise ScopeError(f"SCOPE {field_name} is empty")
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        if raw <= 0:
            raise ScopeError(f"SCOPE {field_name} must be positive")
        return f"{int(raw)}s" if float(raw) == int(raw) else f"{raw}s"
    if not isinstance(raw, str) or not raw.strip():
        raise ScopeError(f"SCOPE {field_name} is empty")
    text = raw.strip()
    if not _HOST_TIMEOUT_RE.fullmatch(text):
        raise ScopeError(f"SCOPE {field_name} is not a duration (e.g. 8s)")
    return text


def parse_deepen(data: dict[str, Any]) -> Deepen:
    """Read ``pass2:`` / ``deepen:`` / top-level ``ports``. ``pass2`` wins on clash."""
    merged: dict[str, Any] = {}
    for key in ("deepen", "pass2"):
        block = data.get(key)
        if block is None:
            continue
        if isinstance(block, (str, int, list)):
            merged["ports"] = block
            continue
        if not isinstance(block, dict):
            raise ScopeError(f"SCOPE {key} must be a mapping or port list")
        for name, value in block.items():
            if value is not None:
                merged[name] = value
    if "ports" not in merged and data.get("ports") is not None:
        merged["ports"] = data.get("ports")

    ports = None
    if "ports" in merged:
        ports = normalize_port_spec(merged["ports"], field_name="pass2.ports")
    host_timeout = None
    if "host_timeout" in merged:
        host_timeout = normalize_host_timeout(
            merged["host_timeout"], field_name="pass2.host_timeout"
        )
    return Deepen(ports=ports, host_timeout=host_timeout)


def parse_targets(raw: Any, *, global_allow_wide: bool) -> list[Target]:
    if raw is None:
        raise ScopeError("SCOPE targets missing")
    if not isinstance(raw, list) or not raw:
        raise ScopeError("SCOPE targets must be a non-empty list")

    targets: list[Target] = []
    for item in raw:
        if isinstance(item, str):
            cidr = item
            allow_wide = global_allow_wide
        elif isinstance(item, dict):
            cidr = item.get("cidr") or item.get("target") or ""
            allow_wide = _as_bool(item.get("allow_wide"), default=global_allow_wide)
        else:
            raise ScopeError("each SCOPE target must be a CIDR string or mapping")

        if not isinstance(cidr, str) or not cidr.strip():
            raise ScopeError("SCOPE target cidr missing")
        token = cidr.strip()
        if is_always_refused_token(token):
            raise ScopeError(f"refused wide spray target: {token}")

        net = parse_v4_network(token)
        listed = str(net)
        if is_wide_network(net):
            if not allow_wide:
                raise ScopeError(
                    f"{listed} is /{net.prefixlen} (/8–/16); set allow_wide: true "
                    "and list this parent CIDR explicitly"
                )
            # Parent CIDR must appear verbatim as a listed target (this one).
            if listed != str(net):
                raise ScopeError(f"wide parent CIDR must be listed verbatim: {listed}")
        targets.append(Target(cidr=token, allow_wide=allow_wide, listed=listed))
    return targets


def from_mapping(data: dict[str, Any], *, verify: bool = True) -> Scope:
    if not data:
        raise ScopeError("empty SCOPE refused")

    consent = data.get("consent") or {}
    if not isinstance(consent, dict):
        raise ScopeError("SCOPE consent must be a mapping")
    if not _as_bool(consent.get("signed")):
        raise ScopeError("unsigned SCOPE refused (consent.signed is not true)")

    signer = str(consent.get("signer") or "").strip()
    purpose = str(consent.get("purpose") or "").strip()
    if not signer or not purpose:
        raise ScopeError("SCOPE consent.signer and consent.purpose are required")

    window = data.get("window") or {}
    if not isinstance(window, dict):
        raise ScopeError("SCOPE window must be a mapping")
    start = parse_iso8601(str(window.get("start") or ""), field_name="start")
    end = parse_iso8601(str(window.get("end") or ""), field_name="end")
    if end <= start:
        raise ScopeError("SCOPE window.end must be after window.start")

    allow_wide = _as_bool(data.get("allow_wide"), default=False)
    targets = parse_targets(data.get("targets"), global_allow_wide=allow_wide)

    tile = data.get("tile") or {}
    if tile is None:
        tile = {}
    if not isinstance(tile, dict):
        raise ScopeError("SCOPE tile must be a mapping")

    version = _as_int(data.get("version"), default=1, name="version", lo=1, hi=1)
    max_workers = _as_int(
        data.get("max_workers"),
        default=_MAX_WORKERS_DEFAULT,
        name="max_workers",
        lo=1,
        hi=_MAX_WORKERS_CEILING,
    )
    max_shards = _as_int(
        data.get("max_shards"),
        default=_MAX_SHARDS_DEFAULT,
        name="max_shards",
        lo=1,
        hi=4096,
    )
    adapter = str(data.get("adapter") or "nmap").strip() or "nmap"
    deepen = parse_deepen(data)
    default_tile = _as_int(
        tile.get("default_prefix"),
        default=DEFAULT_TILE_PREFIX,
        name="tile.default_prefix",
        lo=16,
        hi=32,
    )
    small_tile = _as_int(
        tile.get("small_prefix"),
        default=DEFAULT_SMALL_TILE_PREFIX,
        name="tile.small_prefix",
        lo=default_tile,
        hi=32,
    )

    if verify:
        verify_signature(data)

    scope = Scope(
        version=version,
        demo=_as_bool(data.get("demo")),
        signer=signer,
        purpose=purpose,
        window_start=start,
        window_end=end,
        targets=targets,
        allow_wide=allow_wide,
        max_workers=max_workers,
        max_shards=max_shards,
        adapter=adapter,
        default_tile=default_tile,
        small_tile=small_tile,
        signature=str(data.get("signature") or ""),
        deepen=deepen,
        raw=data,
    )
    return scope


def assert_window(scope: Scope, *, now: datetime | None = None) -> None:
    moment = now or _utc_now()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    if moment < scope.window_start or moment > scope.window_end:
        raise ScopeError(
            f"SCOPE window closed ({scope.window_start.isoformat()} .. "
            f"{scope.window_end.isoformat()})"
        )


def load(
    source: str | Path | dict[str, Any],
    *,
    verify: bool = True,
    require_window: bool = True,
    now: datetime | None = None,
) -> Scope:
    data = _load_mapping(source)
    scope = from_mapping(data, verify=verify)
    if require_window:
        assert_window(scope, now=now)
    return scope


def sign_mapping(data: dict[str, Any], *, key: bytes | None = None) -> dict[str, Any]:
    signed = dict(data)
    signed.pop("signature", None)
    signed["signature"] = compute_signature(signed, key=key)
    return signed


def sign_file(path: Path, *, in_place: bool = True) -> dict[str, Any]:
    data = _load_mapping(path)
    if "demo" not in data:
        data["demo"] = True
    signed = sign_mapping(data)
    if in_place:
        # Preserve a short header comment if present.
        rendered = yaml.safe_dump(signed, sort_keys=False, default_flow_style=False)
        path.write_text(rendered, encoding="utf-8")
    return signed
