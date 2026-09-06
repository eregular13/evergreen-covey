"""Pure CIDR tile math. No scanners. No network I/O."""

from __future__ import annotations

from ipaddress import IPv4Network, ip_network

from covey.errors import ShardError

ALWAYS_REFUSED = frozenset(
    {
        "0.0.0.0/0",
        "0.0.0.0/0.0.0.0",
        "*",
        "any",
        "all",
        "internet",
        "::/0",
    }
)

# Prefix lengths 8 through 16 inclusive are "wide".
WIDE_PREFIX_MIN = 8
WIDE_PREFIX_MAX = 16

DEFAULT_TILE_PREFIX = 24
DEFAULT_SMALL_TILE_PREFIX = 28


def normalize_target_token(raw: str) -> str:
    return (raw or "").strip()


def is_always_refused_token(raw: str) -> bool:
    token = normalize_target_token(raw).lower()
    if token in ALWAYS_REFUSED:
        return True
    if token in {"0.0.0.0", "0/0"}:
        return True
    return False


def parse_v4_network(raw: str) -> IPv4Network:
    token = normalize_target_token(raw)
    if not token:
        raise ShardError("empty CIDR")
    if is_always_refused_token(token):
        raise ShardError(f"refused target token: {token}")
    try:
        net = ip_network(token, strict=False)
    except ValueError as exc:
        raise ShardError(f"invalid CIDR {token!r}: {exc}") from exc
    if not isinstance(net, IPv4Network):
        raise ShardError(f"IPv6 targets are not accepted: {token}")
    if net.prefixlen == 0:
        raise ShardError("refused default route 0.0.0.0/0")
    if net.prefixlen < WIDE_PREFIX_MIN:
        raise ShardError(
            f"{net} is wider than /8; Covey will not expand it"
        )
    return net


def is_wide_network(net: IPv4Network) -> bool:
    return WIDE_PREFIX_MIN <= net.prefixlen <= WIDE_PREFIX_MAX


def tile_prefix_for(
    net: IPv4Network,
    *,
    default_tile: int = DEFAULT_TILE_PREFIX,
    small_tile: int = DEFAULT_SMALL_TILE_PREFIX,
) -> int:
    """Pick a tile prefix for an already-allowed network.

    - Larger than /24 (prefix < 24): tile to /24.
    - Exactly /24: stay /24.
    - Smaller than /24 but coarser than ``small_tile``: tile to ``small_tile``
      (lab /28 → /30s when small_tile=30).
    - At or finer than ``small_tile``: keep the network as one tile
      (or a host if /32).
    """
    if not 0 < default_tile <= 32 or not 0 < small_tile <= 32:
        raise ShardError("tile prefixes must be in 1..32")
    if small_tile < default_tile:
        raise ShardError("small_tile must be >= default_tile")

    prefix = net.prefixlen
    if prefix >= 32:
        return 32
    if prefix < default_tile:
        return default_tile
    if prefix == default_tile:
        return default_tile
    if prefix < small_tile:
        return small_tile
    return prefix


def expand_network(
    net: IPv4Network,
    *,
    default_tile: int = DEFAULT_TILE_PREFIX,
    small_tile: int = DEFAULT_SMALL_TILE_PREFIX,
) -> list[IPv4Network]:
    tile = tile_prefix_for(net, default_tile=default_tile, small_tile=small_tile)
    if tile < net.prefixlen:
        raise ShardError(f"tile /{tile} is coarser than {net}")
    if tile == net.prefixlen:
        return [net]
    return list(net.subnets(new_prefix=tile))


def expand_cidr(
    cidr: str,
    *,
    default_tile: int = DEFAULT_TILE_PREFIX,
    small_tile: int = DEFAULT_SMALL_TILE_PREFIX,
) -> list[str]:
    net = parse_v4_network(cidr)
    return [
        str(tile)
        for tile in expand_network(
            net, default_tile=default_tile, small_tile=small_tile
        )
    ]


def host_list(net: IPv4Network) -> list[str]:
    """Usable hosts if the range is tiny; otherwise empty (caller should tile)."""
    if net.prefixlen < 29:
        return []
    return [str(ip) for ip in net.hosts()]
