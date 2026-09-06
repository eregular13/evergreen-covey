from __future__ import annotations

import pytest

from covey.errors import ShardError
from covey.shard import (
    expand_cidr,
    expand_network,
    host_list,
    is_wide_network,
    parse_v4_network,
    tile_prefix_for,
)


def test_slash28_default_stays_one_tile():
    assert expand_cidr("10.42.0.0/28") == ["10.42.0.0/28"]


def test_slash28_small_prefix_30_makes_four_tiles():
    tiles = expand_cidr("10.42.0.0/28", small_tile=30)
    assert tiles == [
        "10.42.0.0/30",
        "10.42.0.4/30",
        "10.42.0.8/30",
        "10.42.0.12/30",
    ]


def test_slash24_stays_slash24():
    assert expand_cidr("10.1.2.0/24") == ["10.1.2.0/24"]


def test_slash23_becomes_two_slash24s():
    tiles = expand_cidr("10.1.2.0/23")
    assert tiles == ["10.1.2.0/24", "10.1.3.0/24"]


def test_slash16_tiles_to_256_slash24s():
    net = parse_v4_network("10.0.0.0/16")
    assert is_wide_network(net)
    tiles = expand_network(net)
    assert len(tiles) == 256
    assert str(tiles[0]) == "10.0.0.0/24"
    assert str(tiles[-1]) == "10.0.255.0/24"


def test_single_host():
    assert expand_cidr("127.0.0.1/32") == ["127.0.0.1/32"]


def test_refuse_star_and_default_route():
    for token in ("*", "0.0.0.0/0", "any", "all"):
        with pytest.raises(ShardError):
            parse_v4_network(token)


def test_refuse_ipv6():
    with pytest.raises(ShardError, match="IPv6"):
        parse_v4_network("::1/128")


def test_refuse_wider_than_slash8():
    with pytest.raises(ShardError, match="wider than /8"):
        parse_v4_network("10.0.0.0/4")


def test_tile_prefix_rules():
    assert tile_prefix_for(parse_v4_network("10.0.0.0/16")) == 24
    assert tile_prefix_for(parse_v4_network("10.1.2.0/24")) == 24
    assert tile_prefix_for(parse_v4_network("10.1.2.0/26")) == 28
    assert tile_prefix_for(parse_v4_network("10.1.2.0/28")) == 28
    assert tile_prefix_for(parse_v4_network("10.1.2.0/28"), small_tile=30) == 30


def test_host_list_only_for_tiny_ranges():
    assert host_list(parse_v4_network("10.0.0.0/24")) == []
    hosts = host_list(parse_v4_network("10.0.0.0/30"))
    assert hosts == ["10.0.0.1", "10.0.0.2"]
