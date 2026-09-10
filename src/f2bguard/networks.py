"""Efficient immutable membership index for IPv4 and IPv6 networks."""

from __future__ import annotations

import ipaddress
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class _Intervals:
    starts: tuple[int, ...]
    ends: tuple[int, ...]

    def contains(self, value: int) -> bool:
        position = bisect_right(self.starts, value) - 1
        return position >= 0 and value <= self.ends[position]


class NetworkIndex:
    """Merged per-family address intervals with O(log n) membership checks."""

    def __init__(self, networks: Iterable[IPNetwork]):
        ranges: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
        for network in networks:
            if not isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                raise TypeError("NetworkIndex entries must be IPv4Network or IPv6Network")
            ranges[network.version].append(
                (int(network.network_address), int(network.broadcast_address))
            )
        self._families = {
            version: self._merge(family_ranges) for version, family_ranges in ranges.items()
        }

    @staticmethod
    def _merge(ranges: list[tuple[int, int]]) -> _Intervals:
        if not ranges:
            return _Intervals((), ())
        ranges.sort()
        merged: list[list[int]] = []
        for start, end in ranges:
            if not merged or start > merged[-1][1] + 1:
                merged.append([start, end])
            elif end > merged[-1][1]:
                merged[-1][1] = end
        return _Intervals(
            tuple(interval[0] for interval in merged),
            tuple(interval[1] for interval in merged),
        )

    def contains(self, address: str | IPAddress) -> bool:
        parsed = ipaddress.ip_address(address) if isinstance(address, str) else address
        if not isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            raise TypeError("address must be an IP address or literal")
        return self._families[parsed.version].contains(int(parsed))

    def __contains__(self, address: object) -> bool:
        if not isinstance(address, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return False
        try:
            return self.contains(address)
        except ValueError:
            return False

    def exclude(self, addresses: Iterable[str]) -> list[str]:
        """Return input literals that are outside every indexed network."""

        return [address for address in addresses if not self.contains(address)]

    def __len__(self) -> int:
        """Return the number of merged intervals across both families."""

        return sum(len(intervals.starts) for intervals in self._families.values())
