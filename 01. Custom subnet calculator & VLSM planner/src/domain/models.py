"""Immutable value objects shared by the domain, persistence and UI layers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SubnetInfo:
    """Full derived properties of a single IPv4 subnet."""

    network: str  # "192.168.1.0/24"
    prefix: int
    netmask: str  # "255.255.255.0"
    wildcard: str  # "0.0.0.255"
    network_address: str
    broadcast_address: str
    first_host: str
    last_host: str
    total_hosts: int  # 2 ** (32 - prefix)
    usable_hosts: int  # RFC 3021 aware
    binary_network: str  # "11000000.10101000.00000001.00000000"
    binary_mask: str


@dataclass(frozen=True)
class VlsmSegment:
    """A single allocated segment inside a VLSM plan."""

    name: str
    required_hosts: int
    prefix: int  # allocated prefix length
    network: str  # allocated network address ("192.168.1.0")
    usable_hosts: int  # capacity actually provided
    wasted_hosts: int  # capacity - required (>= 0)


@dataclass(frozen=True)
class VlsmPlan:
    """A complete, validated VLSM allocation for a base network."""

    base_network: str
    segments: tuple[VlsmSegment, ...] = field(default_factory=tuple)
    total_required: int = 0
    total_allocated: int = 0  # sum of 2 ** (32 - prefix) per segment
    total_wasted: int = 0
    efficiency: float = 0.0  # total_required / total_allocated


class PlannerError(ValueError):
    """Raised for any user-recoverable planning/validation error."""


class PersistenceError(Exception):
    """Raised when a plan file cannot be read, validated or written."""