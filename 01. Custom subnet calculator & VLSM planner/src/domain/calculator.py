"""Pure subnet calculation logic (IPv4, RFC 4632 / RFC 3021 aware).

Everything in this module is side-effect free: given valid inputs it returns
deterministic results and never touches files, network or the GUI.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List

from .models import PlannerError, SubnetInfo

# Strict octet grammar. ipaddress rejects leading zeros and out-of-range
# octets, but we pre-filter with regex to fail fast with a friendly message.
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_MASK_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_NETWORK_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$")

# Subnet sizes the equal-division feature supports.
DIVISION_PARTS = (2, 4, 8, 16, 32, 64, 128, 256)


def parse_ipv4(text: str) -> ipaddress.IPv4Address:
    """Strictly parse a dotted-quad IPv4 address.

    Raises PlannerError with a user-friendly message on any violation.
    """
    raw = (text or "").strip()
    if not _IPV4_RE.match(raw):
        raise PlannerError(f"'{text}' is not a valid IPv4 address (expected a.b.c.d).")
    try:
        return ipaddress.IPv4Address(raw)
    except ipaddress.AddressValueError as exc:
        raise PlannerError(f"'{text}' is not a valid IPv4 address: {exc}") from exc


def network_from_string(text: str) -> ipaddress.IPv4Network:
    """Parse 'a.b.c.d/nn' into an IPv4Network (host bits are tolerated)."""
    raw = (text or "").strip()
    m = _NETWORK_RE.match(raw)
    if not m:
        raise PlannerError(
            f"'{text}' is not a valid network. Expected 'a.b.c.d/prefix' e.g. '192.168.1.0/24'."
        )
    ip_str, prefix_str = m.group(1), m.group(2)
    parse_ipv4(ip_str)  # pre-validate the address portion
    prefix = _parse_prefix(prefix_str)
    try:
        # strict=False accepts host bits in the address; the network address
        # is then normalized by ipaddress.
        return ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
    except ValueError as exc:
        raise PlannerError(f"'{text}' is not a valid network: {exc}") from exc


def _parse_prefix(text: str) -> int:
    try:
        prefix = int(text)
    except (TypeError, ValueError):
        raise PlannerError(f"'{text}' is not a valid prefix length.") from None
    if not 0 <= prefix <= 32:
        raise PlannerError(f"Prefix length must be between 0 and 32 (got {prefix}).")
    return prefix


def prefix_from_mask(text: str) -> int:
    """Convert a dotted-decimal netmask ('255.255.255.0') to a prefix length."""
    raw = (text or "").strip()
    if not _MASK_RE.match(raw):
        raise PlannerError(f"'{text}' is not a valid netmask (expected a.b.c.d).")
    try:
        net = ipaddress.IPv4Network(f"0.0.0.0/{raw}")
    except ValueError as exc:
        raise PlannerError(
            f"'{text}' is not a contiguous netmask (e.g. 255.255.255.0)."
        ) from exc
    return net.prefixlen


def _to_binary(ip: ipaddress.IPv4Address) -> str:
    return ".".join(f"{int(ip) >> shift & 0xFF:08b}" for shift in (24, 16, 8, 0))


def netmask_from_prefix(prefix: int) -> str:
    """Render a prefix length as a dotted-decimal netmask."""
    if not 0 <= prefix <= 32:
        raise PlannerError(f"Prefix length must be between 0 and 32 (got {prefix}).")
    if prefix == 0:
        mask = 0
    else:
        mask = 0xFFFFFFFF ^ ((1 << (32 - prefix)) - 1)
    return ".".join(str((mask >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def usable_host_count(prefix: int) -> int:
    """Number of usable hosts for a prefix (RFC 3021 aware)."""
    total = 2 ** (32 - prefix)
    if prefix == 32:
        return 1
    if prefix == 31:
        return 2
    return total - 2


def calculate_subnet(ip_text: str, prefix_text: str) -> SubnetInfo:
    """Compute full subnet details for an IP address and prefix length."""
    ip = parse_ipv4(ip_text)
    prefix = _parse_prefix(prefix_text)
    net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    return _subnet_info(net)


def calculate_subnet_from_mask(ip_text: str, mask_text: str) -> SubnetInfo:
    """Compute full subnet details from an IP address and dotted netmask."""
    prefix = prefix_from_mask(mask_text)
    return calculate_subnet(ip_text, str(prefix))


def _subnet_info(net: ipaddress.IPv4Network) -> SubnetInfo:
    prefix = net.prefixlen
    total = 2 ** (32 - prefix)
    usable = usable_host_count(prefix)
    mask_int = int(net.netmask)
    wildcard_int = (~mask_int) & 0xFFFFFFFF
    wildcard = ".".join(str((wildcard_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))

    if prefix == 32:
        first = last = str(net.network_address)
    elif prefix == 31:
        first, last = str(net.network_address), str(net.broadcast_address)
    else:
        first = str(net.network_address + 1)
        last = str(net.broadcast_address - 1)

    return SubnetInfo(
        network=f"{net.network_address}/{prefix}",
        prefix=prefix,
        netmask=str(net.netmask),
        wildcard=wildcard,
        network_address=str(net.network_address),
        broadcast_address=str(net.broadcast_address),
        first_host=first,
        last_host=last,
        total_hosts=total,
        usable_hosts=usable,
        binary_network=_to_binary(net.network_address),
        binary_mask=_to_binary(net.netmask),
    )


def divide_network(network_text: str, parts: int) -> List[SubnetInfo]:
    """Split a network into `parts` equal subnets (parts must be a power of two).

    The new prefix is `base_prefix + log2(parts)`; the base network must be
    large enough to accommodate the requested division.
    """
    if parts not in DIVISION_PARTS:
        raise PlannerError(
            f"Division into {parts} parts is not supported. "
            f"Choose one of: {', '.join(str(p) for p in DIVISION_PARTS)}."
        )
    net = network_from_string(network_text)
    import math

    new_prefix = net.prefixlen + int(math.log2(parts))
    if new_prefix > 32:
        raise PlannerError(
            f"Cannot divide {net} into {parts} parts: the resulting prefix "
            f"/{new_prefix} exceeds /32."
        )
    size = 2 ** (32 - new_prefix)
    results: List[SubnetInfo] = []
    for i in range(parts):
        subnet = ipaddress.IPv4Network(
            (int(net.network_address) + i * size, new_prefix)
        )
        results.append(_subnet_info(subnet))
    return results