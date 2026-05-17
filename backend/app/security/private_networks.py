"""Helpers for detecting private / loopback / link-local addresses.

Active scans against non-public address space are blocked unless the target is
explicitly marked `owned_internal=True`. This prevents accidental scanning of
RFC1918 networks the user does not own.
"""
from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlparse


def _extract_host(value: str) -> str:
    value = value.strip()
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or ""
    # Strip any path or port suffix while keeping bare hostnames intact.
    host = value.split("/")[0]
    host = host.split(":")[0]
    return host


def is_private_ip(value: str) -> bool:
    """True if `value` resolves to an RFC1918 / loopback / link-local / ULA address.

    Accepts a hostname, IP, or URL. If `value` is not an IP literal (e.g. a DNS
    name), this returns False — DNS resolution is intentionally not performed
    here because scans frequently target hostnames that should be matched by
    the explicit scope allowlist, not by a heuristic resolver.
    """
    host = _extract_host(value)
    if not host:
        return False
    try:
        addr = ip_address(host)
    except ValueError:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )
