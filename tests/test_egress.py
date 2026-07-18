"""C1 (SSRF via vision) and leak 6 (unbounded egress): the egress guard must
block private/loopback/link-local targets and enforce the allowlist."""

from __future__ import annotations

import pytest

from glc.security import egress


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",       # loopback
        "169.254.169.254", # cloud metadata (link-local)
        "10.0.0.5",        # private
        "192.168.1.1",     # private
        "172.16.0.1",      # private
        "::1",             # ipv6 loopback
        "fe80::1",         # ipv6 link-local
        "0.0.0.0",         # unspecified
    ],
)
def test_forbidden_ips(ip):
    assert egress._is_forbidden_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_ips_allowed(ip):
    assert egress._is_forbidden_ip(ip) is False


def test_ipv4_mapped_ipv6_metadata_blocked():
    # ::ffff:169.254.169.254 must unwrap and be blocked.
    assert egress._is_forbidden_ip("::ffff:169.254.169.254") is True


def test_assert_host_public_blocks_localhost():
    with pytest.raises(egress.EgressBlocked):
        egress.assert_host_public("localhost")


def test_egress_allowlist_blocks_unknown_host(monkeypatch):
    monkeypatch.setenv("GLC_EGRESS_ALLOWLIST", "api.groq.com")
    with pytest.raises(egress.EgressBlocked):
        egress.assert_egress_allowed("attacker.example.com")


def test_egress_allowlist_allows_listed_host(monkeypatch):
    # A listed, publicly-resolving host passes. Use a well-known public host
    # standing in for a provider endpoint so DNS resolves in CI.
    monkeypatch.setenv("GLC_EGRESS_ALLOWLIST", "one.one.one.one")
    egress.assert_egress_allowed("one.one.one.one")  # resolves to 1.1.1.1
