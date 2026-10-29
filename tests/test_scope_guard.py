"""Scope-Guard (QL1) — fail-safe to inaction."""
from iolite.scope_guard import ScopeConfig, ScopeGuard, ScopeVerdict


def test_empty_allowlist_halts():
    g = ScopeGuard(ScopeConfig(allowed_hosts=[]))
    assert g.check_host("api.example.com").verdict is ScopeVerdict.HALT


def test_in_scope_allows_exact_only():
    g = ScopeGuard(ScopeConfig(allowed_hosts=["api.example.com"]))
    assert g.check_host("api.example.com").allowed
    # suffix must NOT silently pass (would pull an unauthorised host)
    assert not g.check_host("evil-api.example.com.attacker.net").allowed
    assert not g.check_host("example.com").allowed


def test_host_normalisation():
    g = ScopeGuard(ScopeConfig(allowed_hosts=["API.Example.com:443"]))
    assert g.check_host("https://api.example.com/a/b?x=1").allowed


def test_probe_requires_automation_permitted():
    g = ScopeGuard(ScopeConfig(allowed_hosts=["h.test"], automation_permitted=False))
    assert not g.check_probe("h.test", "GET").allowed  # automation off ⇒ halt


def test_probe_blocks_mutating_by_default():
    g = ScopeGuard(ScopeConfig(allowed_hosts=["h.test"], automation_permitted=True,
                               dry_run=True, allow_destructive=False))
    assert g.check_probe("h.test", "GET").allowed
    assert not g.check_probe("h.test", "DELETE").allowed


def test_probe_allows_mutating_only_when_explicit():
    g = ScopeGuard(ScopeConfig(allowed_hosts=["h.test"], automation_permitted=True,
                               dry_run=False, allow_destructive=True))
    assert g.check_probe("h.test", "DELETE").allowed
