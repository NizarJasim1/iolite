"""Scope-Guard adversarial red-team — no out-of-scope host may leak through."""
from iolite.scope_guard import ScopeConfig, ScopeGuard


def _g(allowed, denied=None):
    return ScopeGuard(ScopeConfig(allowed_hosts=allowed, denied_hosts=denied or [],
                                  automation_permitted=True))


def test_wildcard_matches_apex_and_subdomains():
    g = _g(["*.example.com"])
    assert g.check_host("example.com").allowed          # apex
    assert g.check_host("api.example.com").allowed       # sub
    assert g.check_host("a.b.example.com").allowed        # nested sub


def test_wildcard_rejects_lookalikes():
    g = _g(["*.example.com"])
    for evil in ("example.com.evil.net",       # suffix trick
                 "notexample.com",             # no dot boundary
                 "evilexample.com",            # prefix glue
                 "example.com.attacker.io",
                 "xexample.com"):
        assert not g.check_host(evil).allowed, evil


def test_subdomains_only_excludes_apex():
    g = _g([".example.com"])
    assert not g.check_host("example.com").allowed       # apex excluded
    assert g.check_host("api.example.com").allowed


def test_out_of_scope_wins_over_wildcard():
    g = _g(["*.example.com"], denied=["internal.example.com", "*.secret.example.com"])
    assert g.check_host("api.example.com").allowed
    assert not g.check_host("internal.example.com").allowed
    assert not g.check_host("db.secret.example.com").allowed


def test_userinfo_confusion_defeated():
    # classic trick: victim host in the userinfo, real host is evil.com
    g = _g(["*.example.com"])
    assert not g.check_host("https://api.example.com@evil.com/path").allowed


def test_idn_homograph_rejected():
    g = _g(["apple.com"])
    assert g.check_host("apple.com").allowed
    # Cyrillic 'а' (U+0430) — a homograph, must NOT match ascii apple.com
    assert not g.check_host("аpple.com").allowed


def test_scheme_port_path_case_trailingdot_normalised():
    g = _g(["api.example.com"])
    for variant in ("API.Example.com", "https://api.example.com:8443/x?y=1",
                    "api.example.com.", "http://api.example.com/"):
        assert g.check_host(variant).allowed, variant


def test_empty_and_garbage_halt():
    g = _g(["*.example.com"])
    assert not g.check_host("").allowed
    assert not g.check_host("   ").allowed


def test_probe_gate_still_enforced_under_wildcard():
    g = ScopeGuard(ScopeConfig(allowed_hosts=["*.example.com"],
                               automation_permitted=True, dry_run=True,
                               allow_destructive=False))
    assert g.check_probe("api.example.com", "GET").allowed
    assert not g.check_probe("api.example.com", "DELETE").allowed
    assert not g.check_probe("evil.com", "GET").allowed
