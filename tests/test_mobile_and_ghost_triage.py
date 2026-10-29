"""
Surface beyond the web capture (one seam = off-web acquisition):
  G2 — the CLIENT axis: statically mine the mobile/partner binary for hosts and paths the web
       bundle never ships, classify off-web hosts (partner / staging-internal), and compute the
       mobile-only delta vs the web keyset.
  G4 — the TIME axis, finished: widen `temporal_diff` to the Wayback URL feed, then RANK the
       ghosts by authz-risk (privilege, object-id, write, version auth-regression) and emit the
       top ones as existence-oracle probe targets.

Both feed the same downstream (existence_oracle → capture_plan), which is what makes them one
seam and not two chores. Oracle note (AMP): the delta and ranking checks are could-fail — an
empty web keyset must leave EVERY mined key mobile-only and a full one must leave NONE; the
admin/id ghost must outrank the static-asset ghost; a v1 ghost under a live v2 must be flagged
regression. Self-authored inputs => E2; the green gate is the external no-regression half.
"""
from iolite.mobile_mine import mine_mobile, _classify_host
from iolite.models import Endpoint
from iolite.reason.ghost_triage import (ghosts_from_url_feed, triage_ghosts, probe_targets)
from iolite.intent.existence_oracle import probe_existence


_APP = [(
    'const API="https://api.acme.com/v1";'
    'fetch("https://staging-api.acme.com/v1/admin/users");'
    'const P="https://sdk.partner.io/track";'
    'axios.get("/api/v2/orders/{id}");'
    'axios.post("/api/mobile/pair");',
    "classes.dex")]


# ---- G2: mobile / partner static mining -----------------------------------------

def test_host_classifier_separates_main_partner_staging():
    known = {"acme.com"}
    assert _classify_host("api.acme.com", known) == "main"
    assert _classify_host("staging-api.acme.com", known) == "staging"
    assert _classify_host("sdk.partner.io", known) == "partner"


def test_mobile_hosts_and_mobile_only_delta():
    rep = mine_mobile(_APP, known_hosts={"acme.com"})
    assert "staging-api.acme.com" in rep.hosts_staging        # non-prod host the web never calls
    assert "sdk.partner.io" in rep.hosts_partner              # off-web B2B client
    assert any("acme.com" in h for h in rep.hosts_main)
    assert rep.endpoints, "nothing mined from the app blob"

    # delta logic, could-fail: no web keyset => every mined key is mobile-only
    assert len(rep.mobile_only) == len(rep.endpoints)
    all_keys = [e.key for e in rep.endpoints]
    # full web keyset => the web already knows them all => none are mobile-only
    rep2 = mine_mobile(_APP, known_hosts={"acme.com"}, web_keys=all_keys)
    assert rep2.mobile_only == []
    # a path the web DID capture is excluded; a mobile-only one survives
    rep3 = mine_mobile(_APP, known_hosts={"acme.com"}, web_keys=["GET /api/v2/orders/{id}"])
    assert "GET /api/v2/orders/{id}" not in rep3.mobile_only
    assert len(rep3.mobile_only) == len(rep3.endpoints) - 1


# ---- G4: ghost URL feed + authz-risk triage -------------------------------------

def test_ghosts_from_url_feed_set_difference():
    urls = ["https://x.com/api/v1/admin/users", "https://x.com/api/v2/orders",
            "/legacy/export", "https://x.com"]            # last = bare host, skipped
    ghosts = ghosts_from_url_feed(urls, current_keys=["GET /api/v2/orders"])
    keys = {g.key for g in ghosts}
    assert keys == {"GET /api/v1/admin/users", "GET /legacy/export"}   # v2/orders excluded


def test_triage_ranks_privilege_over_noise_and_flags_regression():
    ghosts = [
        Endpoint(method="GET", path="/static/logo.png"),             # noise
        Endpoint(method="DELETE", path="/api/v1/admin/users/{id}"),  # privilege + id + write
        Endpoint(method="GET", path="/api/v1/orders/{id}"),          # regression vs live v2
    ]
    ranked = triage_ghosts(ghosts, current_keys=["GET /api/v2/orders/{id}"])
    assert ranked[0].key == "DELETE /api/v1/admin/users/{id}"        # highest authz-risk first
    assert ranked[-1].key == "GET /static/logo.png" and ranked[-1].score == 0
    reg = next(r for r in ranked if r.key == "GET /api/v1/orders/{id}")
    assert any("auth-regression" in x for x in reg.reasons)


def test_probe_targets_compose_with_existence_oracle():
    ghosts = ghosts_from_url_feed(
        ["https://x.com/api/v1/admin/users/{id}", "https://x.com/favicon.ico"], current_keys=[])
    ranked = triage_ghosts(ghosts)
    targets = probe_targets(ranked, min_score=2)
    assert "/api/v1/admin/users/{id}" in targets                     # privileged ghost kept
    assert "/favicon.ico" not in targets                             # score 0 dropped
    # feed straight to the pair-5 oracle; with no attestation it stays offline (fail-closed)
    res = probe_existence(targets)
    assert res.mode == "offline" and res.sent == 0 and len(res.leads) == len(targets)


def test_triage_is_deterministic():
    g = ghosts_from_url_feed(["https://x.com/api/v1/admin", "/b/export", "/c/role/{id}"], [])
    a = [(r.key, r.score) for r in triage_ghosts(g)]
    b = [(r.key, r.score) for r in triage_ghosts(ghosts_from_url_feed(
        ["https://x.com/api/v1/admin", "/b/export", "/c/role/{id}"], []))]
    assert a == b
