"""
test_simlab.py — the internal hardened-target readiness simulation must stay green: the real
engine, driven against Google/Microsoft/Cloudflare/Akamai-class defence models, has to build
intent correctly, surface the seeded bugs, handle every defence, and never turn a defence into a
boundary or a finding. Deterministic (seed=7).
"""
from iolite.intent import simlab


def test_runs_all_four_profiles():
    results = simlab.run_all(seed=7)
    assert len(results) == 4
    names = {r["persona"].name for r in results}
    assert names == {"google-class", "microsoft-class", "cloudflare-fronted", "akamai-ecommerce"}


def test_every_profile_is_operational():
    for r in simlab.run_all(seed=7):
        d = r["diag"]
        assert d["operational_ok"], (r["persona"].name, d["problems"])


def test_seeded_bugs_surface_everywhere():
    for r in simlab.run_all(seed=7):
        d = r["diag"]
        assert d["bola_surfaced_live"] or d["bola_confirmed_replay"], r["persona"].name
        assert d["tenant_surfaced_live"] or d["tenant_confirmed_replay"], r["persona"].name


def test_defences_never_become_boundaries_or_findings():
    for r in simlab.run_all(seed=7):
        d = r["diag"]
        assert d["no_false_boundary_from_defense"], r["persona"].name
        assert d["findings_all_from_clean_response"], r["persona"].name
        assert not d["order_false_positive"], r["persona"].name   # enforced endpoint stays a true-negative


def test_confirmation_has_true_negatives():
    # the enforced `order` leads must come back clean-denied, not confirmed
    totals = {"denied": 0, "findings": 0}
    for r in simlab.run_all(seed=7):
        totals["denied"] += r["confirm_stats"]["denied"]
        totals["findings"] += len(r["findings"])
    assert totals["denied"] > 0 and totals["findings"] > 0


def test_auth_expiry_is_refreshed_under_load():
    ms = next(r for r in simlab.run_all(seed=7) if r["persona"].name == "microsoft-class")
    s = ms["stress"]
    assert s and s["auth_expired"] > 0 and s["completed"] > 0   # tokens expired AND the run continued


def test_report_renders():
    rep = simlab.build_report(simlab.run_all(seed=7))
    assert "READY" in rep
    assert "How it builds authorization intent" in rep
    assert "Defense-aware confirmation" in rep
