"""
Tests for Point 4 — econ (measured $/hr ledger), kb (cross-session regression/fresh),
collision (sound dedup proxy), readiness (EV gate). Proves: realized-EV recommendations
are deterministic; a weakened guard is flagged as a fresh/low-collision bug; an
UNCONFIRMED finding can never be GO; out-of-scope is DROP.
"""

import os
import tempfile

from iolite.reason.econ import (EconEntry, program_stats, recommend,
                                load_ledger, save_ledger, portfolio_summary)
from iolite.reason.kb import KB, update_from, kb_signals, fresh_endpoints, regressions
from iolite.reason.collision import collision_score
from iolite.reason.readiness import assess
from iolite.reason.differ import ReasonCandidate
from iolite.reason.workflow_intent import DeclaredGuard
from iolite.reason.intent import IntentRule, AccessClass


def _cand(key="POST /api/orders/{id}/refund", gate="status==PAID", pre=None):
    return ReasonCandidate(
        endpoint_key=key, method="POST", path="/api/orders/{id}/refund",
        gap_kind="sequence_gate_skip", intent_class="OWNER_ONLY",
        intent_confidence="high", onyx_effect="STATE_GATE", probe_pids=["A"],
        required_predecessor=gate, pre_state=pre or {"status": "≠PAID"},
        family="workflow_gate_skip")


# ---- econ ---------------------------------------------------------------- #

def test_econ_stats_and_recommend():
    entries = [
        EconEntry("Alpha", "paid", 500, 2), EconEntry("Alpha", "paid", 700, 3),
        EconEntry("Alpha", "paid", 300, 1),                       # $300/hr, acc 1.0, 3 decided
        EconEntry("Beta", "duplicate", 0, 2), EconEntry("Beta", "informational", 0, 2),
        EconEntry("Beta", "not-applicable", 0, 2),                # $0/hr, acc 0, 3 decided
        EconEntry("Gamma", "pending", 0, 1),                      # too few decided
    ]
    stats = program_stats(entries)
    assert stats["Alpha"].dollars_per_hour == 250.0               # 1500 / 6h
    assert stats["Alpha"].acceptance_rate == 1.0
    assert stats["Beta"].acceptance_rate == 0.0
    recs = {r.program: r.action for r in recommend(entries and stats)}
    assert recs["Alpha"] == "FOCUS"
    assert recs["Beta"] == "DROP"
    assert recs["Gamma"] == "EXPLORE"                             # bounded exploration, not premature DROP


def test_econ_roundtrip_and_summary():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "econ.json")
        save_ledger(p, [EconEntry("X", "paid", 1000, 5)])
        back = load_ledger(p)
    assert len(back) == 1 and back[0].program == "X" and back[0].payout == 1000
    s = portfolio_summary([EconEntry("X", "paid", 1000, 5)])
    assert s["blended_dollars_per_hour"] == 200.0


# ---- kb ------------------------------------------------------------------ #

def _intent(keys):
    return {k: IntentRule(k, AccessClass.OWNER_ONLY, "high") for k in keys}


def test_kb_fresh_and_regression():
    kb = KB()
    guards_v1 = [DeclaredGuard("order", "status", "PAID", "requires", "refund", "high", "js")]
    update_from(kb, "prog", _intent(["GET /api/orders/{id}"]), guards_v1)
    prior = kb.program("prog")

    # next session: a NEW endpoint appears, and the PAID guard has VANISHED (weakened)
    intent_v2 = _intent(["GET /api/orders/{id}", "POST /api/orders/{id}/refund"])
    guards_v2 = []                                                # guard gone ⇒ regression
    assert fresh_endpoints(prior, intent_v2) == ["POST /api/orders/{id}/refund"]
    assert regressions(prior, guards_v2) == ["status==PAID"]
    sig = kb_signals(prior, intent_v2, guards_v2)
    assert "POST /api/orders/{id}/refund" in sig["fresh"]
    assert "status" in sig["regressed_objects"]


# ---- collision ----------------------------------------------------------- #

def test_collision_boosted_by_fresh_and_regression():
    cand = _cand()
    base = collision_score(cand, novelty_score=6, kb_sig=None)
    boosted = collision_score(cand, novelty_score=6, kb_sig={
        "fresh": {cand.endpoint_key}, "regressed_objects": {"status"}, "regressions": ["status==PAID"]})
    assert boosted.score > base.score
    assert boosted.p_original > base.p_original
    assert any("REGRESSION" in r for r in boosted.reasons)


# ---- readiness (EV gate) ------------------------------------------------- #

def test_readiness_confirmed_critical_is_go():
    col = collision_score(_cand(), novelty_score=9)               # p_original 0.9
    r = assess(_cand(), "critical", col, confirmed=True, in_scope=True)
    assert r.verdict == "GO" and r.ev > 150


def test_readiness_unconfirmed_never_go():
    col = collision_score(_cand(), novelty_score=9)
    r = assess(_cand(), "critical", col, confirmed=False, in_scope=True)
    assert r.verdict != "GO"                                      # cannot GO without ONYX
    assert r.verdict in ("HOLD", "DROP")


def test_readiness_out_of_scope_is_drop():
    col = collision_score(_cand(), novelty_score=9)
    r = assess(_cand(), "critical", col, confirmed=True, in_scope=False)
    assert r.verdict == "DROP"


def test_readiness_low_value_is_drop():
    col = collision_score(_cand(), novelty_score=1)               # crowded → p_original 0.1
    r = assess(_cand(), "low", col, confirmed=True, in_scope=True)
    assert r.verdict == "DROP"


def test_determinism():
    e = [EconEntry("A", "paid", 100, 1), EconEntry("A", "duplicate", 0, 1),
         EconEntry("A", "paid", 100, 1)]
    assert [r.action for r in recommend(program_stats(e))] == \
           [r.action for r in recommend(program_stats(e))]
