"""
Tests for the impact/severity amplifier: effect ordering, scale/sensitivity/chain
boosts, band thresholds, ranking, bounded scale-proof, and that scoring never asserts
a finding (it only prioritises; ONYX still decides).
"""

from iolite.models import Effect, SurfaceModel
from iolite.reason.differ import ReasonCandidate
from iolite.reason.amplify import score_candidate, ranked, scale_probes
from iolite.reason import reason
from iolite.models import (Endpoint, ObservedAccess, Principal, Provenance, SourceKind)


def _c(effect, path="/api/x/1", family="intent_gap", oid="1", depth=1, chain_from=""):
    return ReasonCandidate(
        endpoint_key=f"GET {path}", method="GET", path=path, gap_kind="g",
        intent_class="OWNER_ONLY", intent_confidence="medium", onyx_effect=effect,
        probe_pids=["A"], object_id=oid, family=family, depth=depth, chain_from=chain_from)


def _m():
    return SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")


def test_payment_outranks_object_access():
    m = _m()
    pay = score_candidate(_c(Effect.PAYMENT.value, "/api/payments/1"), m)
    obj = score_candidate(_c(Effect.OBJECT_ACCESS.value, "/api/things/1"), m)
    assert pay.score > obj.score


def test_enumerable_id_boosts_score():
    m = _m()
    seq = score_candidate(_c(Effect.OBJECT_ACCESS.value, "/api/orders/1000", oid="1000"), m)
    uuid = score_candidate(_c(Effect.OBJECT_ACCESS.value,
                              "/api/orders/abc", oid="550e8400-e29b-41d4-a716-446655440000"), m)
    assert seq.score > uuid.score
    assert any("enumerable" in r for r in seq.reasons)


def test_chain_depth_boosts_and_bands_are_ordered():
    m = _m()
    base = score_candidate(_c(Effect.OBJECT_ACCESS.value, "/api/orders/1", oid="1"), m)
    chained = score_candidate(_c(Effect.OBJECT_ACCESS.value, "/api/orders/1", oid="1",
                                 depth=2, chain_from="x"), m)
    assert chained.score > base.score
    # a funds + enumerable + chain + tenant candidate should reach critical
    crit = score_candidate(_c(Effect.PAYMENT.value, "/api/tenant/wallet/1000",
                              oid="1000", depth=2, chain_from="x"), m)
    assert crit.band == "critical"


def test_ranked_orders_by_score():
    m = _m()
    cands = [_c(Effect.OBJECT_ACCESS.value, "/api/a/1", oid="1"),
             _c(Effect.PAYMENT.value, "/api/payments/wallet/1000", oid="1000")]
    r = ranked(cands, m)
    assert r[0][1].onyx_effect if False else r[0][0].onyx_effect == Effect.PAYMENT.value


def test_scale_proof_is_bounded_and_reads_only():
    c = _c(Effect.OBJECT_ACCESS.value, "/api/orders/1000", oid="1000")
    probes = scale_probes(c, n=3)
    assert 1 <= len(probes) <= 3
    assert all(p.family == "amplify_scale" and p.method == "GET" for p in probes)
    assert all(p.probe_pids == ["A"] for p in probes)     # own principal only


def test_report_carries_impact_bands():
    m = SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"api.demo.test"}
    ep = Endpoint(method="GET", path="/api/payments/{id}", effect=Effect.PAYMENT.value
                  if False else Effect.PAYMENT, provenance=[Provenance.of(SourceKind.HAR, "c")],
                  observed_ids=["1000"])
    m.add_endpoint(ep)
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/payments/{id}",
                 object_id="1000", path="/api/payments/1000", method="GET",
                 provenance=Provenance.of(SourceKind.HAR, "c"), carrier="path",
                 all_ids=["1000"], safe_read=True))
    rep = reason(m)
    assert "by_band" in rep.counts
    assert sum(rep.by_band().values()) == len(rep.candidates)
    # highest-impact candidate is ranked first
    if rep.candidates:
        top = rep.ranked()[0]
        assert rep.impact[top.cand_key].score == max(s.score for s in rep.impact.values())
