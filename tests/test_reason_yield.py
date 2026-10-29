"""
Tests for the yield boosters: novelty/dupe scorer (expected-payout ranking) and the
passive quick-wins detector (an ordinary-bug income stream).
"""

import json
import os
import tempfile

from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.reason import reason, score_novelty, quickwins
from iolite.reason.differ import ReasonCandidate
from iolite.reason.amplify import score_candidate
from iolite.reason.novelty import priority


def _prov():
    return Provenance.of(SourceKind.HAR, "cap")


def _cand(family, path="/api/orders/5", oid="5", depth=1, ek=None):
    return ReasonCandidate(
        endpoint_key=ek or f"GET {path}", method="GET", path=path,
        gap_kind="g", intent_class="OWNER_ONLY", intent_confidence="medium",
        onyx_effect=Effect.OBJECT_ACCESS.value, probe_pids=["B"], object_id=oid,
        family=family, depth=depth)


def test_novel_class_outscores_crowded_enum():
    m = SurfaceModel(host="h")
    novel = score_novelty(_cand("invariant_cross_surface"), m)
    crowded = score_novelty(_cand("assumption_enum", path="/api/users/6", oid="6"), m)
    assert novel.score > crowded.score


def test_ghost_endpoint_boosts_novelty():
    m = SurfaceModel(host="h")
    m.ghost_keys = {"GET /api/legacy/{id}"}
    ghost = score_novelty(_cand("intent_gap", path="/api/legacy/9", oid="9",
                                ek="GET /api/legacy/{id}"), m)
    assert any("ghost" in r for r in ghost.reasons)
    assert ghost.score >= 7


def test_priority_combines_impact_and_novelty():
    m = SurfaceModel(host="h")
    c = _cand("chain_cross_surface", depth=2)
    imp = score_candidate(c, m)
    nov = score_novelty(c, m)
    assert priority(c, imp, nov) == imp.score + nov.score


def test_ranked_by_priority_used_in_report():
    m = SurfaceModel(base_url="https://h", host="h")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"h"}
    ep = Endpoint(method="GET", path="/api/orders/{id}", effect=Effect.OBJECT_ACCESS,
                  provenance=[_prov()], observed_ids=["1000"])
    m.add_endpoint(ep)
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/orders/{id}",
                 object_id="1000", path="/api/orders/1000", method="GET", provenance=_prov(),
                 carrier="path", all_ids=["1000"], safe_read=True))
    rep = reason(m)
    r = rep.ranked_by_priority()
    assert r and rep.priority_of(r[0]) == max(rep.priority_of(c) for c in rep.candidates)


# ---- quick wins -----------------------------------------------------------

def test_quickwin_detects_aws_key_in_js():
    js = "const c = { key: 'AKIAABCDEFGHIJKLMNOP', region: 'us-east-1' };"
    qs = quickwins.detect(js_texts=[js], js_labels=["app.js"])
    assert any("AWS" in q.kind for q in qs)
    # secret is redacted in evidence
    assert "AKIAABCDEFGHIJKLMNOP" not in qs[0].evidence


def test_quickwin_detects_cors_and_verbose_error_in_har():
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://h/api/x"},
         "response": {"status": 200,
                      "headers": [{"name": "Access-Control-Allow-Origin", "value": "*"},
                                  {"name": "Access-Control-Allow-Credentials", "value": "true"}],
                      "content": {"text": "ok"}}},
        {"request": {"method": "GET", "url": "https://h/api/y"},
         "response": {"status": 500, "headers": [],
                      "content": {"text": "Traceback (most recent call last): File ..."}}}]}}
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.har")
        json.dump(har, open(p, "w"))
        qs = quickwins.detect(har_paths=[p])
    kinds = " ".join(q.kind for q in qs)
    assert "CORS" in kinds and "Verbose" in kinds


def test_quickwins_flow_into_reason_report():
    m = SurfaceModel(host="h")

    class _Inputs:
        js_files = []
        archived_js_files = []
        har_files: list = []
    inp = _Inputs()
    with tempfile.TemporaryDirectory() as d:
        js = os.path.join(d, "app.js")
        # Fake key, assembled at runtime so secret scanners don't flag the test itself.
        fake_key = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"
        open(js, "w").write(f"var t='{fake_key}';")
        inp.js_files = [js]
        rep = reason(m, inp)
    assert rep.counts["quickwins"] >= 1
    assert any("Stripe" in q.kind for q in rep.quickwins)


def test_quickwin_writeup_marked_passive():
    from iolite.reason import quickwin_writeup, QuickWin
    from iolite.roe import Engagement
    q = QuickWin(kind="Secret disclosure: AWS access key", severity="high",
                 where="app.js", evidence="AWS ... in app.js", confidence="high")
    wu = quickwin_writeup(q, Engagement(program="Acme"))
    assert "Passive finding" in wu.markdown and "not an ONYX" in wu.markdown
