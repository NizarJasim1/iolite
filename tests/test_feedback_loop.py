"""
The adaptive loop (seam = closing the chain): a CONFIRMED ONYX finding is evidence about a
neighbourhood, so it re-weights discovery and capture toward the siblings of what was proved.

Oracle note (AMP): could-fail checks — a sibling of the SAME object-type as a confirmed BOLA
must outrank an unrelated endpoint it previously tied/led; a candidate sharing NO feature must
be untouched; the learned boost must be CAPPED (never swamp the base authz score); and with no
findings the order must be returned unchanged. Writes into triage's own ledger (ep.risk +
"+N reason"). Self-authored inputs => E2; the green gate is the external no-regression half.
"""
from iolite.models import Endpoint
from iolite.reason.feedback import (ConfirmedFinding, reweight, reweight_capture, _CAP)
from iolite.intent.capture_plan import CaptureStep


def _ep(method, path, risk=0):
    e = Endpoint(method=method, path=path)
    e.risk = risk
    return e


def test_confirmed_finding_lifts_same_type_siblings():
    sibling = _ep("GET", "/api/order/{id}", risk=5)          # same type as the confirmed hole
    unrelated = _ep("GET", "/api/tag/{id}", risk=5)          # no shared feature
    finding = ConfirmedFinding(family="bola", path="/api/order/99", method="GET")
    ranked = reweight([unrelated, sibling], [finding])
    assert ranked[0] is sibling                              # neighbour of the confirmed hole first
    assert sibling.risk > unrelated.risk
    assert any("learned" in r and "order" in r for r in sibling.risk_reasons)


def test_unrelated_candidate_is_untouched():
    unrelated = _ep("GET", "/api/tag/{id}", risk=5)
    reweight([unrelated], [ConfirmedFinding(family="bola", path="/api/order/99")])
    assert unrelated.risk == 5 and not unrelated.risk_reasons   # shares nothing → no learned bump


def test_version_and_privileged_neighbourhoods():
    ver = _ep("GET", "/api/v1/profile")                      # same /v1 family as the finding
    priv = _ep("GET", "/api/admin/stats")                    # same privileged prefix
    f = ConfirmedFinding(family="auth_regression", path="/api/v1/admin/users", method="GET")
    ranked = reweight([ver, priv], [f])
    assert ver.risk >= 4 and priv.risk >= 4                  # both sit in a confirmed neighbourhood
    assert all(r.risk_reasons for r in ranked)


def test_learned_boost_is_capped():
    # a candidate matching EVERY feature of a confirmed finding must still be bounded by _CAP
    twin = _ep("DELETE", "/api/v1/admin/order/{id}")
    f = ConfirmedFinding(family="bfla", path="/api/v1/admin/order/5", method="DELETE",
                         host="api.acme.com")
    reweight([twin], [f], host="api.acme.com")
    assert twin.risk == _CAP                                 # summed features exceed the cap → clamped
    assert any("capped" in r for r in twin.risk_reasons)


def test_no_findings_leaves_order_unchanged():
    a, b = _ep("GET", "/a", risk=3), _ep("GET", "/b", risk=9)
    assert reweight([a, b], []) == [a, b]                    # identity when nothing is confirmed yet


def test_capture_plan_reorders_toward_confirmed_type():
    s_order = CaptureStep(object_type="order", flow="capture POST on order", methods=["POST"], est_tests=4)
    s_tag = CaptureStep(object_type="tag", flow="capture GET on tag", methods=["GET"], est_tests=6)
    steps = reweight_capture([s_tag, s_order],
                             [ConfirmedFinding(family="bola", path="/api/order/1", method="POST")])
    assert steps[0] is s_order                               # the confirmed type's capture jumps the queue
    assert s_order.est_tests > 6 and "learned" in s_order.why
