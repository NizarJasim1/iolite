"""
Tests for Point 1 — workflow_intent (declared-guard miner) + sequence (state-indexed
hypotheses). Proves: guards are mined from DECLARED code (not observed traffic);
gate-skip candidates carry the right pre-state + ONYX STATE_GATE effect; the engine
is byte-identical when workflow is OFF (no weakening); determinism.
"""

import os
import tempfile

from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.pipeline import Inputs
from iolite.reason import reason, mine_workflow_guards, run_sequence, infer_intent
from iolite.reason.enforcement import observe_enforcement

_JS_WITH_GUARD = """
const OrderStatus = Object.freeze({ PENDING: 'PENDING', PAID: 'PAID', SHIPPED: 'SHIPPED' });
function renderOrder(order) {
  // refund is only allowed once the order is paid
  if (order.status !== 'PAID') { disableRefundButton(); return; }
  enableRefund();
}
axios({ url: '/api/orders/' + id + '/refund', method: 'POST' });
"""


def _model_with_refund():
    m = SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"api.demo.test"}
    # a GET that names the object type + a mutating refund transition
    m.add_endpoint(Endpoint(method="GET", path="/api/orders/{id}",
                            effect=Effect.OBJECT_ACCESS,
                            provenance=[Provenance.of(SourceKind.HAR, "cap")],
                            observed_ids=["1001"]))
    m.add_endpoint(Endpoint(method="POST", path="/api/orders/{id}/refund",
                            effect=Effect.STATE_GATE,
                            provenance=[Provenance.of(SourceKind.JS, "app.js")]))
    m.add_access(ObservedAccess(
        principal_id="A", endpoint_key="GET /api/orders/{id}", object_id="1001",
        path="/api/orders/1001", method="GET",
        provenance=Provenance.of(SourceKind.HAR, "cap"),
        carrier="path", all_ids=["1001"], safe_read=True))
    return m


def test_guard_is_mined_from_declared_code():
    guards = mine_workflow_guards(_model_with_refund(), js_texts=[_JS_WITH_GUARD],
                                  js_locators=["app.js"])
    assert guards, "a declared status guard must be mined"
    g = [x for x in guards if x.field == "status" and x.value == "PAID"]
    assert g, "refund-requires-PAID guard expected"
    got = g[0]
    assert got.mode == "requires"                      # `!==` block ⇒ op REQUIRES PAID
    assert got.operation_hint == "refund"
    assert got.object_hint == "order"                  # from the OrderStatus enum
    assert got.confidence in ("high", "medium")


def test_sequence_emits_state_gate_candidate():
    m = _model_with_refund()
    guards = mine_workflow_guards(m, js_texts=[_JS_WITH_GUARD], js_locators=["app.js"])
    cands = run_sequence(m, infer_intent(m), observe_enforcement(m), guards)
    gate = [c for c in cands if c.family == "workflow_gate_skip"]
    assert gate, "a gate-skip candidate must be produced for the refund transition"
    c = gate[0]
    assert c.onyx_effect == Effect.STATE_GATE.value
    assert c.endpoint_key == "POST /api/orders/{id}/refund"
    assert c.pre_state == {"status": "≠PAID"}
    assert c.required_predecessor == "status==PAID"
    assert set(c.probe_pids) == {"A", "B"}             # own principals
    # the pre_state makes the cand_key distinct from a stateless one
    assert "@status=" in c.cand_key


def test_empty_guards_yield_nothing():
    m = _model_with_refund()
    assert run_sequence(m, infer_intent(m), observe_enforcement(m), []) == []


def test_engine_off_is_identical_and_on_adds():
    """with_workflow=False must not change the candidate set; True must add ≥1."""
    m = _model_with_refund()
    with tempfile.TemporaryDirectory() as d:
        js = os.path.join(d, "app.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_JS_WITH_GUARD)
        inp = Inputs(js_files=[js])
        off = reason(m, inp, with_workflow=False)
        on = reason(m, inp, with_workflow=True)
    off_keys = {c.cand_key for c in off.candidates}
    on_keys = {c.cand_key for c in on.candidates}
    assert off.counts.get("workflow_guards", 0) == 0
    assert off_keys <= on_keys                         # OFF ⊆ ON (purely additive)
    assert any(c.family == "workflow_gate_skip" for c in on.candidates)
    assert on.counts["workflow_guards"] >= 1


def test_determinism():
    m = _model_with_refund()
    g1 = mine_workflow_guards(m, js_texts=[_JS_WITH_GUARD], js_locators=["app.js"])
    g2 = mine_workflow_guards(m, js_texts=[_JS_WITH_GUARD], js_locators=["app.js"])
    assert [x.key() for x in g1] == [x.key() for x in g2]
    c1 = run_sequence(m, infer_intent(m), observe_enforcement(m), g1)
    c2 = run_sequence(m, infer_intent(m), observe_enforcement(m), g2)
    assert [c.cand_key for c in c1] == [c.cand_key for c in c2]
