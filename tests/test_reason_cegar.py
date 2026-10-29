"""
Tests for the CEGAR loop (ONYX-as-oracle refinement + chain composer).

Proven here with a SimulatedOracle (deterministic fake verdicts); the LIVE loop runs
ONYX against a real attested target on the operator's machine. We assert: confirmed
capabilities spawn deeper chained candidates, denials prune, depth is bounded, the
static (offline) oracle never fabricates a confirmation, and own-principals-only.
"""

from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.roe import Engagement
from iolite.reason import refine_search, SimulatedOracle, StaticOracle
from iolite.reason.cegar import _escalate
from iolite.reason.intent import infer_intent
from iolite.reason.enforcement import observe_enforcement


def _prov():
    return Provenance.of(SourceKind.HAR, "cap")


def _model():
    m = SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"api.demo.test"}
    # object 5 on a strict object endpoint and a looser search surface (cross-surface)
    m.add_endpoint(Endpoint(method="GET", path="/api/orders/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()], observed_ids=["5"]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/orders/{id}",
                 object_id="5", path="/api/orders/5", method="GET", provenance=_prov(),
                 carrier="path", all_ids=["5"], safe_read=True))
    m.add_endpoint(Endpoint(method="GET", path="/api/search",
                            effect=Effect.FIELD_PROJECTION, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/search",
                 object_id="5", path="/api/search", method="GET", provenance=_prov(),
                 query={"q": "5"}, carrier="query", all_ids=["5"], safe_read=True))
    return m


def test_static_oracle_never_confirms():
    m = _model()
    trace = refine_search(m, Engagement(program="t"), oracle=StaticOracle(), depth=3)
    assert trace.oracle_kind == "static"
    assert trace.confirmed_count == 0          # offline: nothing fabricated
    assert trace.rounds and trace.rounds[0].tested >= 1


def test_confirmed_capability_spawns_deeper_chain():
    m = _model()
    # simulate ONYX confirming the horizontal reach of object 5 at the orders endpoint
    oracle = SimulatedOracle(confirm_keys={"GET /api/orders/{id}"})
    trace = refine_search(m, Engagement(program="t"), oracle=oracle, depth=3)
    assert trace.confirmed_count >= 1
    # a depth-2 chained candidate must have been spawned from the confirmed capability
    deeper = [c for c in trace.all_candidates if c.depth >= 2]
    assert deeper, "confirmed capability must spawn a depth-2 chain candidate"
    assert any(c.family.startswith("chain_") for c in deeper)
    # lineage is recorded
    assert all(c.chain_from for c in deeper)


def test_depth_is_bounded():
    m = _model()
    # confirm everything → the loop would recurse forever without the depth bound
    keys = set(m.endpoints)
    oracle = SimulatedOracle(confirm_keys=keys)
    trace = refine_search(m, Engagement(program="t"), oracle=oracle, depth=2)
    assert len(trace.rounds) <= 2
    assert all(c.depth <= 2 for c in trace.all_candidates)


def test_denied_candidates_are_pruned():
    m = _model()
    oracle = SimulatedOracle(confirm_keys=set())      # deny everything
    trace = refine_search(m, Engagement(program="t"), oracle=oracle, depth=3)
    assert trace.pruned >= 1
    assert trace.confirmed_count == 0


def test_leaked_id_spawns_disclosure_chain():
    m = _model()
    intent, enf = infer_intent(m), observe_enforcement(m)
    cap = next(c for c in refine_search(m, Engagement(program="t"),
               oracle=SimulatedOracle(confirm_keys={"GET /api/orders/{id}"}), depth=1
               ).all_candidates if c.endpoint_key == "GET /api/orders/{id}")
    spawned = _escalate(cap, m, intent, enf, leaked_ids=["777"])
    assert any(c.gap_kind == "chain_disclosure" and c.object_id == "777" for c in spawned)


def test_chain_candidates_use_only_own_principals():
    m = _model()
    oracle = SimulatedOracle(confirm_keys={"GET /api/orders/{id}"})
    trace = refine_search(m, Engagement(program="t"), oracle=oracle, depth=3)
    pids = {p.pid for p in m.principals}
    for c in trace.all_candidates:
        for pid in c.probe_pids:
            assert pid in pids                 # QL6 — never a fabricated principal
