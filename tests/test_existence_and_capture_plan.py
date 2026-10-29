"""
Test-surface completeness (one seam = the acquisition frontier):
  G1 — discover the HIDDEN surface: hypothesise unobserved siblings from observed structure,
       then confirm EXISTENCE only, fail-closed (nothing sent without attestation), with a
       SAFE method, distinguishing 404 from 401/403/405.
  L5 — a prioritised CAPTURE PLAN: diff the exposed write surface against captured flows and
       rank each missing flow by the authz tests it unlocks; G1's hidden hits fold in on top.

Oracle note (AMP): decisive checks are could-fail — the gate must send NOTHING unattested
(assert the sender is never called), existence must classify a real 403 as 'exists' and a 404
as 'absent', and a fully-captured type must yield NO plan step. Self-authored inputs => E2;
the green gate is the external no-regression half; the live probe is ROE-gated, not run here.
"""
from types import SimpleNamespace

from iolite.models import (Effect, Endpoint, ObservedAccess, Provenance, SourceKind, SurfaceModel)
from iolite.intent.existence_oracle import (hidden_path_hypotheses, probe_existence,
                                            ExistenceHit)
from iolite.intent.capture_plan import plan_capture


def _prov():
    return Provenance.of(SourceKind.HAR, "test.har")


def _ep(m, method, path, **kw):
    m.add_endpoint(Endpoint(method=method, path=path, effect=kw.get("effect", Effect.NONE),
                            params=kw.get("params", []), provenance=[_prov()]))


def _acc(m, pid, method, path, oid, **kw):
    m.add_access(ObservedAccess(principal_id=pid, endpoint_key=f"{method} {path}",
                                object_id=oid, path=path.replace("{id}", oid) if oid else path,
                                method=method, provenance=_prov(), carrier="path",
                                body=kw.get("body"), all_ids=[oid] if oid else [],
                                safe_read=kw.get("safe_read", True)))


# ---- G1: hidden-surface hypotheses + gated existence oracle ---------------------

def test_hidden_path_hypotheses_from_structure():
    m = SurfaceModel(base_url="https://t.com", host="t.com")
    _ep(m, "GET", "/api/v1/orders/{id}")
    _ep(m, "GET", "/api/users")
    hyps = {h.path for h in hidden_path_hypotheses(m)}
    assert "/api/v2/orders/{id}" in hyps                 # version sibling
    assert any("/admin/" in p or "/internal/" in p for p in hyps)   # privileged variant
    assert "/api/v1/orders" in hyps                      # item -> collection
    assert "/api/users/{id}" in hyps                     # collection -> item
    assert "/api/v1/orders/{id}" not in hyps and "/api/users" not in hyps  # never the observed


def test_existence_oracle_is_fail_closed_without_attestation():
    calls = []
    sender = lambda method, path: (calls.append((method, path)) or 404)
    eng = SimpleNamespace(attestation="", automation_permitted=False, dry_run=True,
                          max_requests_per_min=30)
    hyps = hidden_path_hypotheses(_min_model())
    res = probe_existence(hyps, engagement=eng, sender=sender, in_scope=True)
    assert res.mode == "offline" and res.sent == 0 and not calls    # NOTHING was sent
    assert len(res.leads) == len(hyps)


def test_existence_oracle_classifies_only_when_attested():
    status_by_path = {"/api/v1/admin/orders/{id}": 403, "/api/v2/orders/{id}": 404,
                      "/api/v1/orders": 200, "/api/v1/orders/{id}/x": 405}
    sender = lambda method, path: status_by_path.get(path, 404)
    eng = SimpleNamespace(attestation="signed", automation_permitted=True, dry_run=False,
                          max_requests_per_min=30)
    hyps = [SimpleNamespace(path=p, reason="h") for p in status_by_path]
    res = probe_existence(hyps, engagement=eng, sender=sender, in_scope=True)
    assert res.mode == "live"
    got = {h.path: h.verdict for h in res.hits}
    assert got.get("/api/v1/admin/orders/{id}") == "protected"   # 403 → exists & guarded
    assert got.get("/api/v1/orders") == "reachable"              # 2xx → exists
    assert got.get("/api/v1/orders/{id}/x") == "exists"          # 405 → exists
    assert "/api/v2/orders/{id}" not in got                      # 404 → absent, dropped
    assert res.hits[0].verdict == "protected"                    # ranked prize-first


def _min_model():
    m = SurfaceModel(base_url="https://t.com", host="t.com")
    _ep(m, "GET", "/api/v1/orders/{id}")
    return m


# ---- L5: coverage-guided capture plan -------------------------------------------

def _plan_model() -> SurfaceModel:
    """`order` exposes GET+PATCH+DELETE (with a server-auth 'role' and ownership 'owner_id'),
    but ONLY GET was captured -> the write families have nothing to reason over. `tag` is a
    read-only resource fully captured -> no gap."""
    m = SurfaceModel(base_url="https://t.com", host="t.com")
    _ep(m, "GET", "/api/order/{id}")
    _ep(m, "PATCH", "/api/order/{id}", params=["role", "owner_id"])
    _ep(m, "DELETE", "/api/order/{id}")
    _ep(m, "GET", "/api/tag/{id}")
    _acc(m, "A", "GET", "/api/order/{id}", "1")      # only the read flow captured
    _acc(m, "A", "GET", "/api/tag/{id}", "9")        # tag fully captured
    return m


def test_capture_plan_prioritises_missing_write_flow():
    steps = plan_capture(_plan_model())
    order = [s for s in steps if s.object_type == "order"]
    assert order, "no capture step for the under-captured 'order' type"
    s = order[0]
    assert "action_bola" in s.unlocks and {"bopla_field", "rebinding"} <= set(s.unlocks)
    assert set(s.methods) == {"PATCH", "DELETE"} and s.est_tests >= 4
    assert not [x for x in steps if x.object_type == "tag"]   # fully captured -> no step


def test_existence_hits_fold_in_as_top_priority():
    hit = ExistenceHit(path="/api/admin/orders/{id}", status=403, verdict="protected")
    steps = plan_capture(_plan_model(), existence_hits=[hit])
    assert any("hidden endpoint" in s.flow and "/api/admin/orders/{id}" in s.flow for s in steps)
    assert steps[0].est_tests >= 15                   # the discovered hidden surface ranks first


def test_plan_is_deterministic():
    a = [(s.object_type, s.flow, s.est_tests) for s in plan_capture(_plan_model())]
    b = [(s.object_type, s.flow, s.est_tests) for s in plan_capture(_plan_model())]
    assert a == b
