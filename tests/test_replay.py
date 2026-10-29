"""Replay planner — fair budget, horizontal + vertical families, GraphQL reads."""
from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite import triage, replay
from iolite.surface_model import privilege_scores, vertical_candidates


def _model():
    m = SurfaceModel()
    m.principals = [Principal("A", "A", auth={"authorization": "x"}),
                    Principal("B", "B", auth={"authorization": "y"})]

    def ep(method, path, effect, roles=None):
        m.add_endpoint(Endpoint(method=method, path=path, effect=effect,
                                role_hints=roles or [],
                                provenance=[Provenance.of(SourceKind.HAR, path)],
                                observed_ids=["1"]))

    def acc(pid, method, cpath, oid, key, body=None):
        m.add_access(ObservedAccess(principal_id=pid, endpoint_key=key, object_id=oid,
                                    path=cpath, method=method,
                                    provenance=Provenance.of(SourceKind.HAR, cpath),
                                    all_ids=[oid], safe_read=True, body=body))

    ep("GET", "/api/orders/{id}", Effect.OBJECT_ACCESS)
    ep("GET", "/api/vehicles/{id}/location", Effect.OBJECT_ACCESS)
    ep("GET", "/api/admin/reports/{id}", Effect.OBJECT_ACCESS, roles=["admin-path"])
    ep("POST", "/graphql", Effect.OBJECT_ACCESS)

    # A holds 50 orders (the HOT endpoint), 1 vehicle, 1 admin report, 1 gql object
    for i in range(1, 51):
        acc("A", "GET", f"/api/orders/{i}", str(i), "GET /api/orders/{id}")
    acc("A", "GET", "/api/vehicles/9/location", "9", "GET /api/vehicles/{id}/location")
    acc("A", "GET", "/api/admin/reports/1", "1", "GET /api/admin/reports/{id}")
    acc("A", "POST", "/graphql", "7", "POST /graphql", body={"query": "query{u(id:7){e}}"})
    triage.rank(m)
    return m


def test_privilege_scores():
    m = _model()
    priv = privilege_scores(m)
    assert priv["A"] > priv["B"]         # A reached the admin endpoint, B did not


def test_vertical_probe_generated():
    m = _model()
    v = vertical_candidates(m)
    admin = [c for c in v if c.endpoint_key == "GET /api/admin/reports/{id}"]
    assert admin and admin[0].probe_pids == ["B"]   # low-priv B probes admin read


def test_graphql_read_probe():
    m = _model()
    plan = replay.build_plan(m, max_probes=500)
    gql = [p for p in plan.probe if p["path"] == "/graphql" and p["method"] == "POST"]
    assert gql and gql[0]["principal"] == "B"


def test_fair_budget_no_starvation():
    m = _model()
    plan = replay.build_plan(m, max_probes=6)
    assert len(plan.probe) <= 6
    # despite 50 order candidates, the rare vehicle + admin + graphql are represented
    covered = {p["path"] for p in plan.probe}
    assert any(x.startswith("/api/vehicles") for x in covered), covered
    assert any(x.startswith("/api/admin") for x in covered), covered
    assert "/graphql" in covered, covered


def test_budget_respected_and_deterministic():
    m = _model()
    a = replay.build_plan(m, max_probes=10).probe
    b = replay.build_plan(m, max_probes=10).probe
    assert len(a) == 10
    assert [ (p["principal"], p["path"], p.get("_object_id")) for p in a ] == \
           [ (p["principal"], p["path"], p.get("_object_id")) for p in b ]


def test_high_risk_first():
    m = _model()
    plan = replay.build_plan(m, max_probes=2)
    # admin endpoint is highest risk (admin hint + object access) → represented first
    assert any("/api/admin" in p["path"] for p in plan.probe)
