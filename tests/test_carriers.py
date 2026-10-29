"""Object-id carriers — path, query, header, JWT, GraphQL var, body."""
import base64
import json

from iolite.carriers import object_ids, decode_jwt_claims, primary_and_all
from iolite.har_ingest import ingest_har
from iolite.scope_guard import ScopeConfig, ScopeGuard
from iolite.surface_model import cross_principal_candidates
from iolite.models import Effect, SurfaceModel


def _jwt(payload: dict) -> str:
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{b({'alg':'none'})}.{b(payload)}."


def test_path_and_query_ids():
    cs = object_ids("GET", "/api/orders/1001", {"expand": "items"})
    assert any(c.carrier == "path" and c.value == "1001" for c in cs)
    cs2 = object_ids("GET", "/api/search", {"userId": "501"})
    assert any(c.carrier == "query" and c.value == "501" for c in cs2)


def test_identity_header_and_jwt():
    cs = object_ids("GET", "/api/me", {}, {"X-Customer-Id": "42",
                                           "Authorization": "Bearer " + _jwt({"sub": "777"})})
    assert any(c.carrier == "header" and c.value == "42" for c in cs)
    assert any(c.carrier == "jwt" and c.value == "777" for c in cs)


def test_jwt_decode_only_identity_claims():
    claims = decode_jwt_claims("Bearer " + _jwt({"sub": "9", "role": "admin", "name": "x"}))
    assert claims == {"sub": "9"}          # non-identity claims dropped


def test_graphql_var_and_body_ids():
    cs = object_ids("POST", "/graphql", {}, {}, {"variables": {"id": 55}, "query": "..."})
    assert any(c.carrier == "gql-var" and c.value == "55" for c in cs)
    cs2 = object_ids("POST", "/api/refund", {}, {}, {"orderId": 88, "amount": 5})
    assert any(c.carrier == "body" and c.value == "88" for c in cs2)
    assert not any(c.value == "5" for c in cs2)   # 'amount' is not an id name


def test_primary_prefers_path():
    cs = object_ids("GET", "/api/orders/1001", {"userId": "501"})
    primary, allids = primary_and_all(cs)
    assert primary == "1001" and "501" in allids


# --- pipeline: query-keyed IDOR must produce a cross-principal probe --------- #
def _har(pid_id):
    return {"log": {"entries": [
        {"request": {"method": "GET", "url": f"https://q.test/api/search?userId={pid_id}",
                     "headers": [{"name": "Authorization", "value": f"Bearer T{pid_id}"}]},
         "response": {"status": 200, "content": {"text": "{}"}}}]}}


def test_query_keyed_idor_becomes_probe():
    guard = ScopeGuard(ScopeConfig(allowed_hosts=["q.test"], automation_permitted=True))
    ra = ingest_har(_har("501"), "A", guard, pid="A")
    rb = ingest_har(_har("502"), "B", guard, pid="B")
    m = SurfaceModel()
    for r in (ra, rb):
        m.principals.append(r.principal)
        for ep in r.endpoints:
            m.add_endpoint(ep)
        for acc in r.accesses:
            m.add_access(acc)
    # endpoint has no path id, but the query id makes it OBJECT_ACCESS
    assert m.endpoints["GET /api/search"].effect == Effect.OBJECT_ACCESS
    cands = cross_principal_candidates(m)
    # B must be asked to reproduce A's request carrying userId=501
    b_probe = [c for c in cands if "B" in c.probe_pids and c.object_id == "501"]
    assert b_probe and b_probe[0].query.get("userId") == "501"
