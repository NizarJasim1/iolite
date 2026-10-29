"""
Tests for Point 2 — deep surface recovery: client-derived GraphQL (introspection-
independent), request-config endpoints, privileged routes, runtime self-disclosure,
and that deep acquisition is additive (deep=False is byte-identical).
"""

import os
import tempfile

from iolite.gql_client import extract_graphql_operations
from iolite.surface_ast import extract_config_endpoints, privileged_routes, deep_recover
from iolite.surface_runtime import ingest_runtime
from iolite.models import Effect
from iolite.pipeline import Inputs, run
from iolite.roe import Engagement

_JS = """
const GET_ORDER = gql`query GetOrder($id: ID!) { order(id: $id) { id status total } }`;
const REFUND = gql`mutation Refund($id: ID!) { refund(id: $id) { id } }`;
api.request({ url: '/api/admin/users', method: 'POST' });
const routes = [{ path: '/admin/billing' }, { path: '/dashboard' }];
"""

_PERSISTED = '{"7f3a":"query Me { me { id email } }","9b1c":"mutation Pay($id:ID!){ pay(id:$id){ id } }"}'


def test_graphql_client_ops_without_introspection():
    eps = {e.key: e for e in extract_graphql_operations(_JS, "app.js")}
    assert "QUERY order" in eps
    assert "MUTATION refund" in eps
    assert eps["QUERY order"].effect == Effect.OBJECT_ACCESS      # id arg → BOLA surface
    assert eps["MUTATION refund"].effect == Effect.PAYMENT        # refund → value effect
    assert "id" in eps["QUERY order"].params


def test_persisted_query_map():
    eps = {e.key: e for e in extract_graphql_operations(_PERSISTED, "pq.json")}
    assert "QUERY me" in eps
    assert "MUTATION pay" in eps


def test_request_config_endpoints_and_method():
    eps = {e.key: e for e in extract_config_endpoints(_JS, "app.js")}
    assert "POST /api/admin/users" in eps                         # url+method separate keys
    assert eps["POST /api/admin/users"].effect == Effect.AUTHORITY
    assert "admin-path" in eps["POST /api/admin/users"].role_hints


def test_privileged_routes():
    routes = privileged_routes(_JS)
    assert "/admin/billing" in routes
    assert "/dashboard" not in routes                            # not privileged → excluded


def test_runtime_self_disclosure_ingest():
    log = {"calls": [
        {"method": "POST", "url": "https://h/api/orders/123/refund", "status": 200,
         "principal": "A"},
        {"method": "GET", "url": "https://h/api/orders/123", "status": 200, "principal": "A"},
        {"method": "POST", "url": "https://h/gql",
         "gql": "mutation Pay($id:ID!){ pay(id:$id){ id } }"},
    ]}
    eps, accs = ingest_runtime(log, "runtime")
    keys = {e.key for e in eps}
    assert "POST /api/orders/{id}/refund" in keys
    assert "MUTATION pay" in keys                                # gql record recovered
    assert any(a.object_id == "123" and a.principal_id == "A" for a in accs)
    # highest evidence tier — the client actually sent it
    assert any(p.tier.value == "T1_LIVE" for e in eps for p in e.provenance)


def test_deep_recover_merges():
    eps = {e.key for e in deep_recover([(_JS, "app.js")])}
    assert "POST /api/admin/users" in eps
    assert "QUERY order" in eps and "MUTATION refund" in eps


def test_pipeline_deep_is_additive():
    """deep=False must not change the surface; deep=True must add ≥1 endpoint."""
    eng = Engagement.template()
    with tempfile.TemporaryDirectory() as d:
        js = os.path.join(d, "app.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_JS)
        inp = Inputs(js_files=[js])
        base = run(eng, inp, deep=False)
        deep = run(eng, inp, deep=True)
    assert len(deep.model.endpoints) >= len(base.model.endpoints)
    assert "QUERY order" in deep.model.endpoints           # client GraphQL now present
    assert "QUERY order" not in base.model.endpoints        # ... and absent without deep
