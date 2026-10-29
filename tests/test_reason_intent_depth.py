"""
Tests for the deep intent reconstruction: field-name/self/tenant/JWT signals, the
TENANT_ISOLATED class, raw-leakage mining (OpenAPI security, GraphQL @auth, HAR
ownership errors), and the webhook-origin assumption.
"""

import json
import os
import tempfile

from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.reason import reason, infer_intent, mine_leakage, jwt_role_based
from iolite.reason.intent import AccessClass, RANK
from iolite.reason.signals import endpoint_signals


def _prov():
    return Provenance.of(SourceKind.HAR, "cap")


def test_self_scoped_is_owner_high():
    ep = Endpoint(method="GET", path="/api/me/profile", effect=Effect.OBJECT_ACCESS,
                  provenance=[_prov()])
    m = SurfaceModel(host="h"); m.add_endpoint(ep)
    r = infer_intent(m)[ep.key]
    assert r.access_class == AccessClass.OWNER_ONLY and r.confidence == "high"


def test_tenant_field_is_tenant_isolated():
    ep = Endpoint(method="GET", path="/api/reports/{id}", effect=Effect.FIELD_PROJECTION,
                  params=["tenant_id", "id"], provenance=[_prov()])
    m = SurfaceModel(host="h"); m.add_endpoint(ep)
    r = infer_intent(m)[ep.key]
    assert r.access_class == AccessClass.TENANT_ISOLATED
    assert RANK[AccessClass.TENANT_ISOLATED] > RANK[AccessClass.OWNER_ONLY]


def test_role_field_is_privileged():
    ep = Endpoint(method="PATCH", path="/api/users/{id}", effect=Effect.OBJECT_ACCESS,
                  params=["id", "is_admin"], provenance=[_prov()])
    m = SurfaceModel(host="h"); m.add_endpoint(ep)
    r = infer_intent(m)[ep.key]
    assert r.access_class == AccessClass.ADMIN_ONLY


def test_owner_field_raises_confidence():
    ep = Endpoint(method="GET", path="/api/docs/{id}", effect=Effect.OBJECT_ACCESS,
                  params=["id", "owner_id"], provenance=[_prov()])
    sig = endpoint_signals(ep)
    assert sig.field_owner
    m = SurfaceModel(host="h"); m.add_endpoint(ep)
    assert infer_intent(m)[ep.key].confidence == "high"


def test_jwt_role_based_detection():
    # a JWT whose payload carries a "role" claim  (header.payload.sig, base64url)
    import base64
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1", "role": "user"}).encode()).decode().rstrip("=")
    tok = "eyJhbGciOiJIUzI1NiJ9." + payload + ".sig"
    p = Principal(pid="A", label="A", auth={"Authorization": f"Bearer {tok}"})
    assert jwt_role_based([p]) is True


def test_rank_ordering_still_holds():
    assert RANK[AccessClass.ADMIN_ONLY] > RANK[AccessClass.ROLE_RESTRICTED]
    assert RANK[AccessClass.ROLE_RESTRICTED] > RANK[AccessClass.TENANT_ISOLATED]
    assert RANK[AccessClass.OWNER_ONLY] > RANK[AccessClass.AUTHENTICATED]


def test_leakage_openapi_security_raises_intent():
    m = SurfaceModel(host="h")
    m.add_endpoint(Endpoint(method="GET", path="/api/admin/stats",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    spec = {"paths": {"/api/admin/stats": {"get": {"security": [{"oauth": ["admin"]}]}}}}
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "openapi.json")
        json.dump(spec, open(p, "w"))
        lk = mine_leakage(m, openapi_path=p)
    assert lk.get("GET /api/admin/stats") == AccessClass.ADMIN_ONLY


def test_leakage_har_ownership_error_raises_intent():
    m = SurfaceModel(host="h")
    har = {"log": {"entries": [{
        "request": {"method": "GET", "url": "https://h/api/orders/9"},
        "response": {"status": 403, "content": {"text": "Forbidden: you are not the owner"}}}]}}
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.har")
        json.dump(har, open(p, "w"))
        lk = mine_leakage(m, har_paths=[p])
    assert any(v == AccessClass.OWNER_ONLY for v in lk.values())


def test_leakage_merges_into_reason_when_more_restrictive():
    m = SurfaceModel(host="h")
    ep = Endpoint(method="GET", path="/api/things", effect=Effect.FIELD_PROJECTION,
                  provenance=[_prov()])
    m.add_endpoint(ep)

    class _Inputs:
        openapi_file = ""
        graphql_file = ""
        har_files: list = []
    inp = _Inputs()
    # inject a HAR that marks /api/things admin-guarded
    with tempfile.TemporaryDirectory() as d:
        har = {"log": {"entries": [{
            "request": {"method": "GET", "url": "https://h/api/things"},
            "response": {"status": 403, "content": {"text": "admin only"}}}]}}
        p = os.path.join(d, "c.har")
        json.dump(har, open(p, "w"))
        inp.har_files = [p]
        rep = reason(m, inp)
    assert rep.intent["GET /api/things"].access_class == AccessClass.ADMIN_ONLY
    assert rep.counts["leakage_hints"] >= 1


def test_webhook_assumption_fires():
    m = SurfaceModel(base_url="https://h", host="h")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"h"}
    m.add_endpoint(Endpoint(method="GET", path="/api/webhooks/{id}",
                            effect=Effect.FIELD_PROJECTION, provenance=[_prov()], observed_ids=["7"]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/webhooks/{id}",
                 object_id="7", path="/api/webhooks/7", method="GET", provenance=_prov(),
                 carrier="path", all_ids=["7"], safe_read=True))
    rep = reason(m)
    assert rep.by_family().get("assumption_webhook", 0) >= 1


def test_assumption_catalog_now_seven():
    from iolite.reason.assumptions import catalog_status
    assert len(catalog_status()) == 7
