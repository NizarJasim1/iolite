"""
The enforcement / identity boundary (one seam):
  L4 — acquire the FEDERATION/identity surface (authz-server endpoints, provider, protocol,
       identity claims) from legal evidence; emit propose-only identity-authz leads.
  G6 — model the target's authz ARCHITECTURE (topology + pattern + identity) and rank the
       PRESSURE POINTS, incl. the sharp one: test the service path UNDER a gateway.

Oracle note (AMP): both are passive analysers; the decisive checks are could-fail
(provider/protocol inferred from a REAL decoded JWT; the gateway-bypass point present with a
gateway and ABSENT without — a zero-FP floor). Self-authored inputs => E2; the green gate is
the external no-regression half; a live `.well-known` fetch is an ROE-gated lead, not done here.
"""
import base64
import json

from iolite.models import (Effect, Endpoint, ObservedAccess, Provenance, SourceKind, SurfaceModel)
from iolite.intent.federation import mine_federation
from iolite.intent.architecture import model_architecture, summarize


def _prov(loc=""):
    return Provenance.of(SourceKind.HAR, loc or "test.har")


def _jwt(payload: dict) -> str:
    h = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.sig"


def _ep(m, method, path, **kw):
    m.add_endpoint(Endpoint(method=method, path=path, effect=kw.get("effect", Effect.NONE),
                            role_hints=kw.get("roles", []), params=kw.get("params", []),
                            provenance=[_prov()]))


def _fed_model() -> SurfaceModel:
    m = SurfaceModel(base_url="https://app.target.com", host="app.target.com")
    for p in ("/oauth2/authorize", "/oauth2/token", "/.well-known/openid-configuration",
              "/.well-known/jwks.json", "/userinfo", "/api/orders/{id}"):
        _ep(m, "GET", p)
    return m


_ISS = "https://login.microsoftonline.com/abc123/v2.0"


# ---- L4: federation surface -----------------------------------------------------

def test_federation_surface_mined_from_real_evidence():
    m = _fed_model()
    auth = [f"Bearer {_jwt({'iss': _ISS, 'aud': 'clientA', 'sub': 'u1', 'tid': 'T1', 'email': 'a@x'})}",
            f"Bearer {_jwt({'iss': _ISS, 'aud': 'clientB', 'sub': 'u1', 'tid': 'T2'})}"]
    fs = mine_federation(m, authorizations=auth)
    assert {"authorize", "token", "discovery", "jwks", "userinfo"} <= set(fs.endpoints)
    assert fs.provider == "Azure AD"                       # inferred from the JWT issuer
    assert fs.protocol == "OIDC"
    assert {"aud", "sub", "tid", "iss"} <= set(fs.identity_claims)
    # propose-only identity leads, from observed facts
    joined = " ".join(fs.hypotheses).lower()
    assert "audience" in joined                            # two distinct client audiences
    assert "cross-tenant" in joined or "across tenants" in joined   # same sub, two tenants
    assert fs.leads                                        # ROE-gated endpoints to fetch next


def test_federation_honest_floor_without_identity_surface():
    m = SurfaceModel(base_url="https://app.target.com", host="app.target.com")
    _ep(m, "GET", "/api/orders/{id}")
    _ep(m, "POST", "/api/orders")
    fs = mine_federation(m)
    assert not fs.present and fs.provider == "" and not fs.endpoints


# ---- G6: architecture model + pressure points -----------------------------------

def _gw_model() -> SurfaceModel:
    m = SurfaceModel(base_url="https://app.target.com", host="app.target.com")
    _ep(m, "POST", "/graphql")
    _ep(m, "GET", "/api/orders/{id}")
    return m


def test_gateway_bypass_pressure_point_present():
    am = model_architecture(_gw_model())
    assert am.topology == "graphql-gateway-over-rest"
    cs = [p for p in am.pressure_points if p["onyx_effect"] == "CROSS_SURFACE"
          and "/api/orders/{id}" in p["surface"]]
    assert cs and "non-gateway" in cs[0]["why"], "the service-layer bypass point is missing"


def test_no_gateway_point_without_a_gateway():
    """Zero-FP floor: a plain direct-service surface gets NO gateway-bypass pressure point."""
    m = SurfaceModel(base_url="https://app.target.com", host="app.target.com")
    _ep(m, "GET", "/api/orders/{id}")
    am = model_architecture(m)
    assert am.topology == "direct-service"
    assert not any(p["onyx_effect"] == "CROSS_SURFACE" and "non-gateway" in p["why"]
                   for p in am.pressure_points)


def test_authz_pattern_rebac_from_fields():
    m = SurfaceModel(base_url="https://app.target.com", host="app.target.com")
    _ep(m, "GET", "/api/order/{id}", params=["tenant_id", "owner_id"])
    m.add_access(ObservedAccess(
        principal_id="X", endpoint_key="GET /api/order/{id}", object_id="5",
        path="/api/order/5", method="GET", provenance=_prov(), carrier="path",
        body={"tenant_id": "T1", "owner_id": "X"}, all_ids=["5"], safe_read=True))
    am = model_architecture(m)
    assert am.authz_pattern.startswith("ReBAC")


def test_identity_folds_into_architecture():
    m = _fed_model()
    fs = mine_federation(m, authorizations=[f"Bearer {_jwt({'iss': _ISS, 'aud': 'c', 'sub': 'u'})}"])
    am = model_architecture(_gw_model(), federation=fs)
    assert am.provider == "Azure AD" and am.protocol == "OIDC"
    assert any(p["onyx_effect"] == "AUTHORITY_GRANT" for p in am.pressure_points)
    assert summarize(am)["identity"]["provider"] == "Azure AD"
