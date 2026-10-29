"""
The relational authorization lattice (iolite.intent.relation_model) — built from a
REAL SurfaceModel, asserting the derivation is correct on every dimension that a
per-endpoint access class cannot express: ownership, action-lift, field (BOPLA),
ownership-field rebinding, lifecycle state exclusion, and tenant isolation.
"""
from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.intent.relation_model import (Action, Decision, build_lattice,
                                          summarize, _classify_field)


def _prov():
    return Provenance.of(SourceKind.HAR, "t.har")


def _model():
    m = SurfaceModel(base_url="https://t", host="t")
    m.principals = [Principal("A", "a"), Principal("B", "b"), Principal("AD", "admin")]

    def acc(pid, method, path, oid, effect=Effect.OBJECT_ACCESS, body=None,
            safe_read=True, roles=None, params=None):
        tmpl = path.replace(oid, "{id}") if oid else path
        m.add_endpoint(Endpoint(method=method, path=tmpl, effect=effect,
                                role_hints=roles or [], params=params or [],
                                provenance=[_prov()], observed_ids=[oid] if oid else []))
        m.add_access(ObservedAccess(principal_id=pid, endpoint_key=f"{method} {tmpl}",
                                    object_id=oid, path=path, method=method,
                                    provenance=_prov(), body=body, all_ids=[oid] if oid else [],
                                    safe_read=safe_read))
    acc("A", "GET", "/api/vault/1001", "1001")
    acc("A", "PATCH", "/api/vault/1001", "1001", effect=Effect.OWNERSHIP,
        body={"title": "x"}, safe_read=False)
    acc("B", "GET", "/api/vault/2002", "2002")
    acc("A", "PATCH", "/api/account/5005", "5005", effect=Effect.OWNERSHIP,
        body={"role": "member"}, safe_read=False, params=["role"])
    acc("A", "POST", "/api/transfer", "", effect=Effect.PAYMENT,
        body={"owner_id": "A", "amount": 5}, safe_read=False, params=["owner_id"])
    acc("A", "GET", "/api/report/7007", "7007", body={"tenant_id": "T1"}, params=["tenant_id"])
    acc("B", "GET", "/api/report/7008", "7008", body={"tenant_id": "T2"}, params=["tenant_id"])
    acc("A", "PATCH", "/api/invoice/9001", "9001", effect=Effect.OWNERSHIP,
        body={"status": "archived"}, safe_read=False)
    return m


def test_field_classification():
    assert _classify_field("role") == "server_auth"
    assert _classify_field("price") == "server_auth"
    assert _classify_field("is_admin") == "server_auth"
    assert _classify_field("owner_id") == "ownership"
    assert _classify_field("account_id") == "ownership"
    assert _classify_field("title") == "plain"


def test_lattice_holders_and_fields():
    lat = build_lattice(_model())
    assert lat.objects["1001"].holders == {"A"}
    assert lat.objects["2002"].holders == {"B"}
    s = summarize(lat)
    assert "account.role" in s["server_authoritative_fields"]
    assert "transfer.owner_id" in s["ownership_fields"]
    assert any("archived" in e for e in s["excluded_state_objects"])


def test_owner_scoped_read_deny_and_allow():
    lat = build_lattice(_model())
    dec, why = lat.intended_decision("B", Action.READ,
                                     endpoint_key="GET /api/vault/{id}", oid="1001")
    assert dec == Decision.DENY and "owner-scoped" in why
    dec2, _ = lat.intended_decision("A", Action.READ,
                                    endpoint_key="GET /api/vault/{id}", oid="1001")
    assert dec2 == Decision.ALLOW


def test_action_lift_write_ge_read():
    """A write by a non-owner is denied even where the read class was weak: write>=read."""
    lat = build_lattice(_model())
    dec, why = lat.intended_decision("B", Action.WRITE,
                                     endpoint_key="PATCH /api/vault/{id}", oid="1001")
    assert dec == Decision.DENY


def test_bopla_owner_cannot_set_server_field():
    lat = build_lattice(_model())
    dec, why = lat.intended_decision("A", Action.WRITE,
                                     endpoint_key="PATCH /api/account/{id}", oid="5005",
                                     field_name="role")
    assert dec == Decision.DENY and "server-authoritative" in why


def test_rebinding_ownership_field_to_other():
    lat = build_lattice(_model())
    dec, why = lat.intended_decision("A", Action.CREATE,
                                     endpoint_key="POST /api/transfer", oid="",
                                     field_name="owner_id", field_value="B")
    assert dec == Decision.DENY and "rebinding" in why.lower()


def test_state_exclusion_blocks_mutation():
    lat = build_lattice(_model())
    dec, why = lat.intended_decision("A", Action.WRITE,
                                     endpoint_key="PATCH /api/invoice/{id}", oid="9001",
                                     state="archived")
    assert dec == Decision.DENY and "state-exclusion" in why


def test_tenant_isolation_cross_tenant_deny():
    lat = build_lattice(_model())
    # B (tenant T2) reaching A's report 7007 (tenant T1) -> cross-tenant deny
    dec, why = lat.intended_decision("B", Action.READ,
                                     endpoint_key="GET /api/report/{id}", oid="7007")
    assert dec == Decision.DENY and "tenant" in why.lower()


def test_raise_only_safety_unknown_is_lead_not_allow():
    """No intent signal -> UNKNOWN (a lead), never a silent ALLOW that hides a bug."""
    lat = build_lattice(_model())
    dec, _ = lat.intended_decision("B", Action.READ,
                                   endpoint_key="GET /api/unknownthing", oid="")
    assert dec in (Decision.UNKNOWN, Decision.DENY)
