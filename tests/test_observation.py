"""
observation — deep extraction of one exchange: enforcement class, JWT claims (identity),
server-stated owner/tenant/state, embedded objects (enumeration), typed fields.
"""
import base64
import json

from iolite.intent.observation import observe, decode_jwt_claims, _status_class


def _jwt(claims):
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return "hdr." + b(claims) + ".sig"


def test_status_class_mapping():
    assert _status_class(200) == "ALLOW"
    assert _status_class(401) == "AUTHN_DENY"
    assert _status_class(403) == "AUTHZ_DENY"
    assert _status_class(404) == "MASKED"
    assert _status_class(429) == "RATE"


def test_decode_jwt_claims_payload_only():
    c = decode_jwt_claims("Bearer " + _jwt({"sub": "u1", "role": "admin", "tenant": "T9"}))
    assert c.get("sub") == "u1" and c.get("role") == "admin" and c.get("tenant") == "T9"


def test_decode_non_jwt_is_empty():
    assert decode_jwt_claims("Bearer opaque-token") == {}
    assert decode_jwt_claims("") == {}


def test_observe_extracts_identity_and_owner():
    o = observe("bob", "GET", "https://api.t.com/api/vault/1001",
                req_headers={"authorization": "Bearer " + _jwt({"sub": "u_bob", "role": "user", "tenant": "T1"})},
                status=200, resp_body={"id": "1001", "owner_id": "u_alice", "secret": "tok_abc123x"})
    assert o.object_id == "1001" and o.object_type == "vault"
    assert o.owner_ref == "u_alice"          # server-stated owner
    assert o.sub == "u_bob" and o.role == "user" and o.tenant == "T1"
    assert o.enforce == "ALLOW" and o.got_value is True
    assert "tok_abc123x" in o.disc_values


def test_observe_enforcement_denial_no_value():
    o = observe("carol", "GET", "https://api.t.com/api/vault/1001", status=403,
                resp_body={"error": "forbidden"})
    assert o.enforce == "AUTHZ_DENY" and o.got_value is False


def test_observe_embedded_collection_ids():
    o = observe("bob", "GET", "https://api.t.com/api/vault",
                resp_body=[{"id": "1001", "owner_id": "u_alice"},
                           {"id": "1002", "owner_id": "u_alice"}])
    ids = {e["id"] for e in o.embedded}
    assert {"1001", "1002"} <= ids
    assert all(e["owner"] == "u_alice" for e in o.embedded)
