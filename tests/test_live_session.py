"""
live_session — scan WHILE browsing. Incremental hot path must confirm a cross-account
BOLA the instant it appears, drop out-of-scope, dedup, and still produce a full snapshot.
"""
from iolite.intent.live_session import LiveSession


def _seed(s):
    s.ingest_raw("alice", "POST", "https://api.t.com/api/vault", status=201,
                 resp_body={"id": "1001", "secret": "tok_7h3Qe9x1"})
    s.ingest_raw("alice", "GET", "https://api.t.com/api/vault/1001",
                 resp_body={"id": "1001", "secret": "tok_7h3Qe9x1"})


def test_instant_bola_on_cross_account_read():
    s = LiveSession(scope_hosts={"api.t.com"})
    _seed(s)
    ev = s.ingest_raw("bob", "GET", "https://api.t.com/api/vault/1001",
                      resp_body={"id": "1001", "secret": "tok_7h3Qe9x1"})
    kinds = [e.kind for e in ev]
    assert "corroborated" in kinds
    assert s.status()["corroborated"] == 1


def test_no_event_for_owner_reading_own_object():
    s = LiveSession(scope_hosts={"api.t.com"})
    _seed(s)
    ev = s.ingest_raw("alice", "GET", "https://api.t.com/api/vault/1001",
                      resp_body={"id": "1001", "secret": "tok_7h3Qe9x1"})
    assert all(e.kind != "corroborated" for e in ev)


def test_out_of_scope_dropped():
    s = LiveSession(scope_hosts={"api.t.com"})
    ev = s.ingest_raw("bob", "GET", "https://evil.com/x/9", resp_body={"secret": "zzz"})
    assert ev and ev[0].kind == "dropped"
    assert s.status()["exchanges"] == 0


def test_dedup_same_finding_once():
    s = LiveSession(scope_hosts={"api.t.com"})
    _seed(s)
    s.ingest_raw("bob", "GET", "https://api.t.com/api/vault/1001", resp_body={"id": "1001", "secret": "tok_7h3Qe9x1"})
    s.ingest_raw("bob", "GET", "https://api.t.com/api/vault/1001", resp_body={"id": "1001", "secret": "tok_7h3Qe9x1"})
    assert s.status()["corroborated"] == 1


def test_shared_default_value_not_confirmed():
    s = LiveSession(scope_hosts={"api.t.com"})
    # 'standard' is shared across many objects -> not a discriminator
    s.ingest_raw("alice", "POST", "https://api.t.com/api/item", status=201, resp_body={"id": "1", "type": "standard"})
    s.ingest_raw("alice", "GET", "https://api.t.com/api/item/2", resp_body={"id": "2", "type": "standard"})
    s.ingest_raw("alice", "GET", "https://api.t.com/api/item/3", resp_body={"id": "3", "type": "standard"})
    ev = s.ingest_raw("bob", "GET", "https://api.t.com/api/item/1", resp_body={"id": "1", "type": "standard"})
    assert all(e.kind != "corroborated" for e in ev)


def test_live_tenant_crossing():
    s = LiveSession(scope_hosts={"api.t.com"})
    s.ingest_raw("alice", "POST", "https://api.t.com/api/report", status=201,
                 resp_body={"id": "7", "secret": "tok_rep_aaaa1"}, req_body={"tenant_id": "T1"})
    s.ingest_raw("alice", "GET", "https://api.t.com/api/report/7",
                 resp_body={"id": "7", "tenant_id": "T1"})
    ev = s.ingest_raw("bob", "GET", "https://api.t.com/api/report/7",
                      resp_body={"id": "7", "tenant_id": "T2"})
    assert any(e.kind == "corroborated" and e.data.get("family") == "tenant" for e in ev)


def test_snapshot_builds_full_report():
    s = LiveSession(scope_hosts={"api.t.com"})
    _seed(s)
    s.ingest_raw("bob", "GET", "https://api.t.com/api/vault/1001", resp_body={"id": "1001", "secret": "tok_7h3Qe9x1"})
    rep = s.snapshot()
    assert rep.exchanges == 3
    assert any(f.family == "read_bola" for f in rep.corroborated)


# --- v1.19: deep signals (identity, contrast boundary, enumeration) via ingest ---

import base64 as _b64
import json as _json


def _hdr(sub):
    p = _b64.urlsafe_b64encode(_json.dumps({"sub": sub, "role": "user", "tenant": "T1"}).encode()).decode().rstrip("=")
    return {"authorization": "Bearer h." + p + ".s"}


def test_boundary_learned_and_precise_violation():
    s = LiveSession(scope_hosts={"api.t.com"})
    s.ingest_raw("alice", "POST", "https://api.t.com/api/vault", status=201, req_headers=_hdr("u_alice"),
                 resp_body={"id": "1001", "owner_id": "u_alice", "secret": "tok_x1y2z3q"})
    s.ingest_raw("alice", "GET", "https://api.t.com/api/vault/1001", req_headers=_hdr("u_alice"),
                 resp_body={"id": "1001", "owner_id": "u_alice", "secret": "tok_x1y2z3q"})
    ev_bob = s.ingest_raw("bob", "GET", "https://api.t.com/api/vault/1001", req_headers=_hdr("u_bob"),
                          resp_body={"id": "1001", "owner_id": "u_alice", "secret": "tok_x1y2z3q"})
    assert any(e.kind == "corroborated" for e in ev_bob)
    ev_carol = s.ingest_raw("carol", "GET", "https://api.t.com/api/vault/1001", status=403,
                            req_headers=_hdr("u_carol"), resp_body={"error": "forbidden"})
    kinds = [e.kind for e in ev_carol]
    assert "enforcement_denial" in kinds and "boundary_learned" in kinds
    pol = s.policy()["object_types"]["vault"]
    assert pol["intent"] == "owner_scoped" and pol["enforced"] is True


def test_enumeration_leak_live():
    s = LiveSession(scope_hosts={"api.t.com"})
    s.ingest_raw("alice", "GET", "https://api.t.com/api/doc/1", req_headers=_hdr("u_alice"),
                 resp_body={"id": "1", "owner_id": "u_alice", "secret": "tok_aaa111z"})
    ev = s.ingest_raw("bob", "GET", "https://api.t.com/api/doc", req_headers=_hdr("u_bob"),
                      resp_body=[{"id": "1", "owner_id": "u_alice"}, {"id": "2", "owner_id": "u_alice"}])
    assert any(e.kind == "enumeration_leak" for e in ev)
