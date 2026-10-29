"""
policy_learn — learn the authorization policy by CONTRAST from deep observations:
precise ownership (owner_id↔sub), enforced-boundary learning, violation, enumeration leak.
"""
import base64
import json

from iolite.intent.observation import observe
from iolite.intent.policy_learn import PolicyLearner


def _jwt(claims):
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return "h." + b(claims) + ".s"


def _obs(principal, sub, method, url, status=200, body=None):
    return observe(principal, method, url, status=status,
                   req_headers={"authorization": "Bearer " + _jwt({"sub": sub, "role": "user", "tenant": "T1"})},
                   resp_body=body)


def _kinds(sigs):
    return [s.kind for s in sigs]


def test_precise_ownership_from_owner_id_sub():
    pl = PolicyLearner()
    pl.update(_obs("alice", "u_alice", "POST", "https://api.t.com/api/vault", 201,
                   {"id": "1", "owner_id": "u_alice", "secret": "tok_aaa111x"}))
    assert pl.obj_owner.get("1") == "alice"   # owner read from owner_id == alice's sub


def test_violation_detected_precisely():
    pl = PolicyLearner()
    pl.update(_obs("alice", "u_alice", "POST", "https://api.t.com/api/vault", 201,
                   {"id": "1", "owner_id": "u_alice", "secret": "tok_aaa111x"}))
    sigs = pl.update(_obs("bob", "u_bob", "GET", "https://api.t.com/api/vault/1", 200,
                          {"id": "1", "owner_id": "u_alice", "secret": "tok_aaa111x"}))
    assert "corroborated" in _kinds(sigs)
    assert pl.violations and pl.violations[0]["owner"] == "alice"


def test_boundary_learned_from_contrast():
    pl = PolicyLearner()
    pl.update(_obs("alice", "u_alice", "GET", "https://api.t.com/api/doc/9", 200,
                   {"id": "9", "owner_id": "u_alice", "secret": "tok_doc999z"}))
    sigs = pl.update(_obs("carol", "u_carol", "GET", "https://api.t.com/api/doc/9", 403,
                          {"error": "forbidden"}))
    kinds = _kinds(sigs)
    assert "enforcement_denial" in kinds and "boundary_learned" in kinds
    assert pl.types["doc"].enforced is True
    assert pl.types["doc"].intent == "owner_scoped"


def test_enumeration_leak_signal():
    pl = PolicyLearner()
    pl.update(_obs("alice", "u_alice", "GET", "https://api.t.com/api/vault/1", 200,
                   {"id": "1", "owner_id": "u_alice", "secret": "tok_aaa111x"}))
    sigs = pl.update(_obs("bob", "u_bob", "GET", "https://api.t.com/api/vault", 200,
                          [{"id": "1", "owner_id": "u_alice"}, {"id": "2", "owner_id": "u_alice"}]))
    assert "enumeration_leak" in _kinds(sigs)


def test_no_violation_when_owner_reads_own():
    pl = PolicyLearner()
    pl.update(_obs("alice", "u_alice", "POST", "https://api.t.com/api/vault", 201,
                   {"id": "1", "owner_id": "u_alice", "secret": "tok_aaa111x"}))
    sigs = pl.update(_obs("alice", "u_alice", "GET", "https://api.t.com/api/vault/1", 200,
                          {"id": "1", "owner_id": "u_alice", "secret": "tok_aaa111x"}))
    assert "corroborated" not in _kinds(sigs)
    assert pl.types["vault"].owner_allow >= 1


def test_summary_reports_learned_policy():
    pl = PolicyLearner()
    pl.update(_obs("alice", "u_alice", "GET", "https://api.t.com/api/doc/9", 200,
                   {"id": "9", "owner_id": "u_alice", "secret": "tok_doc999z"}))
    pl.update(_obs("carol", "u_carol", "GET", "https://api.t.com/api/doc/9", 403, {"error": "x"}))
    s = pl.summary()
    assert s["object_types"]["doc"]["intent"] == "owner_scoped"
    assert s["object_types"]["doc"]["enforced"] is True
    assert s["principals"]["alice"]["sub"] == "u_alice"
