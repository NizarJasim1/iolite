"""
har_capture — ingest REAL multi-account HARs WITH responses (the plumbing that revives
offline corroboration on real data). Self-contained: writes HARs to a temp dir.
"""
import json
import os
import tempfile

from iolite.intent.har_capture import exchanges_from_dir, exchanges_from_har, principals_in
from iolite.intent.corroborate import corroborate
from iolite.intent.schema_learn import learn_schema

_ALICE = {"log": {"entries": [
    {"request": {"method": "POST", "url": "https://api.t.com/api/vault",
                 "postData": {"text": "{\"title\":\"x\"}"}},
     "response": {"status": 201, "content": {"text": "{\"id\":\"1001\",\"secret\":\"tok_7h3Qe9x1\"}"}}},
    {"request": {"method": "GET", "url": "https://api.t.com/api/vault/1001"},
     "response": {"status": 200, "content": {"text": "{\"id\":\"1001\",\"secret\":\"tok_7h3Qe9x1\"}"}}},
]}}
_BOB = {"log": {"entries": [
    {"request": {"method": "POST", "url": "https://api.t.com/api/vault",
                 "postData": {"text": "{\"title\":\"y\"}"}},
     "response": {"status": 201, "content": {"text": "{\"id\":\"2002\",\"secret\":\"tok_Zk1p2Lq8\"}"}}},
    # bob's capture contains alice's object 1001 with alice's secret
    {"request": {"method": "GET", "url": "https://api.t.com/api/vault/1001"},
     "response": {"status": 200, "content": {"text": "{\"id\":\"1001\",\"secret\":\"tok_7h3Qe9x1\"}"}}},
    # out-of-scope traffic that MUST be dropped
    {"request": {"method": "GET", "url": "https://evil.other.com/api/vault/9"},
     "response": {"status": 200, "content": {"text": "{\"id\":\"9\",\"secret\":\"tok_other\"}"}}},
]}}


def _dir():
    d = tempfile.mkdtemp(prefix="iolite_caps_")
    with open(os.path.join(d, "acct_alice.har"), "w") as fh:
        json.dump(_ALICE, fh)
    with open(os.path.join(d, "acct_bob.har"), "w") as fh:
        json.dump(_BOB, fh)
    return d


def test_parses_responses_and_principals():
    ex = exchanges_from_dir(_dir(), scope_hosts={"api.t.com"})
    assert set(principals_in(ex)) == {"alice", "bob"}
    assert any(e.response_fields.get("secret") == "tok_7h3Qe9x1" for e in ex)


def test_owned_inference_create_vs_access():
    ex = exchanges_from_dir(_dir(), scope_hosts={"api.t.com"})
    # alice created 1001 (owns); bob accessed 1001 (does not own)
    alice_1001 = [e for e in ex if e.principal == "alice" and e.object_id == "1001"]
    bob_1001 = [e for e in ex if e.principal == "bob" and e.object_id == "1001"]
    assert any(e.owned for e in alice_1001)
    assert bob_1001 and all(not e.owned for e in bob_1001)


def test_scope_filtering_drops_out_of_scope():
    ex = exchanges_from_dir(_dir(), scope_hosts={"api.t.com"})
    assert all("evil.other.com" not in e.endpoint_key for e in ex)
    assert all(e.object_id != "9" for e in ex)   # out-of-scope object never ingested


def test_offline_corroboration_on_real_hars():
    ex = exchanges_from_dir(_dir(), scope_hosts={"api.t.com"})
    found = corroborate(ex, learn_schema(ex))
    assert any(f.family == "read_bola" and f.object_id == "1001" and f.attacker == "bob"
               for f in found)


def test_base64_encoded_response_body():
    import base64
    body = base64.b64encode(b'{"id":"77","secret":"tok_b64value1"}').decode()
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://api.t.com/api/x/77"},
         "response": {"status": 200, "content": {"encoding": "base64", "text": body}}}]}}
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "p_carol.har"), "w") as fh:
        json.dump(har, fh)
    ex = exchanges_from_har(os.path.join(d, "p_carol.har"), "carol", scope_hosts={"api.t.com"})
    assert ex and ex[0].response_fields.get("secret") == "tok_b64value1"
