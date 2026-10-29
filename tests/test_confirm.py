"""
confirm — the defense-aware live replay confirmer: leads → cross-principal GET replays →
value-presence decision. A finding requires the attacker to reproduce the holder's private
value on a CLEAN 2xx; clean-403 is a (correct) non-finding; a WAF block is parked, never a finding.
"""
from types import SimpleNamespace as NS

from iolite.intent.confirm import confirm_leads, build_probe_tasks


def _lead(oid, fam="read_bola", attacker="bob", holder="alice"):
    return NS(family=fam, method="GET", path=f"/api/vault/{oid}", object_id=oid,
              attacker=attacker, holder=holder, endpoint_key="GET /api/vault/{id}", payout=1500)


_AUTH = {"bob": {"authorization": "Bearer bob"}}
_HOLDER = {"1001": {"tok_secret_x1a"}, "2002": {"tok_secret_y2b"}, "3003": {"tok_secret_z3c"}}


def _send(req):
    u = req["url"]
    if "1001" in u:   # vulnerable: leaks alice's secret to bob
        return {"status": 200, "headers": {}, "body": {"id": "1001", "secret": "tok_secret_x1a"}}
    if "2002" in u:   # properly protected: clean 403
        return {"status": 403, "headers": {"content-type": "application/json"}, "body": {"error": "forbidden"}}
    if "3003" in u:   # behind a WAF
        return {"status": 403, "headers": {"cf-ray": "x", "server": "cloudflare"}, "body": "Attention Required"}
    return {"status": 404, "headers": {}, "body": {}}


def test_only_vulnerable_object_is_confirmed():
    leads = [_lead("1001"), _lead("2002"), _lead("3003")]
    findings, res = confirm_leads(leads, _send, _AUTH, _HOLDER, base_url="https://api.t.com",
                                  concurrent=False, budget=50)
    assert len(findings) == 1 and findings[0].object_id == "1001"
    assert res.stats["denied"] >= 1          # the clean 403 is a (correct) non-finding
    assert res.stats["blocked"] >= 1         # the WAF path is parked


def test_waf_block_is_never_a_finding():
    findings, res = confirm_leads([_lead("3003")], _send, _AUTH, _HOLDER,
                                  base_url="https://api.t.com", concurrent=True, budget=20)
    assert findings == []


def test_value_presence_required_no_value_no_finding():
    # target returns 200 but WITHOUT the holder's secret -> not a finding
    def send(req):
        return {"status": 200, "headers": {}, "body": {"id": "1001", "public": "hello"}}
    findings, res = confirm_leads([_lead("1001")], send, _AUTH, _HOLDER,
                                  base_url="https://api.t.com", concurrent=False, budget=20)
    assert findings == []


def test_only_read_get_families_are_probed():
    leads = [NS(family="action_bola", method="DELETE", path="/api/vault/9", object_id="9",
                attacker="bob", holder="alice", endpoint_key="DELETE /api/vault/{id}", payout=3000)]
    tasks = build_probe_tasks(leads, _AUTH, _HOLDER, base_url="https://api.t.com")
    assert tasks == []                        # writes are NOT replayed here (Wall-7 territory)


def test_scope_guard_blocks_out_of_scope_probe():
    sent = []
    def send(req):
        sent.append(req["url"]); return {"status": 200, "headers": {}, "body": {"secret": "tok_secret_x1a"}}
    leads = [_lead("1001")]
    confirm_leads(leads, send, _AUTH, _HOLDER, base_url="https://evil.com", concurrent=False,
                  budget=20, scope_ok=lambda r: "api.t.com" in r["url"])
    assert all("evil.com" not in u for u in sent)
