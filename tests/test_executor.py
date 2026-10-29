"""
executor — defense-aware, EV-prioritized task execution against a SIMULATED hardened target
(rate ceiling + Cloudflare WAF path + token expiry). Deterministic via a virtual clock.
"""
import time

from iolite.intent.pacer import AdaptivePacer
from iolite.intent.executor import run_tasks, run_tasks_concurrent, Task
from iolite.intent.defense import DefenseProfile


class VClock:
    def __init__(self): self.t = 0.0
    def now(self): return self.t
    def sleep(self, s): self.t += max(0.0, s)


def _target(ceiling=5.0, expire_after=0):
    """A defended API: >ceiling req/s → 429; /blocked → Cloudflare WAF 403; if expire_after>0 the
    token expires after that many OKs (until refreshed to Bearer t1)."""
    st = {"last": -999.0, "ok": 0}
    def send(req):
        now = _target.vc.now()
        gap = now - st["last"]; st["last"] = now
        if gap < 1.0 / ceiling - 1e-9:
            return {"status": 429, "headers": {"retry-after": "1"}, "body": "slow", "latency_ms": 5}
        if "/blocked" in req["url"]:
            return {"status": 403, "headers": {"cf-ray": "x", "server": "cloudflare"},
                    "body": "Attention Required", "latency_ms": 5}
        if expire_after and req.get("headers", {}).get("authorization") == "Bearer t0" and st["ok"] >= expire_after:
            return {"status": 401, "headers": {}, "body": {"error": "jwt expired"}, "latency_ms": 5}
        st["ok"] += 1
        return {"status": 200, "headers": {}, "body": {"id": "x", "secret": "tok_abcd1"}, "latency_ms": 10}
    return send


def _run(tasks, **kw):
    vc = VClock(); _target.vc = vc
    pacer = AdaptivePacer(rate=12.0, clock=vc.now, sleep=vc.sleep)
    prof = DefenseProfile(host="api.t.com")
    send = kw.pop("send", _target())
    return run_tasks(tasks, send, pacer=pacer, profile=prof, **kw), pacer, prof, vc


def _tasks(n=15):
    return [Task(f"t{i}", {"method": "GET", "url": f"https://api.t.com/v/{i}",
                           "headers": {"authorization": "Bearer t0"}}, ev=100 - i) for i in range(n)]


def test_completes_all_legit_tasks_under_rate_ceiling():
    res, pacer, prof, vc = _run(_tasks(15), budget=200)
    assert res.stats["completed"] >= 15
    assert pacer.rate < 12.0                       # learned to slow below the start rate
    assert prof.summary()["rate_limited"] >= 1     # hit and absorbed the limit


def test_waf_path_is_parked_not_hammered():
    tasks = _tasks(5) + [Task("waf", {"method": "GET", "url": "https://api.t.com/blocked",
                                      "headers": {"authorization": "Bearer t0"}}, ev=200)]
    res, pacer, prof, vc = _run(tasks, budget=200, max_retries=5)
    assert any(b["tid"] == "waf" for b in res.blocked)      # gave up on the walled path
    assert prof.summary()["waf_blocks"] >= 1 and prof.summary()["vendor"] == "cloudflare"


def test_auth_refresh_recovers_expiry():
    refreshed = {"n": 0}
    def refresh(req):
        refreshed["n"] += 1
        req["headers"]["authorization"] = "Bearer t1"
    res, pacer, prof, vc = _run(_tasks(12), budget=300, refresh_auth=refresh,
                                send=_target(expire_after=6))
    assert refreshed["n"] >= 1 and res.stats["completed"] >= 12


def test_budget_is_respected():
    res, pacer, prof, vc = _run(_tasks(50), budget=10)
    assert res.stats["sends"] <= 10


def test_ev_priority_high_first():
    seen = []
    def send(req):
        seen.append(req["url"]); return {"status": 200, "headers": {}, "body": {"id": "x"}, "latency_ms": 1}
    tasks = [Task("lo", {"method": "GET", "url": "https://api.t.com/lo"}, ev=1),
             Task("hi", {"method": "GET", "url": "https://api.t.com/hi"}, ev=99)]
    _run(tasks, budget=10, send=send)
    assert seen[0].endswith("/hi")                 # highest EV executed first


def test_scope_guard_blocks_out_of_scope():
    sent = []
    def send(req):
        sent.append(req["url"]); return {"status": 200, "headers": {}, "body": {"id": "x"}}
    tasks = [Task("in", {"method": "GET", "url": "https://api.t.com/x"}, ev=5),
             Task("out", {"method": "GET", "url": "https://evil.com/x"}, ev=9)]
    _run(tasks, budget=10, send=send, scope_ok=lambda r: "api.t.com" in r["url"])
    assert all("evil.com" not in u for u in sent)


# --- parallel executor (real threads; latency-bound) ---------------------------

def test_concurrent_completes_all_and_parallelizes():
    def send(req):
        time.sleep(0.01)                     # 10ms remote latency
        return {"status": 200, "headers": {}, "body": {"id": "x", "secret": "tok_abcd1"}}
    tasks = [Task(f"t{i}", {"method": "GET", "url": f"https://api.t.com/v/{i}"}, ev=100 - i)
             for i in range(24)]
    pacer = AdaptivePacer(rate=500.0, max_rate=1000.0, max_concurrency=6)
    res = run_tasks_concurrent(tasks, send, pacer=pacer, profile=DefenseProfile(),
                               budget=100, workers=6)
    assert res.stats["completed"] == 24
    assert res.stats["max_inflight"] >= 3    # genuine parallelism


def test_concurrent_respects_budget():
    def send(req):
        return {"status": 200, "headers": {}, "body": {"id": "x"}}
    tasks = [Task(f"t{i}", {"method": "GET", "url": f"https://api.t.com/v/{i}"}, ev=1)
             for i in range(50)]
    res = run_tasks_concurrent(tasks, send, pacer=AdaptivePacer(rate=1000.0, max_rate=1000.0),
                               profile=DefenseProfile(), budget=12, workers=4)
    assert res.stats["sends"] <= 12
