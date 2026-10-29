"""
executor.py — the defense-aware, EV-prioritized task runner behind the gated live step.

Given a set of confirmation tasks (each a concrete request + its expected value/EV), it executes
them at the fastest pace the target tolerates: AIMD pacing (pacer.py), a hard global budget,
EV-first ordering, automatic back-off + bounded retry on any defensive block, and a token-refresh
hook when auth expires. It never decides a finding (that is the oracle's job) — it just DELIVERS
the probes efficiently and safely, and hands back responses + a learned defence profile.

`send(request) -> {status, headers, body, latency_ms}` is injected: real HTTP (behind ScopeGuard
+ the engagement) in production, a simulated defended target in tests. Deterministic with an
injected pacer clock. Own accounts only (QL6); scope enforced via `scope_ok`.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .defense import classify, is_block, is_authz_denial, Defense, DefenseProfile
from .pacer import AdaptivePacer


@dataclass
class Task:
    tid: str
    request: dict                 # {method, url, headers, body}
    ev: int = 0
    kind: str = ""
    attempts: int = 0


@dataclass
class ExecResult:
    completed: list = field(default_factory=list)   # [{tid, status, defense, response}]
    denied: list = field(default_factory=list)       # clean authz/authn denials (a boundary)
    blocked: list = field(default_factory=list)      # gave up after retries (defence)
    stats: dict = field(default_factory=dict)
    profile: dict = field(default_factory=dict)


def _retry_after(headers: dict | None) -> float:
    try:
        v = (headers or {}).get("retry-after") or (headers or {}).get("Retry-After")
        return float(v) if v is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def run_tasks(tasks, send, *, pacer: AdaptivePacer | None = None,
              profile: DefenseProfile | None = None, budget: int = 1000,
              max_retries: int = 3, refresh_auth=None, scope_ok=None, on_event=None) -> ExecResult:
    """Execute tasks EV-first under the pacer + budget, adapting to defences. Deterministic
    given a deterministic `send` and pacer clock."""
    pacer = pacer or AdaptivePacer()
    profile = profile or DefenseProfile()
    emit = on_event or (lambda *a, **k: None)
    res = ExecResult()
    queue = sorted(list(tasks), key=lambda t: -t.ev)
    budget = int(budget)
    sends = 0

    while queue and budget > 0:
        t = queue.pop(0)
        if scope_ok is not None and not scope_ok(t.request):
            emit("scope_skip", t.tid, {"url": t.request.get("url")})
            continue
        pacer.before()
        resp = send(t.request) or {}
        budget -= 1
        sends += 1
        t.attempts += 1
        status = int(resp.get("status", 0) or 0)
        headers, body = resp.get("headers") or {}, resp.get("body")
        d, vendor = classify(status, headers, body)
        profile.update(d, vendor=vendor, latency_ms=float(resp.get("latency_ms", 0) or 0),
                       rate_now=pacer.rate, retry_after=_retry_after(headers))

        if is_block(d):
            # A pace block (429/5xx) means slow down globally; a WAF/challenge is a
            # request-specific wall (often permanent) — penalize lightly and give up on
            # THAT task fast instead of tanking throughput for everything else.
            if d in (Defense.RATE_LIMITED, Defense.SERVER_ERROR):
                pacer.on_block(retry_after=_retry_after(headers))
                allowed = max_retries
            else:
                pacer.soft_penalty()
                allowed = 1
            emit("defense_block", t.tid, {"defense": d, "vendor": vendor, "rate": round(pacer.rate, 2)})
            if t.attempts <= allowed:
                queue.append(t)
                queue.sort(key=lambda x: -x.ev)
            else:
                res.blocked.append({"tid": t.tid, "defense": d, "vendor": vendor})
            continue

        if d == Defense.AUTH_EXPIRED:
            emit("auth_expired", t.tid, {})
            if refresh_auth and t.attempts <= max_retries:
                try:
                    refresh_auth(t.request)     # mutate request headers with a fresh token
                except Exception:               # noqa: BLE001
                    pass
                queue.append(t)
                queue.sort(key=lambda x: -x.ev)
            else:
                res.blocked.append({"tid": t.tid, "defense": d})
            continue

        # a real response (2xx / clean 4xx / clean authz denial)
        pacer.on_ok()
        if is_authz_denial(d):
            res.denied.append({"tid": t.tid, "status": status, "defense": d})
        res.completed.append({"tid": t.tid, "status": status, "defense": d, "response": resp,
                              "ev": t.ev, "kind": t.kind})

    res.stats = {"sends": sends, "completed": len(res.completed), "denied": len(res.denied),
                 "blocked": len(res.blocked), "pacer": pacer.snapshot()}
    res.profile = profile.summary()
    return res


def run_tasks_concurrent(tasks, send, *, pacer: AdaptivePacer | None = None,
                         profile: DefenseProfile | None = None, budget: int = 1000,
                         max_retries: int = 3, refresh_auth=None, scope_ok=None,
                         on_event=None, workers: int | None = None) -> ExecResult:
    """Parallel sibling of run_tasks: a worker pool parallelizes request LATENCY (the real
    bottleneck on remote targets) while the pacer — serialized by a lock — keeps the GLOBAL
    rate within the target's tolerance. Pool size defaults to pacer.max_concurrency. Same
    defence handling, budget, EV ordering, auth-refresh and scope guard as the sequential path.
    Thread-safe; terminates cleanly when the queue drains and nothing is in flight."""
    pacer = pacer or AdaptivePacer()
    profile = profile or DefenseProfile()
    emit = on_event or (lambda *a, **k: None)
    res = ExecResult()
    st = {"queue": sorted(list(tasks), key=lambda t: -t.ev), "budget": int(budget),
          "sends": 0, "inflight": 0, "max_inflight": 0}
    lock = threading.Lock()
    pace_lock = threading.Lock()

    def worker():
        while True:
            with lock:
                if st["budget"] <= 0:
                    return
                if st["queue"]:
                    t = st["queue"].pop(0)
                    st["budget"] -= 1
                    st["inflight"] += 1
                    st["max_inflight"] = max(st["max_inflight"], st["inflight"])
                elif st["inflight"] == 0:
                    return                      # nothing queued, nothing in flight → done
                else:
                    t = None                    # wait for an in-flight task to maybe requeue
            if t is None:
                time.sleep(0.001)
                continue
            if scope_ok is not None and not scope_ok(t.request):
                emit("scope_skip", t.tid, {})
                with lock:
                    st["inflight"] -= 1
                continue
            try:
                with pace_lock:
                    pacer.before()
                with lock:
                    st["sends"] += 1
                resp = send(t.request) or {}
                t.attempts += 1
                status = int(resp.get("status", 0) or 0)
                headers, body = resp.get("headers") or {}, resp.get("body")
                d, vendor = classify(status, headers, body)
                with lock:
                    profile.update(d, vendor=vendor, latency_ms=float(resp.get("latency_ms", 0) or 0),
                                   rate_now=pacer.rate, retry_after=_retry_after(headers))
                if is_block(d):
                    if d in (Defense.RATE_LIMITED, Defense.SERVER_ERROR):
                        with pace_lock:
                            pacer.on_block(retry_after=_retry_after(headers))
                        allowed = max_retries
                    else:
                        with pace_lock:
                            pacer.soft_penalty()
                        allowed = 1
                    emit("defense_block", t.tid, {"defense": d, "vendor": vendor})
                    if t.attempts <= allowed:
                        with lock:
                            st["queue"].append(t); st["queue"].sort(key=lambda x: -x.ev)
                    else:
                        with lock:
                            res.blocked.append({"tid": t.tid, "defense": d, "vendor": vendor})
                    continue
                if d == Defense.AUTH_EXPIRED:
                    emit("auth_expired", t.tid, {})
                    if refresh_auth and t.attempts <= max_retries:
                        try:
                            refresh_auth(t.request)
                        except Exception:       # noqa: BLE001
                            pass
                        with lock:
                            st["queue"].append(t); st["queue"].sort(key=lambda x: -x.ev)
                    else:
                        with lock:
                            res.blocked.append({"tid": t.tid, "defense": d})
                    continue
                with pace_lock:
                    pacer.on_ok()
                with lock:
                    if is_authz_denial(d):
                        res.denied.append({"tid": t.tid, "status": status, "defense": d})
                    res.completed.append({"tid": t.tid, "status": status, "defense": d,
                                          "response": resp, "ev": t.ev, "kind": t.kind})
            finally:
                with lock:
                    st["inflight"] -= 1

    n = max(1, int(workers or pacer.max_concurrency))
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=30)
    res.stats = {"sends": st["sends"], "completed": len(res.completed), "denied": len(res.denied),
                 "blocked": len(res.blocked), "max_inflight": st["max_inflight"],
                 "pacer": pacer.snapshot()}
    res.profile = profile.summary()
    return res
