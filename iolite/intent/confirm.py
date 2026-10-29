"""
confirm.py — the defense-aware LIVE confirmer: turn EV-ranked leads into safe cross-principal
replay probes, execute them at top speed through the adaptive executor, and DECIDE each by
value-presence (the metamorphic oracle), never by a status code.

This wires the deep layer end to end: GENERATE (divergence) → SCHEDULE (EV) → EXECUTE (pacer +
parallel + defence-aware, executor.py) → DISPOSE (value-presence). It confirms the READ-side
families by safe replay (read_bola / chained / tenant): replay the holder's own request as the
attacker principal and check whether the attacker's response reproduces the holder's
object-specific private value. A finding requires value presence on a non-defensive (clean)
response — a 403/429/WAF is never a finding.

Write/field/state families are NOT replayed here (that needs the reversible intervention saga,
Wall-7) — confirm only issues reads. Own accounts only (QL6); scope enforced; nothing is
confirmed from a defensive block.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .corroborate import _looks_discriminating
from .defense import Defense
from .executor import Task, run_tasks, run_tasks_concurrent
from .pacer import AdaptivePacer
from .defense import DefenseProfile

_READ_FAMILIES = ("read_bola", "chained", "tenant")


@dataclass
class ConfirmFinding:
    family: str
    object_id: str
    attacker: str
    holder: str
    endpoint_key: str
    evidence: str
    severity: str = "high"
    cert: dict = field(default_factory=dict)


def _disc_values(body) -> set:
    out = set()
    def rec(v, d=0):
        if d > 6:
            return
        if isinstance(v, dict):
            for x in v.values():
                rec(x, d + 1)
        elif isinstance(v, list):
            for x in v[:200]:
                rec(x, d + 1)
        elif _looks_discriminating(v):
            out.add(str(v))
    rec(body)
    return out


def build_probe_tasks(leads, principal_auth: dict, holder_values: dict, *, base_url: str = "") -> list:
    """Make one safe GET replay Task per READ-side lead: the ATTACKER principal re-issues the
    holder's request. `principal_auth[pid]` is that principal's auth headers (the operator's own
    accounts). `holder_values[oid]` is the discriminating value(s) the holder legitimately saw —
    the proof target. Only read-side families, GET only."""
    tasks = []
    for i, lead in enumerate(leads):
        if getattr(lead, "family", "") not in _READ_FAMILIES:
            continue
        if str(getattr(lead, "method", "GET")).upper() != "GET":
            continue
        auth = principal_auth.get(getattr(lead, "attacker", ""))
        if auth is None:
            continue
        path = getattr(lead, "path", "")
        url = (base_url.rstrip("/") + path) if base_url and path.startswith("/") else (path or url_of(lead))
        expect = set(holder_values.get(str(getattr(lead, "object_id", "")), set()))
        req = {"method": "GET", "url": url, "headers": dict(auth), "body": None}
        t = Task(tid=f"L{i}:{getattr(lead,'family','')}:{getattr(lead,'object_id','')}",
                 request=req, ev=int(getattr(lead, "payout", 0)), kind=getattr(lead, "family", ""))
        t.request["_expect"] = expect
        t.request["_lead"] = {"family": lead.family, "object_id": str(lead.object_id),
                              "attacker": lead.attacker, "holder": getattr(lead, "holder", ""),
                              "endpoint_key": lead.endpoint_key}
        tasks.append(t)
    return tasks


def url_of(lead) -> str:
    return getattr(lead, "path", "") or ""


def confirm_leads(leads, send, principal_auth: dict, holder_values: dict, *, base_url: str = "",
                  pacer: AdaptivePacer | None = None, profile: DefenseProfile | None = None,
                  budget: int = 500, concurrent: bool = True, scope_ok=None,
                  on_event=None) -> tuple[list, object]:
    """Execute the read-side confirmation probes and decide by value presence. Returns
    (findings, exec_result)."""
    tasks = build_probe_tasks(leads, principal_auth, holder_values, base_url=base_url)
    pacer = pacer or AdaptivePacer(rate=(profile.safe_rate if profile else 3.0))
    profile = profile or DefenseProfile()
    runner = run_tasks_concurrent if concurrent else run_tasks
    res = runner(tasks, send, pacer=pacer, profile=profile, budget=budget,
                 scope_ok=scope_ok, on_event=on_event)
    findings = []
    seen = set()
    for c in res.completed:
        if c["defense"] != Defense.OK:          # a finding only on a clean 2xx response
            continue
        # recover the task's expectation + lead
        resp = c.get("response") or {}
        tid = c["tid"]
        expect, lead = _lookup(tasks, tid)
        if not expect:
            continue
        got = _disc_values(resp.get("body"))
        hit = sorted(got & expect)
        if hit:
            key = (lead["family"], lead["object_id"], lead["attacker"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(ConfirmFinding(
                family=lead["family"], object_id=lead["object_id"], attacker=lead["attacker"],
                holder=lead["holder"], endpoint_key=lead["endpoint_key"],
                evidence=f"{lead['attacker']} reproduced {lead['holder'] or 'the owner'}'s private "
                         f"value(s) {hit[:2]} for {lead['object_id']} on a clean 2xx response",
                severity=("critical" if lead["family"] == "tenant" else "high"),
                cert={"proof": "live replay as a non-owner reproduced the owner's object-specific "
                               "private value on a clean (non-defensive) response — value-presence Δstate",
                      "object": lead["object_id"], "replayable": True, "write_safe": True,
                      "defense_checked": True}))
    return findings, res


def _lookup(tasks, tid):
    for t in tasks:
        if t.tid == tid:
            return t.request.get("_expect", set()), t.request.get("_lead", {})
    return set(), {}


# --------------------------------------------------------------------------- #
# a real, scope-guarded HTTP sender (production). Tests inject a simulated send #
# --------------------------------------------------------------------------- #

def http_sender(scope_hosts, *, allow_write: bool = False, timeout: int = 8):
    """Build send(request)->{status,headers,body,latency_ms} over urllib, enforcing scope and
    (by default) refusing non-GET. Reads only — the safe confirmation surface."""
    import json as _json
    import time as _time
    import urllib.request
    import urllib.error
    hosts = set(scope_hosts or [])

    def _host(url):
        return url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].lower()

    def send(req):
        method = str(req.get("method", "GET")).upper()
        url = req.get("url", "")
        if hosts and _host(url) not in hosts:
            return {"status": -2, "headers": {}, "body": "out-of-scope (refused)"}
        if method != "GET" and not allow_write:
            return {"status": -3, "headers": {}, "body": "write refused (read-only confirm)"}
        data = _json.dumps(req["body"]).encode() if req.get("body") is not None else None
        r = urllib.request.Request(url, data=data, method=method)
        for k, v in (req.get("headers") or {}).items():
            r.add_header(k, v)
        t0 = _time.monotonic()
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return _finish(resp.status, hdrs, body, t0, _time)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
            return _finish(e.code, hdrs, body, t0, _time)
        except Exception as e:      # noqa: BLE001
            return {"status": -1, "headers": {}, "body": str(e),
                    "latency_ms": (_time.monotonic() - t0) * 1000}

    def _finish(status, hdrs, body, t0, _time):
        try:
            parsed = _json.loads(body)
        except Exception:
            parsed = body
        return {"status": status, "headers": hdrs, "body": parsed,
                "latency_ms": (_time.monotonic() - t0) * 1000}

    return send
