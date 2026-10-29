"""
live_session.py — scan WHILE you browse, with a DEEP response reader feeding a precise,
contrast-learning intent builder.

v1.18 flattened responses and only caught "both accounts got it". v1.19 feeds every call
through `observation.observe` (deep: nested objects, collections, enforcement status, JWT
claims, server-stated owner/parent/tenant/state) into `policy_learn.PolicyLearner`, which
LEARNS the access-control function by CONTRAST (owner allowed vs non-owner denied) and reads
ownership from the stated `owner_id`↔`sub` link rather than guessing. The result:

  * instant, precise confirmations (BOLA / cross-tenant), pinned to the real owner;
  * the intent model gets STRONGER per event — it announces a boundary only once it has seen
    it enforced (owner allowed AND non-owner denied), with a confidence that grows;
  * new live signals the old system couldn't produce: `boundary_learned`,
    `enforcement_denial` (teaches intent), `enumeration_leak` (chained precursor).

Hot path stays O(fields). `snapshot()` still runs the full Wall-5/6 pipeline for the dossier.
Passive, scoped, own-accounts-only. The tool crafts nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .capture import CapturedExchange, _scalars
from .corroborate import CorroboratedFinding
from .har_capture import _host_path, _response_ids
from .observation import observe
from .policy_learn import PolicyLearner
from .defense import DefenseProfile, Defense

_MUTATING = ("POST", "PUT", "PATCH", "DELETE")
_SELF = {"me", "self", "current", "mine", "profile"}

_DEF_SEV = {Defense.RATE_LIMITED: "info", Defense.WAF_BLOCK: "medium",
            Defense.CHALLENGE: "medium", Defense.AUTH_EXPIRED: "info"}


def _defense_event(obs):
    """A live event when the target's defences respond — so the operator sees the WAF/rate
    wall as it happens, and the pacer is seeded for the gated step."""
    if obs.defense not in _DEF_SEV:
        return None
    titles = {
        Defense.RATE_LIMITED: "rate limited (429) — executor will back off and ride the ceiling",
        Defense.WAF_BLOCK: f"WAF/bot block ({obs.waf_vendor or 'edge'}) on {obs.endpoint_key}",
        Defense.CHALLENGE: f"bot/JS challenge ({obs.waf_vendor or 'edge'}) encountered",
        Defense.AUTH_EXPIRED: "auth token expired — re-auth needed (not an authz boundary)",
    }
    return LiveEvent("defense", _DEF_SEV[obs.defense], titles[obs.defense], obs.url_path,
                     {"defense": obs.defense, "vendor": obs.waf_vendor})


@dataclass
class LiveEvent:
    kind: str                 # corroborated | boundary_learned | enforcement_denial |
                              # enumeration_leak | dropped | info
    severity: str
    title: str
    detail: str = ""
    data: dict = field(default_factory=dict)


class LiveSession:
    def __init__(self, scope_hosts=None, engagement=None):
        self.scope = set(scope_hosts or [])
        self.engagement = engagement
        self.exchanges: list = []
        self.n = 0
        self.learner = PolicyLearner()
        self.defense_profile = DefenseProfile()     # learned target defences (seeds the executor's pacer)
        self.corroborated: list = []        # CorroboratedFinding (mirrors learner.violations)
        self._created: dict = {}
        self._seen_violations = 0
        self.event_log: list = []           # bounded feed for the live dashboard
        self._evseq = 0

    # ------------------------------------------------------------------ ingest
    def ingest_raw(self, principal: str, method: str, url: str, *, req_body=None,
                   status: int = 200, resp_body=None, req_headers=None,
                   resp_headers=None, claims=None) -> list:
        host, _ = _host_path(url)
        if self.scope and host not in self.scope:
            return [LiveEvent("dropped", "info", f"out-of-scope {host} ignored")]

        obs = observe(principal, method, url, req_headers=req_headers, req_body=req_body,
                      status=status, resp_headers=resp_headers, resp_body=resp_body,
                      seq=self.n, claims=claims)
        # keep a CapturedExchange for snapshot/corroborate/divergence compatibility
        self.exchanges.append(self._as_exchange(obs, req_body, resp_body))
        self.n += 1
        if obs.host:
            self.defense_profile.host = self.defense_profile.host or obs.host
        self.defense_profile.update(obs.defense, vendor=obs.waf_vendor, latency_ms=obs.latency_ms)

        events: list = []
        dev = _defense_event(obs)
        if dev:
            events.append(dev)
        for s in self.learner.update(obs):
            events.append(LiveEvent(s.kind, s.severity, s.title, s.detail, s.data))
        # mirror new violations into self.corroborated (as CorroboratedFinding)
        while self._seen_violations < len(self.learner.violations):
            v = self.learner.violations[self._seen_violations]
            self._seen_violations += 1
            self.corroborated.append(CorroboratedFinding(
                family=v["family"], object_id=v["object_id"], owner=v["owner"],
                attacker=v["attacker"], endpoint_key=v["endpoint_key"],
                evidence=v["evidence"], severity=v["severity"], cert=v["cert"]))
        # feed the live dashboard (bounded)
        for e in events:
            self.event_log.append({"seq": self._evseq, "kind": e.kind, "severity": e.severity,
                                   "title": e.title, "detail": e.detail})
            self._evseq += 1
        if len(self.event_log) > 800:
            self.event_log = self.event_log[-800:]
        return events

    def _as_exchange(self, obs, req_body, resp_body) -> CapturedExchange:
        owned = False
        if obs.object_id:
            if obs.owner_ref and obs.sub and obs.owner_ref == obs.sub:
                owned = True
            elif obs.method in _MUTATING and 200 <= obs.status < 300:
                owned = True
                self._created.setdefault(obs.principal, set()).add(obs.object_id)
            elif obs.object_id in self._created.get(obs.principal, set()):
                owned = True
            elif any(seg.lower() in _SELF for seg in obs.url_path.split("/")):
                owned = True
        return CapturedExchange(
            principal=obs.principal, endpoint_key=obs.endpoint_key, method=obs.method,
            object_id=obs.object_id, owned=owned,
            request_fields=_scalars(req_body if isinstance(req_body, dict) else {}),
            response_fields=_scalars(resp_body if isinstance(resp_body, dict) else {}),
            response_ids=_response_ids(resp_body), status=obs.status,
            tenant=obs.tenant_ref or obs.tenant, seq=obs.seq)

    # --------------------------------------------------------------- reporting
    def status(self) -> dict:
        return {"exchanges": self.n,
                "principals": sorted({e.principal for e in self.exchanges}),
                "objects": len(self.learner.obj_type),
                "corroborated": len(self.learner.violations),
                "learned_types": len(self.learner.types),
                "defense": self.defense_profile.summary(),
                "scope": sorted(self.scope)}

    def policy(self) -> dict:
        """The LEARNED authorization policy so far (intent per type + confidence + evidence)."""
        return self.learner.summary()

    def events_since(self, seq: int) -> list:
        return [e for e in self.event_log if e["seq"] >= seq]

    def graph(self) -> dict:
        """A compact relation graph for the dashboard: principals (with identity), objects (typed,
        with owner/tenant/state), and the confirmed cross-account exposures as edges."""
        lr = self.learner
        principals = []
        owns = {}
        for _oid, owner in lr.obj_owner.items():
            owns[owner] = owns.get(owner, 0) + 1
        pids = set(lr.principal_sub) | set(lr.principal_role) | set(lr.principal_tenant) | set(owns)
        for p in sorted(pids):
            principals.append({"pid": p, "role": lr.principal_role.get(p, ""),
                               "tenant": lr.principal_tenant.get(p, ""),
                               "sub": lr.principal_sub.get(p, ""), "owns": owns.get(p, 0)})
        objects = [{"id": oid, "type": lr.obj_type.get(oid, ""), "owner": lr.obj_owner.get(oid, ""),
                    "tenant": lr.obj_tenant.get(oid, ""), "state": lr.obj_state.get(oid, "")}
                   for oid in sorted(lr.obj_type)][:300]
        confirmations = [{"object": v["object_id"], "attacker": v["attacker"],
                          "owner": v["owner"], "family": v["family"], "severity": v["severity"]}
                         for v in lr.violations]
        return {"principals": principals, "objects": objects, "confirmations": confirmations}

    def snapshot(self, *, budget: int = 300):
        """Full Wall-5/6 methodology on everything seen so far (heavier; call on demand)."""
        from .schema_learn import learn_schema
        from .corroborate import corroborate
        from .hunt import model_from_exchanges, HuntReport
        from . import kill_chain as _kc
        ex = self.exchanges
        schema = learn_schema(ex)
        rep = HuntReport(principals=sorted({e.principal for e in ex}), exchanges=len(ex),
                         scope_hosts=sorted(self.scope))
        rep.schema = {"server_auth_fields": sorted(schema.server_auth_fields),
                      "ownership_fields": sorted(schema.ownership_fields),
                      "state_fields": sorted(schema.state_fields),
                      "terminal_states": sorted(schema.terminal_states)}
        seen = {(f.family, f.object_id, f.attacker) for f in self.corroborated}
        rep.corroborated = list(self.corroborated)
        for f in corroborate(ex, schema):
            k = (f.family, f.object_id, f.attacker)
            if k not in seen:
                seen.add(k)
                rep.corroborated.append(f)
        host = next((h for h in self.scope), "")
        model = model_from_exchanges(ex, base_url=(f"https://{host}" if host else ""), host=host)
        kc = _kc.run(model, budget=budget, exchanges=ex, schema=schema)
        rep.leads = kc.leads
        rep.by_family = kc.by_family
        rep.learned_policy = self.learner.summary()      # the contrast-learned intent
        return rep
