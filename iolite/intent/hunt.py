"""
hunt.py — the practical, end-to-end driver for an AUTHORIZED bug-bounty target.

This is the field entry point the self-audit said was missing: it takes a folder of real
multi-account HAR captures (one per account) and runs the whole deep layer on REAL data,
not the demo:

  captures/ (alice.har, bob.har, …)
    → exchanges (request + response)                [har_capture]
    → learn the schema (language-agnostic)          [schema_learn]
    → CORROBORATE offline — proven bugs, 0 requests  [corroborate]
    → build the surface model + relational lattice   [relation_model]
    → GENERATE wide divergence leads (EV-ranked)     [divergence]
    → (optional, gated) LIVE intervention confirm     [engine.run_target behind preflight]
    → submittable dossier                             [dossier]

Safety is load-bearing and unchanged: the offline path sends NOTHING. The live path runs
ONLY when an Engagement is attested (roe.py), is scope-guarded and rate-governed, uses the
operator's own accounts, and is reads-only unless the operator explicitly allows reversible
writes. Out-of-scope hosts are dropped at ingestion. Own captures only (QL6).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Effect, Endpoint, ObservedAccess, Principal, Provenance, SourceKind, SurfaceModel
from . import kill_chain as _kc
from .har_capture import exchanges_from_dir, principals_in
from .schema_learn import learn_schema
from .corroborate import corroborate


def _effect_for(method: str, has_id: bool, path: str) -> Effect:
    pl = path.lower()
    if "/admin" in pl or "/internal" in pl or "/staff" in pl:
        return Effect.AUTHORITY
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return Effect.OWNERSHIP if has_id else Effect.NONE
    return Effect.OBJECT_ACCESS if has_id else Effect.NONE


def model_from_exchanges(exchanges, base_url: str = "", host: str = "") -> SurfaceModel:
    """Build a real SurfaceModel from captured exchanges (so the generator runs on real
    data). Deterministic. Reads become ObservedAccess; writes register endpoints+methods."""
    m = SurfaceModel(base_url=base_url, host=host)
    seen_p = {}
    for pid in principals_in(exchanges):
        seen_p[pid] = Principal(pid=pid, label=pid)
    m.principals = [seen_p[k] for k in sorted(seen_p)]
    prov = Provenance.of(SourceKind.HAR, "hunt")
    for e in exchanges:
        method, _, path_t = e.endpoint_key.partition(" ")
        has_id = "{id}" in path_t or bool(e.object_id)
        ep = Endpoint(method=method, path=path_t, effect=_effect_for(method, has_id, path_t),
                      provenance=[prov], observed_ids=[e.object_id] if e.object_id else [],
                      params=sorted(set(e.request_fields) | set(e.response_fields)),
                      role_hints=["admin"] if ("/admin" in path_t.lower() or "/internal" in path_t.lower()) else [])
        m.add_endpoint(ep)
        safe = (method == "GET")
        if e.object_id:
            m.add_access(ObservedAccess(
                principal_id=e.principal, endpoint_key=e.endpoint_key, object_id=e.object_id,
                path=path_t.replace("{id}", e.object_id), method=method, provenance=prov,
                body=e.request_fields or None, all_ids=[e.object_id], safe_read=safe))
    return m


@dataclass
class HuntReport:
    principals: list = field(default_factory=list)
    exchanges: int = 0
    schema: dict = field(default_factory=dict)
    corroborated: list = field(default_factory=list)     # proven offline (0 requests)
    leads: list = field(default_factory=list)             # EV-ranked DivergenceCandidate
    by_family: dict = field(default_factory=dict)
    live_findings: list = field(default_factory=list)     # from gated live intervention
    confirm_findings: list = field(default_factory=list)   # from defense-aware replay confirmer
    live_status: str = "not run"
    scope_hosts: list = field(default_factory=list)
    learned_policy: dict = field(default_factory=dict)     # contrast-learned intent per type
    exec_profile: dict = field(default_factory=dict)       # learned defence profile from the live run


def hunt(folder: str, *, engagement=None, budget: int = 300, rich: bool = True,
         live: bool = False, target_cfg: dict | None = None,
         live_replay: bool = False, principal_auth: dict | None = None,
         send=None, base_url: str = "") -> HuntReport:
    """Run the full offline hunt on a captures folder; optionally the gated live confirm
    (intervention engine) and/or the defense-aware REPLAY confirmer (`live_replay`)."""
    scope = set((engagement.in_scope_hosts if engagement else []) or [])
    ex = exchanges_from_dir(folder, scope_hosts=scope or None)
    rep = HuntReport(principals=principals_in(ex), exchanges=len(ex),
                     scope_hosts=sorted(scope))
    if not ex:
        rep.live_status = "no in-scope exchanges found in captures"
        return rep

    schema = learn_schema(ex)
    rep.schema = {"server_auth_fields": sorted(schema.server_auth_fields),
                  "ownership_fields": sorted(schema.ownership_fields),
                  "state_fields": sorted(schema.state_fields),
                  "terminal_states": sorted(schema.terminal_states)}

    # OFFLINE — proven bugs, zero traffic
    rep.corroborated = corroborate(ex, schema)

    # GENERATE leads from the real model
    host = next((h for h in scope), "")
    model = model_from_exchanges(ex, base_url=(f"https://{host}" if host else ""), host=host)
    kc = _kc.run(model, budget=budget, rich=rich, exchanges=ex, schema=schema)
    rep.leads = kc.leads
    rep.by_family = kc.by_family

    # LIVE (gated) — reuse the tested intervention confirmer behind preflight + attestation
    if live:
        rep.live_status = _run_live(engagement, model, target_cfg, rep)
    # LIVE REPLAY (gated) — defense-aware read-side confirmation of the EV-ranked leads
    if live_replay:
        rep.live_status = _run_replay(engagement, rep, ex, principal_auth, send,
                                      host, base_url, budget)
    return rep


def _holder_values(exchanges) -> dict:
    from .corroborate import _looks_discriminating
    hv: dict = {}
    for e in exchanges:
        if not e.object_id:
            continue
        for v in e.response_fields.values():
            if _looks_discriminating(v):
                hv.setdefault(str(e.object_id), set()).add(str(v))
    return hv


def _run_replay(engagement, rep, exchanges, principal_auth, send, host, base_url, budget) -> str:
    if engagement is None or not engagement.attested():
        return "REPLAY REFUSED: no attested engagement (RoE)."
    if not engagement.automation_permitted:
        return "REPLAY REFUSED: engagement.automation_permitted is false."
    if not principal_auth:
        return "REPLAY SKIPPED: no principal auth provided (need your own accounts' headers)."
    try:
        from .confirm import confirm_leads, http_sender
        from .pacer import AdaptivePacer
        from .defense import DefenseProfile
        base = base_url or (f"https://{host}" if host else "")
        sender = send or http_sender(set(rep.scope_hosts))
        prof = DefenseProfile(host=host)
        pacer = AdaptivePacer(rate=2.0)
        scope_ok = (lambda r: (not rep.scope_hosts) or any(h in r.get("url", "") for h in rep.scope_hosts))
        findings, res = confirm_leads(rep.leads, sender, principal_auth, _holder_values(exchanges),
                                      base_url=base, pacer=pacer, profile=prof, budget=budget,
                                      concurrent=True, scope_ok=scope_ok)
        rep.confirm_findings = findings
        rep.exec_profile = res.profile
        return (f"replay ran: {res.stats['completed']} probes, {len(findings)} confirmed, "
                f"{res.stats['blocked']} blocked by defences; safe_rate≈{res.profile.get('safe_rate')}")
    except Exception as e:      # noqa: BLE001
        return f"replay error: {e}"


def _run_live(engagement, model, target_cfg, rep) -> str:
    if engagement is None or not engagement.attested():
        return "REFUSED: no attested Engagement (roe). Live confirmation needs written authorisation."
    if not engagement.automation_permitted:
        return "REFUSED: engagement.automation_permitted is false."
    if target_cfg is None:
        return ("SKIPPED: no --target intervention config. Offline corroboration + leads only. "
                "Provide an engine target.json (see docs/notes/WALL7.md) to auto-confirm by intervention.")
    try:
        from .preflight import preflight
        pf = preflight(engagement, model, spec=None, allow_write=False)
        ok = getattr(pf, "ok", None)
        if ok is False:
            return f"REFUSED by preflight: {getattr(pf, 'reasons', pf)}"
    except Exception as e:      # noqa: BLE001 — preflight is best-effort here
        return f"preflight unavailable ({e}); refusing live to stay fail-closed"
    try:
        from .engine import run_target
        findings = run_target(target_cfg)
        rep.live_findings = [f for f in findings if f.verdict == "FINDING"]
        return f"ran: {len(findings)} kinds, {len(rep.live_findings)} confirmed by Δstate"
    except SystemExit as e:
        return f"live auth/setup error: {e}"
    except Exception as e:      # noqa: BLE001
        return f"live run error: {e}"
