"""
kill_chain.py — the UNIFIED intent kill-chain, WIRED to IOLITE's real surface model.

This is the v1.14 pipeline's promise, delivered: `pipeline.py` proved the composition
on an in-process target; this runs the SAME six stages over an actual
`iolite.models.SurfaceModel` built from acquired evidence —

  GENERATE  divergence.enumerate_divergences(model, lattice)   [wide, 8 families]
   -> REDUCE   quotient by authorization-equivalence class       [representatives]
   -> SCHEDULE EV priority under a hard budget                    [graceful leads]
   -> CONFIRM  metamorphic.decide(evidence)                       [the ONE sound gate]
   -> CERTIFY  replayable certificate per confirmed finding
   -> REPORT   EV-ranked dossiers + per-family coverage + lattice summary

Clean separation of powers (IOLITE's invariant): GENERATE is fully wired and runs
offline on the real model; CONFIRM is a pluggable `evidence_provider`. Offline the
provider is `evidence_from_model` (honest: it yields LEADs with the exact live probe,
REFUSES irreversible writes, and marks an attacker who is legitimately authorized as
CLEAN — it never fabricates a confirmation). The live provider is ONYX's Δstate
confirmer. Widening GENERATE can only raise recall; only the single CONFIRM gate can
turn a proposal into a finding, so the false-positive rate cannot rise. Deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import (Effect, Endpoint, ObservedAccess, Principal, Provenance,
                      SourceKind, SurfaceModel)
from . import divergence as _div
from . import metamorphic as _mm


# --------------------------------------------------------------------------- #
# stages                                                                       #
# --------------------------------------------------------------------------- #

def reduce_quotient(cands):
    """Collapse to one representative per authorization-equivalence class (family,
    action, field, object-type), keeping the highest-payout member. Returns (reps, raw)."""
    by: dict = {}
    for c in cands:
        k = c.equiv_class
        if k not in by or c.payout > by[k].payout:
            by[k] = c
    reps = sorted(by.values(), key=lambda c: (-c.payout, c.family, c.path))
    return reps, len(cands)


def schedule(reps, budget):
    ordered = sorted(reps, key=lambda c: (-c.payout, c.family, c.path))
    return ordered[:budget], ordered[budget:]


@dataclass
class Report:
    raw: int = 0
    quotient: int = 0
    scheduled: int = 0
    by_family: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)      # (cand, cert) — confirmed by the live oracle
    corroborated: list = field(default_factory=list)  # CorroboratedFinding — proven OFFLINE, 0 requests
    leads: list = field(default_factory=list)          # cand
    refused: list = field(default_factory=list)        # cand (unsafe writes)
    abstained: list = field(default_factory=list)
    clean: int = 0
    ev_total: int = 0
    lattice: dict = field(default_factory=dict)
    schema: dict = field(default_factory=dict)         # learned schema summary

    @property
    def confirmed_total(self) -> int:
        return len(self.findings) + len(self.corroborated)

    @property
    def false_positives(self) -> int:
        # a finding whose candidate was a decoy would be an FP; decoys are tagged
        return sum(1 for c, _ in self.findings if getattr(c, "_decoy", False))


def run(model: SurfaceModel, *, budget: int = 200, rich: bool = True,
        evidence_provider=None, exchanges=None, schema=None) -> Report:
    """Run the wired kill-chain over a real SurfaceModel.

    v1.16: evidence is captured (request+response), the schema is LEARNED from it, and
    `corroborate` proves bugs OFFLINE (0 requests) before any live step runs. The lattice
    uses the learned schema (language-agnostic); generation widens over it; the one
    metamorphic gate disposes of the rest."""
    from .capture import exchanges_from_model
    from .schema_learn import learn_schema
    from .corroborate import corroborate
    from ..surface_model import privilege_scores

    ex = exchanges if exchanges is not None else exchanges_from_model(model)
    sch = schema or learn_schema(ex, priv_scores=privilege_scores(model))

    provider = evidence_provider or (lambda c: _mm.evidence_from_model(model, c))
    lat = _div.build_lattice(model, rich=rich, schema=sch, exchanges=ex)
    raw = _div.enumerate_divergences(model, lat, rich=rich)
    reps, raw_n = reduce_quotient(raw)
    todo, leads_over = schedule(reps, budget)
    # FIX (self-critique #9): the quotient must NOT silently truncate. Every non-
    # representative instance is preserved as a lower-ranked lead (coverage degrades by
    # value, never silently), so a real bug on a specific object is never dropped.
    rep_keys = {c.key for c in reps}
    degraded = sorted((c for c in raw if c.key not in rep_keys),
                      key=lambda c: (-c.payout, c.family, c.path))

    rep = Report(raw=raw_n, quotient=len(reps), scheduled=len(todo),
                 by_family=_div.family_counts(raw))
    from .relation_model import summarize
    rep.lattice = summarize(lat)
    rep.schema = {"ownership_fields": sorted(sch.ownership_fields),
                  "server_auth_fields": sorted(sch.server_auth_fields),
                  "state_fields": sorted(sch.state_fields),
                  "terminal_states": sorted(sch.terminal_states),
                  "privilege_fields": sorted(sch.privilege_fields)}

    # OFFLINE corroboration — proven from the captures, zero requests
    rep.corroborated = corroborate(ex, sch)
    rep.ev_total += sum(2500 if f.severity == "critical" else 1500 for f in rep.corroborated)

    for c in todo:
        ev = provider(c)
        res = _mm.decide(ev, family=c.family,
                         coord=(c.method, c.path, c.object_id, c.field_name),
                         derivation=c.derivation)
        v = res.verdict
        if v == _mm.Verdict.CONFIRMED:
            rep.findings.append((c, res.cert))
            rep.ev_total += c.payout
        elif v == _mm.Verdict.LEAD:
            rep.leads.append(c)
        elif v == _mm.Verdict.REFUSED:
            rep.refused.append(c)
        elif v == _mm.Verdict.ABSTAIN:
            rep.abstained.append(c)
        else:
            rep.clean += 1
    rep.leads.extend(leads_over)
    rep.leads.extend(degraded)        # preserved, ranked — never silently truncated
    return rep


# --------------------------------------------------------------------------- #
# a REAL demo SurfaceModel (not hardcoded verdicts — the lattice derives these) #
# --------------------------------------------------------------------------- #

def _prov(locator=""):
    return Provenance.of(SourceKind.HAR, locator or "demo.har")


def build_demo_model() -> SurfaceModel:
    """A small but real SurfaceModel exercising every divergence family. Nothing here
    states a verdict — it states OBSERVED legitimate accesses; the lattice + oracle
    derive intent and decisions. (Mirrors a tiny multi-principal capture.)"""
    m = SurfaceModel(base_url="https://demo.example", host="demo.example")
    A = Principal("A", "alice");  B = Principal("B", "bob")
    AD = Principal("AD", "admin")
    m.principals = [A, B, AD]

    def acc(pid, method, path, oid, effect=Effect.OBJECT_ACCESS, body=None,
            query=None, safe_read=True, roles=None, params=None):
        # template the concrete id so the endpoint key and the access key agree
        tmpl = path.replace(oid, "{id}") if oid else path
        m.add_endpoint(Endpoint(method=method, path=tmpl, effect=effect,
                                role_hints=roles or [], params=params or [],
                                provenance=[_prov()], observed_ids=[oid] if oid else []))
        m.add_access(ObservedAccess(
            principal_id=pid, endpoint_key=f"{method} {tmpl}",
            object_id=oid, path=path, method=method, provenance=_prov(),
            query=query or {}, body=body, carrier="path",
            all_ids=[oid] if oid else [], safe_read=safe_read))

    # owner-scoped read + write + delete surface (read_bola, action_bola, chained)
    acc("A", "GET",    "/api/vault/1001", "1001")
    acc("A", "PATCH",  "/api/vault/1001", "1001", effect=Effect.OWNERSHIP, body={"title": "x"}, safe_read=False)
    acc("B", "GET",    "/api/vault/2002", "2002")
    acc("A", "DELETE", "/api/doc/3003",   "3003", effect=Effect.OWNERSHIP, safe_read=False)
    acc("B", "GET",    "/api/doc/4004",   "4004")

    # BOPLA: account carries a server-authoritative 'role' field
    acc("A", "PATCH", "/api/account/5005", "5005", effect=Effect.OWNERSHIP,
        body={"name": "alice", "role": "member"}, safe_read=False, params=["role"])
    # REBINDING: transfer trusts a client-supplied owner_id
    acc("A", "POST", "/api/transfer", "", effect=Effect.PAYMENT,
        body={"amount": 10, "owner_id": "A"}, safe_read=False, params=["owner_id"])

    # TENANT: report is tenant-scoped (tenant_id field); A in T1, B in T2
    acc("A", "GET", "/api/report/7007", "7007", body={"tenant_id": "T1"}, params=["tenant_id"])
    acc("B", "GET", "/api/report/7008", "7008", body={"tenant_id": "T2"}, params=["tenant_id"])

    # WORKFLOW-STATE: invoice 9001 is archived, yet a PATCH surface exists
    acc("A", "PATCH", "/api/invoice/9001", "9001", effect=Effect.OWNERSHIP,
        body={"status": "archived"}, safe_read=False)

    # VERTICAL / BFLA: an admin-only function reached only by AD
    acc("AD", "GET", "/api/admin/users", "", effect=Effect.AUTHORITY, roles=["admin"])
    # give AD a higher privilege score by a second admin-guarded read
    acc("AD", "POST", "/api/admin/grant", "", effect=Effect.AUTHORITY_GRANT,
        roles=["admin"], safe_read=False)
    return m


def build_demo_exchanges():
    """Response-bearing evidence (what a 2-account HAR contains). Deliberately in a
    non-English vocabulary to prove the schema is LEARNED, not wordlisted. Contains a
    real cross-account secret reproduction (an offline-provable BOLA) and a server-
    authoritative field reflected on a write (offline-provable BOPLA)."""
    from .capture import CapturedExchange as CE
    return [
        CE("A", "GET /api/vault/{id}", "GET", "1001", owned=True,
           response_fields={"secreto": "tok_7h3Qe9", "estado": "activo", "duenio": "A"}, seq=0),
        CE("B", "GET /api/vault/{id}", "GET", "2002", owned=True,
           response_fields={"secreto": "tok_Zk1p2L", "estado": "activo", "duenio": "B"}, seq=1),
        # B's capture ALSO contains A's vault 1001 with A's secret -> BOLA proven offline
        CE("B", "GET /api/vault/{id}", "GET", "1001", owned=False,
           response_fields={"secreto": "tok_7h3Qe9", "estado": "activo", "duenio": "A"}, seq=2),
        # invoice lifecycle pendiente -> archivado (terminal LEARNED, no English)
        CE("A", "GET /api/invoice/{id}", "GET", "9001", owned=True,
           response_fields={"estado": "pendiente"}, seq=3),
        CE("A", "PATCH /api/invoice/{id}", "PATCH", "9001", owned=True,
           request_fields={"estado": "archivado"}, response_fields={"estado": "archivado"}, seq=4),
        # BOPLA: 'nivel' only ever in responses (server-set); a PATCH sets it, server reflects it
        CE("A", "GET /api/account/{id}", "GET", "5005", owned=True,
           response_fields={"nivel": "miembro"}, seq=5),
        CE("A", "PATCH /api/account/{id}", "PATCH", "5005", owned=True,
           request_fields={"nivel": "admin"}, response_fields={"nivel": "admin"}, seq=6),
    ]


def main() -> int:
    model = build_demo_model()
    rep = run(model, budget=200, exchanges=build_demo_exchanges())
    print("UNIFIED INTENT KILL-CHAIN — WIRED to the real surface model")
    print("=" * 84)
    print(f"  GENERATE : {rep.raw} raw divergence candidates across {len(rep.by_family)} families")
    print(f"             {rep.by_family}")
    print(f"  REDUCE   : -> {rep.quotient} authorization-equivalence representatives")
    print(f"  SCHEDULE : {rep.scheduled} under budget")
    print("  LEARN    : schema learned from evidence (language-agnostic):")
    print(f"             server-authoritative={rep.schema['server_auth_fields']}  "
          f"state={rep.schema['state_fields']}  terminal(learned)={rep.schema['terminal_states']}")
    print(f"  CONFIRM  : {len(rep.corroborated)} CORROBORATED offline (0 requests) | "
          f"{len(rep.leads)} live-leads | {len(rep.refused)} refused(unsafe) | {rep.clean} clean")
    # the offline-proven findings (what pays with zero traffic)
    print("  corroborated (proven from captures, no packets sent):")
    for f in rep.corroborated:
        print(f"    ✓ {f.family:12s} obj={f.object_id} [{f.attacker} got {f.owner}'s]  {f.evidence}")
    print("  top live-leads (family · probe · intended-deny derivation):")
    for c in rep.leads[:6]:
        print(f"    - {c.family:14s} {c.method} {c.path}  [{c.attacker}→denied]  ${c.payout}")
        print(f"         ∵ {c.derivation}")
    print("=" * 84)
    fams = set(rep.by_family)
    expected = {"read_bola", "action_bola", "bopla_field", "rebinding",
                "workflow_state", "tenant", "vertical"}
    missing = expected - fams
    assert not missing, f"families not generated from the real model: {missing}"
    assert rep.quotient <= rep.raw, "quotient did not reduce"
    assert rep.false_positives == 0, "a decoy leaked through the gate"
    assert all(c.action != "delete" for c, _ in rep.findings), "an irreversible write was 'confirmed' offline"
    # the v1.16 wins: schema LEARNED (no English wordlist) + offline corroboration
    assert "secreto" in rep.schema["server_auth_fields"], "failed to LEARN a non-English server field"
    assert "estado" in rep.schema["state_fields"], "failed to LEARN a non-English state field"
    assert "archivado" in rep.schema["terminal_states"], "failed to LEARN a non-English terminal state"
    assert any(f.family == "read_bola" for f in rep.corroborated), "offline corroboration proved nothing"
    print("WIRED + LEARNED + CORROBORATED: families generated from a real model; the schema")
    print("   was LEARNED from evidence (non-English fields understood); a real BOLA was")
    print("   PROVEN offline from 2-account captures with ZERO requests; unsafe writes")
    print("   refused; FP=0. Live ONYX confirms the remaining EV-ranked leads.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
