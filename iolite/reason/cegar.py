"""
reason · cegar — Counterexample-Guided Abstraction Refinement for authorization.

The closed loop that makes the engine a "Critical maker": hypothesize → test (ONYX
Δstate) → refine → deepen, converging on the deepest reachable violation.

  round r:
    1. take the untested candidate frontier (depth r)
    2. ONYX (the oracle) DECIDES each: confirmed | denied | unknown
    3. refine:
         · denied  → prune that branch (record, never re-emit)
         · confirmed → a CONFIRMED CAPABILITY → the chain composer spawns depth r+1
           candidates that build ON that capability (cross-surface escalation,
           privilege-lateral, deepen invariant/assumption probes on the proven object)
    4. stop at depth k, empty frontier, or budget exhausted

Transplanted from model checking's CEGAR. Bounded depth k (real authz chains are
short). reason PROPOSES; ONYX DISPOSES (QL5). Own principals only (QL6). Legal:
the live oracle runs only under an attested engagement. Deterministic (QL4).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Effect, SurfaceModel
from ..roe import Engagement
from . import BOUNDED_DEPTH_K
from .intent import infer_intent
from .enforcement import observe_enforcement
from .engine import reason as _reason
from .differ import ReasonCandidate
from .oracle import Oracle, StaticOracle, OracleVerdict


@dataclass
class CegarRound:
    depth: int
    tested: int = 0
    confirmed: list[str] = field(default_factory=list)   # cand_keys
    denied: int = 0
    unknown: int = 0
    spawned: int = 0


@dataclass
class CegarTrace:
    oracle_kind: str
    depth_k: int
    rounds: list[CegarRound] = field(default_factory=list)
    confirmed_chain: list[dict] = field(default_factory=list)   # confirmed caps, in order
    pruned: int = 0
    all_candidates: list[ReasonCandidate] = field(default_factory=list)

    @property
    def confirmed_count(self) -> int:
        return len(self.confirmed_chain)

    def summary(self) -> str:
        return (f"CEGAR[{self.oracle_kind}] k={self.depth_k} · rounds={len(self.rounds)} · "
                f"confirmed={self.confirmed_count} · pruned={self.pruned} · "
                f"candidates={len(self.all_candidates)}")


# effects that, once confirmed, are worth escalating into a deeper chain
_ESCALATE_EFFECTS = {Effect.OBJECT_ACCESS.value, Effect.AUTHORITY.value,
                     Effect.OWNERSHIP.value, Effect.CROSS_SURFACE.value,
                     Effect.FIELD_PROJECTION.value, Effect.STATE_GATE.value}


def _escalate(cap: ReasonCandidate, model: SurfaceModel, intent, enf,
              leaked_ids: list[str]) -> list[ReasonCandidate]:
    """Chain composer: from a CONFIRMED capability, spawn depth+1 candidates that
    build on it. Deterministic, own-principals-only, bounded."""
    out: list[ReasonCandidate] = []
    pid = cap.probe_pids[0] if cap.probe_pids else ""
    if not pid or cap.onyx_effect not in _ESCALATE_EFFECTS:
        return out

    # 1. cross-surface escalation — the proven principal now reaches the SAME object
    #    on every OTHER surface that addresses it.
    if cap.object_id:
        other_keys = sorted({acc.endpoint_key for acc in model.accesses
                             if cap.object_id in (acc.all_ids or [acc.object_id])
                             and acc.endpoint_key != cap.endpoint_key})
        for k in other_keys:
            acc = next(a for a in model.accesses if a.endpoint_key == k)
            out.append(ReasonCandidate(
                endpoint_key=k, method=acc.method, path=acc.path,
                gap_kind="chain_cross_surface", intent_class=cap.intent_class,
                intent_confidence="medium", onyx_effect=Effect.CROSS_SURFACE.value,
                probe_pids=[pid], holder_pid=cap.holder_pid, object_id=cap.object_id,
                carrier=acc.carrier, family="chain_cross_surface",
                query=dict(acc.query or {}), body=acc.body,
                depth=cap.depth + 1, chain_from=cap.cand_key,
                rationale=(f"chain: {pid} proven on object {cap.object_id} at "
                           f"'{cap.endpoint_key}' → now reaches it on '{k}'")))

    # 2. privilege-lateral — a confirmed BFLA unlocks the OTHER privileged endpoints.
    if cap.onyx_effect in (Effect.AUTHORITY.value, Effect.OWNERSHIP.value):
        for ep in model.sorted_endpoints():
            if ep.key == cap.endpoint_key:
                continue
            if ep.effect in (Effect.AUTHORITY, Effect.AUTHORITY_GRANT) or \
               any(w in r.lower() for r in ep.role_hints for w in ("admin", "internal", "staff")):
                path = ep.path
                if "{" in path:
                    borrow = ep.observed_ids[0] if ep.observed_ids else cap.object_id
                    if not borrow:
                        continue
                    import re
                    path = re.sub(r"\{[^}/]+\}", borrow, path, count=1)
                out.append(ReasonCandidate(
                    endpoint_key=ep.key, method=ep.method, path=path,
                    gap_kind="chain_privilege_lateral", intent_class="ADMIN_ONLY",
                    intent_confidence="medium", onyx_effect=ep.effect.value or Effect.AUTHORITY.value,
                    probe_pids=[pid], holder_pid="", object_id="",
                    carrier="path", family="chain_privilege_lateral",
                    depth=cap.depth + 1, chain_from=cap.cand_key,
                    rationale=(f"chain: {pid} proven privileged at '{cap.endpoint_key}' → "
                               f"attempts sibling privileged endpoint '{ep.key}'")))

    # 3. leaked-id disclosure — if ONYX evidence leaked new ids, reach them.
    for lid in sorted(set(leaked_ids))[:10]:
        npath = cap.path.replace(cap.object_id, lid, 1) if cap.object_id else cap.path
        out.append(ReasonCandidate(
            endpoint_key=cap.endpoint_key, method=cap.method, path=npath,
            gap_kind="chain_disclosure", intent_class="OWNER_ONLY",
            intent_confidence="medium", onyx_effect=Effect.OBJECT_ACCESS.value,
            probe_pids=[pid], holder_pid="", object_id=lid, carrier=cap.carrier,
            depth=cap.depth + 1, chain_from=cap.cand_key,
            rationale=f"chain: id {lid} leaked by the confirmed read → {pid} reaches it"))
    return out


def refine_search(model: SurfaceModel, engagement: Engagement,
                  oracle: Oracle | None = None, depth: int = BOUNDED_DEPTH_K,
                  budget_per_round: int = 200, inputs=None) -> CegarTrace:
    oracle = oracle or StaticOracle()
    intent = infer_intent(model)
    enf = observe_enforcement(model)

    frontier = list(_reason(model, inputs).candidates)
    for c in frontier:
        c.depth = 1
    trace = CegarTrace(oracle_kind=oracle.kind, depth_k=depth)
    tested_keys: set[str] = set()
    all_by_key: dict[str, ReasonCandidate] = {c.cand_key: c for c in frontier}

    for r in range(1, depth + 1):
        batch = [c for c in frontier if c.cand_key not in tested_keys][:budget_per_round]
        if not batch:
            break
        rnd = CegarRound(depth=r, tested=len(batch))
        verdicts = oracle.test(model, batch, engagement)
        next_frontier: list[ReasonCandidate] = []
        for c in batch:
            tested_keys.add(c.cand_key)
            v = verdicts.get(c.cand_key) or OracleVerdict(c.cand_key, None)
            if v.confirmed is True:
                rnd.confirmed.append(c.cand_key)
                trace.confirmed_chain.append(
                    {"cand": c.cand_key, "endpoint": c.endpoint_key, "object": c.object_id,
                     "effect": c.onyx_effect, "depth": c.depth, "severity": v.severity,
                     "from": c.chain_from})
                spawned = _escalate(c, model, intent, enf, v.leaked_ids)
                for s in spawned:
                    if s.cand_key not in all_by_key and s.cand_key not in tested_keys:
                        all_by_key[s.cand_key] = s
                        next_frontier.append(s)
                rnd.spawned += len(spawned)
            elif v.confirmed is False:
                rnd.denied += 1
                trace.pruned += 1          # prune this branch — never re-emit
            else:
                rnd.unknown += 1
        trace.rounds.append(rnd)
        frontier = next_frontier
        if not frontier:
            break

    trace.all_candidates = sorted(all_by_key.values(),
                                  key=lambda c: (c.depth, c.family, c.endpoint_key, c.object_id))
    return trace
