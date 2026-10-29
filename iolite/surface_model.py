"""
⑤ Surface model — assemble mined + observed surface into one deterministic model.

Provides the analysis views ONYX-style detectors care about:
  * object graph   — which principals legitimately held which object ids
  * role matrix    — which endpoints are privilege-guarded, and by what hint
  * cross-principal object candidates — an object one principal holds that another
    principal might reach (the BOLA pairing ONYX will confirm by Δstate)

Pure aggregation over the SurfaceModel; no verdicts (QL5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Effect, Endpoint, SurfaceModel


def merge_endpoints(model: SurfaceModel, endpoints) -> None:
    for ep in endpoints:
        model.add_endpoint(ep)


def role_matrix(model: SurfaceModel) -> list[dict]:
    """Endpoints carrying a privilege hint — the BFLA surface. Deterministic."""
    rows = []
    for ep in model.sorted_endpoints():
        if ep.role_hints:
            rows.append({"endpoint": ep.key, "effect": ep.effect.value,
                         "hints": sorted(set(ep.role_hints)),
                         "tier": ep.best_tier.value})
    return rows


@dataclass
class BolaCandidate:
    endpoint_key: str
    object_id: str
    holder_pid: str            # who legitimately holds it
    probe_pids: list[str]      # your OTHER principals who should be denied it
    path: str
    method: str
    query: dict = field(default_factory=dict)   # reproduce the exact request
    body: object = None
    carrier: str = "path"      # which carrier held the id (path/query/jwt/...)
    family: str = "horizontal" # horizontal (peer BOLA) | vertical (privilege / BFLA)


_PRIV_EFFECTS = {Effect.AUTHORITY, Effect.AUTHORITY_GRANT}


def _is_privileged(ep: Endpoint) -> bool:
    return (ep.effect in _PRIV_EFFECTS
            or any(("admin" in r or "internal" in r or "staff" in r) for r in ep.role_hints))


def privilege_scores(model: SurfaceModel) -> dict[str, int]:
    """priv[pid] = # of distinct privilege-guarded endpoints this principal legitimately
    reached. A measured fact (RL1-style), never assumed."""
    per: dict[str, set] = {p.pid: set() for p in model.principals}
    for acc in model.accesses:
        ep = model.endpoints.get(acc.endpoint_key)
        if ep and _is_privileged(ep) and acc.principal_id in per:
            per[acc.principal_id].add(acc.endpoint_key)
    return {pid: len(s) for pid, s in per.items()}


def _sig(acc) -> tuple:
    return (acc.endpoint_key, str(acc.object_id),
            tuple(sorted((k, str(v)) for k, v in (acc.query or {}).items())))


def cross_principal_candidates(model: SurfaceModel) -> list[BolaCandidate]:
    """HORIZONTAL (peer BOLA): each OTHER principal we control reproduces the exact
    read (path+query+body) for an object it does NOT hold. Reads only (GET or a
    GraphQL query POST). Own-principals only (QL6). Deterministic."""
    all_pids = [p.pid for p in model.principals]
    out, seen = [], set()
    for acc in model.accesses:
        if not acc.safe_read:
            continue
        ids = acc.all_ids or [acc.object_id]
        holders = set().union(*(model.holdings.get(i, set()) for i in ids)) if ids else set()
        others = [p for p in all_pids if p not in holders]
        if not others or _sig(acc) in seen:
            continue
        seen.add(_sig(acc))
        out.append(BolaCandidate(
            endpoint_key=acc.endpoint_key, object_id=acc.object_id,
            holder_pid=acc.principal_id, probe_pids=sorted(others),
            path=acc.path, method=acc.method, query=dict(acc.query or {}),
            body=acc.body, carrier=acc.carrier, family="horizontal"))
    out.sort(key=lambda c: (c.endpoint_key, str(c.object_id),
                            tuple(sorted((c.query or {}).items()))))
    return out


def vertical_candidates(model: SurfaceModel) -> list[BolaCandidate]:
    """VERTICAL (BFLA / privilege escalation): a LOWER-privilege principal reproduces
    a read that only a HIGHER-privilege principal legitimately made against a
    privilege-guarded endpoint. Own-principals only. ONYX confirms whether the
    lower-privilege principal is wrongly authorised. Deterministic."""
    priv = privilege_scores(model)
    out, seen = [], set()
    for acc in model.accesses:
        if not acc.safe_read:
            continue
        ep = model.endpoints.get(acc.endpoint_key)
        if not (ep and _is_privileged(ep)):
            continue
        p_priv = priv.get(acc.principal_id, 0)
        attackers = sorted([q for q, s in priv.items() if s < p_priv])
        if not attackers or _sig(acc) in seen:
            continue
        seen.add(_sig(acc))
        out.append(BolaCandidate(
            endpoint_key=acc.endpoint_key, object_id=acc.object_id,
            holder_pid=acc.principal_id, probe_pids=attackers,
            path=acc.path, method=acc.method, query=dict(acc.query or {}),
            body=acc.body, carrier=acc.carrier, family="vertical"))
    out.sort(key=lambda c: (c.endpoint_key, str(c.object_id)))
    return out


def stats(model: SurfaceModel) -> dict:
    eps = list(model.endpoints.values())
    by_effect: dict[str, int] = {}
    for ep in eps:
        by_effect[ep.effect.value] = by_effect.get(ep.effect.value, 0) + 1
    by_tier: dict[str, int] = {}
    for ep in eps:
        t = ep.best_tier.value
        by_tier[t] = by_tier.get(t, 0) + 1
    return {
        "endpoints": len(eps),
        "principals": len(model.principals),
        "observed_accesses": len(model.accesses),
        "objects": len(model.holdings),
        "ghost_endpoints": len(model.ghost_keys),
        "by_effect": dict(sorted(by_effect.items())),
        "by_tier": dict(sorted(by_tier.items())),
        "role_guarded": len(role_matrix(model)),
    }
