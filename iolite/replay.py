"""
⑦ Replay planner — "record once, replay as N principals" (own principals only).

v0.5: two probe families + a FAIR, risk-ordered, bounded budget.

  * SEED     — each principal's own legitimate reads (envelopes for ONYX)
  * HORIZONTAL probes — peer BOLA: another principal reproduces a read of an object
                it does not hold
  * VERTICAL probes   — BFLA / privilege escalation: a lower-privilege principal
                reproduces a read only a higher-privilege principal legitimately made

Budget allocation is ROUND-ROBIN across endpoint groups, groups ordered by the
endpoint's authz-risk (triage). This guarantees a hot endpoint with thousands of ids
cannot starve the rest — every endpoint gets representation within the budget, high
risk first. Reads only; own principals only (QL6). Deterministic (QL4).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import SurfaceModel
from .surface_model import cross_principal_candidates, vertical_candidates


@dataclass
class ReplayPlan:
    seed: list[dict] = field(default_factory=list)
    probe: list[dict] = field(default_factory=list)

    @property
    def horizontal(self) -> int:
        return sum(1 for p in self.probe if p.get("_family") == "horizontal")

    @property
    def vertical(self) -> int:
        return sum(1 for p in self.probe if p.get("_family") == "vertical")

    @property
    def summary(self) -> str:
        objs = {p.get("path") for p in self.probe}
        return (f"{len(self.seed)} seed · {len(self.probe)} probes "
                f"({self.horizontal} horizontal, {self.vertical} vertical) "
                f"across {len(objs)} path(s)")


def _seed(model: SurfaceModel) -> list[dict]:
    out, seen = [], set()
    for acc in sorted(model.accesses,
                      key=lambda a: (a.principal_id, a.path,
                                     str(sorted((a.query or {}).items())))):
        if not acc.safe_read:
            continue
        sig = (acc.principal_id, acc.method, acc.path,
               tuple(sorted((acc.query or {}).items())))
        if sig in seen:
            continue
        seen.add(sig)
        item = {"principal": acc.principal_id, "method": acc.method, "path": acc.path}
        if acc.query:
            item["query"] = acc.query
        if acc.body is not None and acc.method != "GET":
            item["body"] = acc.body
        out.append(item)
    return out


def build_plan(model: SurfaceModel, max_probes: int = 500,
               per_endpoint_cap: int | None = None) -> ReplayPlan:
    plan = ReplayPlan(seed=_seed(model))

    groups: dict[str, list[dict]] = {}

    def push(cand):
        for pid in cand.probe_pids:
            item = {"principal": pid, "method": cand.method, "path": cand.path,
                    "_family": cand.family, "_replayed_from": cand.holder_pid,
                    "_object_id": cand.object_id, "_carrier": cand.carrier}
            if cand.query:
                item["query"] = cand.query
            if cand.body is not None:
                item["body"] = cand.body
            groups.setdefault(cand.endpoint_key, []).append(item)

    for c in cross_principal_candidates(model):
        push(c)
    for c in vertical_candidates(model):
        push(c)

    def risk(k: str) -> int:
        ep = model.endpoints.get(k)
        return ep.risk if ep else 0

    ordered = sorted(groups, key=lambda k: (-risk(k), k))
    idx = {k: 0 for k in ordered}
    taken = {k: 0 for k in ordered}
    remaining = max(0, max_probes)
    progress = True
    while remaining > 0 and progress:
        progress = False
        for k in ordered:
            if remaining <= 0:
                break
            lst = groups[k]
            if idx[k] >= len(lst) or (per_endpoint_cap is not None and taken[k] >= per_endpoint_cap):
                continue
            plan.probe.append(lst[idx[k]])
            idx[k] += 1
            taken[k] += 1
            remaining -= 1
            progress = True
    return plan
