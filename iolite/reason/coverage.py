"""
reason · coverage — the honest recall signal.

ONYX guarantees PRECISION (zero false positives). The 90%-ambition is a RECALL
problem: of the surface the developer meant to restrict, how much did we actually
probe? This meter reports that fraction and names the untested restricted endpoints
(false-negative risk) and the CRUD methods present on object resources that no
candidate exercises — so the operator acquires more instead of mistaking silence for
safety.

Deterministic (QL4). Measures, never claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import SurfaceModel
from .intent import IntentRule, AccessClass, RANK

_CRUD = ("GET", "POST", "PUT", "PATCH", "DELETE")


@dataclass
class CoverageReport:
    restricted: int = 0
    covered: int = 0
    untested: list[str] = field(default_factory=list)     # restricted, no candidate
    method_gaps: list[str] = field(default_factory=list)   # resource: missing CRUD methods

    @property
    def pct(self) -> float:
        return round(self.covered / self.restricted, 3) if self.restricted else 1.0


def coverage(model: SurfaceModel, intent: dict[str, IntentRule], candidates) -> CoverageReport:
    restricted = [k for k, r in intent.items() if r.rank >= RANK[AccessClass.OWNER_ONLY]]
    probed = {c.endpoint_key for c in candidates}
    covered = [k for k in restricted if k in probed]
    untested = sorted(k for k in restricted if k not in probed)

    # method-level gaps on object resources: methods present per template path vs CRUD
    by_path: dict[str, set[str]] = {}
    for key in model.endpoints:
        try:
            method, path = key.split(" ", 1)
        except ValueError:
            continue
        if "{" in path:                       # object resource
            by_path.setdefault(path, set()).add(method.upper())
    gaps = []
    for path in sorted(by_path):
        missing = [m for m in _CRUD if m not in by_path[path]]
        if missing and by_path[path]:         # some methods seen, others not → acquire them
            gaps.append(f"{path}: missing {','.join(missing)}")

    return CoverageReport(restricted=len(restricted), covered=len(covered),
                          untested=untested, method_gaps=gaps)
