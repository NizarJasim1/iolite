"""
reason · enforcement — measure the ENFORCED access policy (E) from evidence.

The offline E is what the captures already prove: which of YOUR principals actually
reached each endpoint, and which principals legitimately held each object. The
*live* E — "would principal B reach A's object?" — is never assumed here; that
question is emitted as an ONYX probe and answered by Δstate. So this module reports
only OBSERVED reachability (ground truth), plus the holdings graph the differ needs.

Deterministic (QL4), provenance-grounded (QL3). No verdicts, no live traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import SurfaceModel


@dataclass
class EnfObservation:
    """Observed enforcement facts for one endpoint key."""
    endpoint_key: str
    reached_by: set[str] = field(default_factory=set)     # principals seen reaching it
    objects: set[str] = field(default_factory=set)        # object ids seen at it
    safe_read: bool = True                                # every observed access was a read

    @property
    def reached(self) -> bool:
        return bool(self.reached_by)


@dataclass
class EnforcementView:
    per_endpoint: dict[str, EnfObservation] = field(default_factory=dict)
    holdings: dict[str, set[str]] = field(default_factory=dict)   # object_id -> holder pids
    all_principals: tuple[str, ...] = ()

    def holders_of(self, object_id: str) -> set[str]:
        return set(self.holdings.get(object_id, set()))

    def non_holders(self, object_id: str) -> list[str]:
        held = self.holders_of(object_id)
        return sorted(p for p in self.all_principals if p not in held)


def observe_enforcement(model: SurfaceModel) -> EnforcementView:
    view = EnforcementView(
        all_principals=tuple(sorted(p.pid for p in model.principals)),
        holdings={oid: set(pids) for oid, pids in model.holdings.items()},
    )
    for acc in model.accesses:
        obs = view.per_endpoint.get(acc.endpoint_key)
        if obs is None:
            obs = EnfObservation(endpoint_key=acc.endpoint_key)
            view.per_endpoint[acc.endpoint_key] = obs
        obs.reached_by.add(acc.principal_id)
        for oid in (acc.all_ids or [acc.object_id]):
            if oid:
                obs.objects.add(str(oid))
        obs.safe_read = obs.safe_read and acc.safe_read
    view.per_endpoint = dict(sorted(view.per_endpoint.items()))
    return view
