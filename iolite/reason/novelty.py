"""
reason · novelty — the money filter. A confirmed bug that is a DUPLICATE pays $0.
ONYX guards validity; this guards ORIGINALITY, steering effort to bugs unlikely to be
already reported, so expected PAYOUT (not just confirmation) is maximised.

priority = impact.score + novelty.score

Signals that a bug is likely still un-found: it lives on a freshly-shipped/ghost
endpoint, a secondary/deep surface, a rare bug class, or a multi-step chain. Signals
it is likely crowded: sequential-id IDOR on a mainstream core object (everyone tries
that first). Deterministic (QL4); a heuristic, never a guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import SurfaceModel
from .differ import ReasonCandidate
from .amplify import ImpactScore

_NOVEL_FAMILIES = {
    "invariant_non_interference", "invariant_conservation", "invariant_freshness",
    "invariant_information_flow", "invariant_cross_surface", "assumption_nested_child",
    "assumption_webhook", "assumption_lifecycle", "assumption_export",
    "chain_cross_surface", "chain_privilege_lateral", "chain_disclosure",
}
_CROWDED_FAMILIES = {"assumption_enum"}
_COMMON_TOKENS = ("users", "user", "orders", "order", "profile", "/me", "account",
                  "accounts", "posts", "comments")


@dataclass
class NoveltyScore:
    cand_key: str
    score: int
    reasons: list[str] = field(default_factory=list)


def _clamp(n: int) -> int:
    return max(0, min(10, n))


def score_novelty(c: ReasonCandidate, model: SurfaceModel) -> NoveltyScore:
    s, reasons = 5, []
    hay = (c.path + " " + c.endpoint_key).lower()
    common = any(t in hay for t in _COMMON_TOKENS)

    if c.endpoint_key in model.ghost_keys:
        s += 4; reasons.append("+4 ghost/freshly-shipped endpoint (fewer eyes)")
    if c.depth >= 2 or c.chain_from:
        s += 3; reasons.append("+3 multi-step chain (few hunters go this deep)")
    if c.family in _NOVEL_FAMILIES:
        s += 3; reasons.append("+3 rare/novel bug class (not in pattern libraries)")
    if c.gap_kind == "declared_unreached_gap":
        s += 2; reasons.append("+2 shadow surface (no one reached it)")
    if c.intent_class == "TENANT_ISOLATED":
        s += 2; reasons.append("+2 tenant-isolation break (rare, high-value)")

    if c.family in _CROWDED_FAMILIES and common:
        s -= 3; reasons.append("-3 sequential IDOR on a mainstream object (crowded — likely dup)")
    if c.family in ("intent_gap", "observed_object_gap") and common and c.depth == 1:
        s -= 1; reasons.append("-1 core object, shallow (commonly tested)")

    return NoveltyScore(cand_key=c.cand_key, score=_clamp(s), reasons=reasons)


def novelty_map(cands: list[ReasonCandidate], model: SurfaceModel) -> dict[str, NoveltyScore]:
    return {c.cand_key: score_novelty(c, model) for c in cands}


def priority(c: ReasonCandidate, impact: ImpactScore | None,
             nov: NoveltyScore | None) -> int:
    return (impact.score if impact else 0) + (nov.score if nov else 0)
