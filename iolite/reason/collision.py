"""
reason · collision — the SOUND half of de-duplication. Whether a finding is actually
a duplicate is UNKNOWABLE offline (the report history is private to the platform), so
we never predict it. Instead we score OBSERVABLE collision proxies — how crowded the
surface is and how FRESH it is — which are what make a duplicate more or less likely.

  higher score / p_original  ⇒  lower expected collision  ⇒  more likely to pay.

Built on the existing novelty score, sharpened with cross-session KB freshness
(fresh endpoint, guard regression). p_original is a PROXY, labelled as such — never a
claimed probability. Deterministic (QL4).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CollisionScore:
    cand_key: str
    score: int                          # 0..10, higher = less collision (more original)
    p_original: float                   # score/10 — a labelled PROXY, not a probability
    reasons: list[str] = field(default_factory=list)


def _clamp(n: int) -> int:
    return max(0, min(10, n))


def collision_score(cand, novelty_score: int, kb_sig: dict | None = None) -> CollisionScore:
    s = int(novelty_score)
    reasons = [f"novelty base {novelty_score}/10 (crowding/depth/rarity)"]
    if kb_sig:
        if cand.endpoint_key in kb_sig.get("fresh", ()):  # unseen in prior sessions
            s += 1
            reasons.append("+1 fresh endpoint (not seen in a prior session — fewer eyes)")
        regressed = kb_sig.get("regressed_objects", set())
        gate = (getattr(cand, "required_predecessor", "") or "").lower()
        pre = " ".join(str(k).lower() for k in (getattr(cand, "pre_state", {}) or {}))
        if regressed and any(tok and (tok in gate or tok in pre) for tok in regressed):
            s += 3
            reasons.append("+3 guard REGRESSION (a gate weakened since last session — "
                           "freshly-introduced bug, very low collision)")
    s = _clamp(s)
    return CollisionScore(cand_key=cand.cand_key, score=s,
                          p_original=round(s / 10.0, 2), reasons=reasons)
