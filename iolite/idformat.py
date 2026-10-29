"""
Id shape + enumerability classifier.

Determines the BLAST RADIUS of an object-access surface: a short sequential
integer means an attacker can walk the entire collection; a UUID bounds it to
disclosed ids. Ported from ONYX's `classify_enumerability` so IOLITE's risk
ranking and ONYX's report agree.
"""

from __future__ import annotations

import re

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def classify(object_id: str) -> tuple[str, str]:
    """Return (level, note). level ∈ {sequential,numeric,uuid,opaque,slug,unknown}."""
    s = str(object_id).strip()
    if not s:
        return "unknown", ""
    if s.isdigit():
        if len(s) <= 9:
            return ("sequential",
                    "short sequential integer — every object enumerable by "
                    "incrementing; blast radius is the whole collection")
        return ("numeric", "numeric id — enumeration feasible but slower")
    if _UUID_RE.match(s):
        return ("uuid", "UUID (high entropy) — needs a disclosed id to exploit at scale")
    if len(s) >= 16 and all(c in "0123456789abcdefABCDEF-_=" for c in s):
        return ("opaque", "long opaque token — enumeration impractical")
    return ("slug", "human-readable slug — may be guessable/discoverable")


# how much each level adds to the authz-risk score (transparent integers)
ENUM_WEIGHT = {"sequential": 6, "numeric": 4, "slug": 3, "uuid": 1, "opaque": 1, "unknown": 0}


def enumerability_of(observed_ids) -> tuple[str, str, int]:
    """Pick the most-enumerable level across observed ids (worst case drives risk)."""
    best_level, best_note, best_w = "unknown", "", 0
    for oid in observed_ids or []:
        level, note = classify(oid)
        w = ENUM_WEIGHT.get(level, 0)
        if w > best_w:
            best_level, best_note, best_w = level, note, w
    return best_level, best_note, best_w
