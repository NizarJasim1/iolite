"""
live_calibrate — the SOUNDNESS transfer (Point 5). Protects ONYX's zero-false-positive
guarantee when it moves from a deterministic synthetic target to a NON-DETERMINISTIC
live one.

The threat: a live response changes between two reads for reasons unrelated to authz —
timestamps, counters, A/B buckets, cache, load-balanced replicas, personalisation. A
naive Δstate read-back could see that "change" and FALSELY confirm a breach. That would
destroy the one asset the whole toolchain sells: soundness.

The fix (grounded in the flaky-REST-API literature): before confirming anything, MEASURE
the target's own non-determinism from repeated authenticated reads of YOUR OWN objects
(safe, own data), learn which fields are volatile and the stability quorum, and feed that
into ONYX's existing stability voting + volatile projection. A live Δstate is then sound
only when a change survives on SECURITY-bearing fields after the calibrated noise is
projected out — otherwise ONYX ABSTAINS (honest) rather than false-confirm.

Pure, deterministic (QL4). The sampling itself (issuing the reads) is on-device; this
module holds the calibration + the soundness test, both testable offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# field names that are volatile by convention — treated as noise even with one sample
_KNOWN_VOLATILE = ("timestamp", "time", "ts", "date", "updated", "created", "now",
                   "etag", "nonce", "csrf", "token", "trace", "request_id", "requestid",
                   "seq", "sequence", "cursor", "page", "count", "views", "seen",
                   "last_seen", "version", "revision", "expires", "iat", "exp", "jti",
                   "random", "rand", "uuid", "session")


def _flatten(obj, prefix: str = "", depth: int = 0, out: dict | None = None) -> dict:
    """Bounded flatten to dotted paths (2 levels), for field-level diffing."""
    out = {} if out is None else out
    if depth > 2:
        out[prefix.rstrip(".")] = "…"
        return out
    if isinstance(obj, dict):
        for k in sorted(obj, key=str):
            _flatten(obj[k], f"{prefix}{k}.", depth + 1, out)
    elif isinstance(obj, list):
        out[prefix.rstrip(".") + "[]"] = len(obj)          # list identity by length only
    else:
        out[prefix.rstrip(".")] = obj
    return out


def _is_known_volatile(path: str) -> bool:
    leaf = path.rsplit(".", 1)[-1].rstrip("[]").lower()
    return any(v == leaf or v in leaf for v in _KNOWN_VOLATILE)


@dataclass
class StabilityProfile:
    volatile_fields: list[str] = field(default_factory=list)
    security_fields: list[str] = field(default_factory=list)
    stability_k: int = 1
    noise_ratio: float = 0.0
    samples: int = 0
    notes: list[str] = field(default_factory=list)

    def to_onyx(self) -> dict:
        """The knobs to set on ONYX's confirmer before a live scan (it already supports
        stability voting + volatile projection — we only supply the calibrated values)."""
        return {"stability_k": self.stability_k,
                "strip_volatile_fields": list(self.volatile_fields),
                "stability_strip_volatile": bool(self.volatile_fields)}


def calibrate_from_samples(samples: list[dict]) -> StabilityProfile:
    """Learn the target's non-determinism from ≥2 repeated reads of the SAME own object.
    Deterministic. With <2 samples, only convention-based volatiles are known."""
    flats = [_flatten(s) for s in samples if isinstance(s, dict)]
    all_paths = sorted({p for f in flats for p in f})
    volatile: set[str] = set()
    for p in all_paths:
        if _is_known_volatile(p):
            volatile.add(p)
        vals = [f.get(p, "\0missing") for f in flats]
        if len(set(map(repr, vals))) > 1:                  # differs across samples ⇒ volatile
            volatile.add(p)
    security = [p for p in all_paths if p not in volatile]
    noise = round(len(volatile) / len(all_paths), 3) if all_paths else 0.0
    k = 1 if not volatile else (5 if noise >= 0.34 else 3)
    notes = []
    if len(flats) < 2:
        notes.append("only 1 sample — volatility known by convention only; take ≥3 for a real baseline")
    if noise >= 0.5:
        notes.append("HIGH non-determinism — confirmations will be conservative (good: fewer false positives)")
    if not security:
        notes.append("no stable security-bearing field observed — ONYX will likely ABSTAIN here (honest)")
    return StabilityProfile(volatile_fields=sorted(volatile), security_fields=security,
                            stability_k=k, noise_ratio=noise, samples=len(flats), notes=notes)


def is_sound_delta(before: dict, after: dict, profile: StabilityProfile) -> tuple[bool, list[str]]:
    """Would a change from `before`→`after` be a SOUND Δstate (a real security change)
    rather than calibrated noise? Projects out volatile fields, then looks for a
    surviving change on a security-bearing field. Returns (sound, changed_fields)."""
    fb, fa = _flatten(before or {}), _flatten(after or {})
    volatile = set(profile.volatile_fields)
    changed = []
    for p in sorted(set(fb) | set(fa)):
        if p in volatile or _is_known_volatile(p):
            continue
        if fb.get(p, "\0m") != fa.get(p, "\0m"):
            changed.append(p)
    return (bool(changed), changed)
