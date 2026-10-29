"""
reason · intent — reconstruct the developer's INTENDED access policy (I).

The developer sees only intent and assumes enforcement matches it. We rebuild a
shadow of that intent from what the app legally leaks (JS role guards, mined role
hints, GraphQL/OpenAPI provenance, effect classes, and the *shape* of the endpoint
— an addressable object is presumptively owner-scoped). The gap between this I and
the measured enforcement E is where the bugs neither developer nor scanner sees.

Every rule is deterministic (QL4) and carries its evidence + confidence (QL3).
This module states INTENT only — it never measures reachability and never decides.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from ..models import Effect, Endpoint, SurfaceModel
from ..normalize import object_ids, SELF_ALIASES
from .signals import endpoint_signals, IntentSignals

_TEMPLATE_SEG = re.compile(r"\{([^}/]+)\}")


class AccessClass(str, Enum):
    """Intended access, ordered least → most restrictive (compare by RANK)."""
    PUBLIC = "PUBLIC"                 # anyone, unauthenticated
    AUTHENTICATED = "AUTHENTICATED"  # any logged-in principal
    OWNER_ONLY = "OWNER_ONLY"        # only the principal that owns the object
    TENANT_ISOLATED = "TENANT_ISOLATED"  # only principals of the owning tenant/org
    ROLE_RESTRICTED = "ROLE_RESTRICTED"  # only a named non-admin role
    ADMIN_ONLY = "ADMIN_ONLY"        # only admin/internal/staff
    UNKNOWN = "UNKNOWN"              # no signal — presumptively unconstrained


RANK = {
    AccessClass.PUBLIC: 0,
    AccessClass.AUTHENTICATED: 1,
    AccessClass.OWNER_ONLY: 2,
    AccessClass.TENANT_ISOLATED: 3,
    AccessClass.ROLE_RESTRICTED: 4,
    AccessClass.ADMIN_ONLY: 5,
    AccessClass.UNKNOWN: -1,
}

# Effects that are intrinsically privileged (function-level) → ADMIN/ROLE.
_PRIV_EFFECTS = {Effect.AUTHORITY, Effect.AUTHORITY_GRANT}
# Effects that address/return an owned object or a value-bearing resource → OWNER.
_OWNED_EFFECTS = {Effect.OBJECT_ACCESS, Effect.OWNERSHIP, Effect.PAYMENT,
                  Effect.PRICE, Effect.INVENTORY, Effect.COUPON,
                  Effect.FIELD_PROJECTION}
_ADMIN_WORDS = ("admin", "internal", "staff", "root", "superuser", "console", "mgmt")


@dataclass(frozen=True)
class IntentRule:
    """The intended access class for one endpoint, with why we believe it."""
    endpoint_key: str
    access_class: AccessClass
    confidence: str                 # high | medium | low
    signals: tuple[str, ...] = field(default_factory=tuple)   # human-checkable reasons
    onyx_effect: str = Effect.NONE.value
    separates: tuple[str, ...] = field(default_factory=tuple)  # whom intent means to keep out (Point 3)

    @property
    def rank(self) -> int:
        return RANK[self.access_class]


def _addresses_object(ep: Endpoint) -> bool:
    """Does this endpoint address a specific object id — a concrete id segment, a
    templated {id} segment (not a self-alias like /me), or an observed concrete id?"""
    for oid in object_ids(ep.path):
        if oid.strip("{}").lower() not in SELF_ALIASES:
            return True
    for name in _TEMPLATE_SEG.findall(ep.path):
        if name.strip().lower() not in SELF_ALIASES:
            return True
    return bool(ep.observed_ids) and ep.effect in _OWNED_EFFECTS


def _infer_one(ep: Endpoint, sig: IntentSignals | None = None) -> IntentRule:
    sig = sig or endpoint_signals(ep)
    signals: list[str] = []
    cls = AccessClass.UNKNOWN
    conf = "low"

    role_words = [r for r in ep.role_hints
                  if any(w in r.lower() for w in _ADMIN_WORDS)]
    other_roles = [r for r in ep.role_hints if r not in role_words]
    admin_field = any(f in ("is_admin", "isadmin", "is_superuser") or "admin" in f
                      for f in sig.field_role)

    # Priority: most restrictive well-evidenced intent wins.
    if ep.effect in _PRIV_EFFECTS or role_words or admin_field:
        cls = AccessClass.ADMIN_ONLY
        conf = "high" if (role_words or admin_field) else "medium"
        if role_words:
            signals.append(f"role-guard hint: {sorted(set(role_words))}")
        if admin_field:
            signals.append(f"admin/privilege field(s): {sig.field_role}")
        if ep.effect in _PRIV_EFFECTS:
            signals.append(f"privileged effect {ep.effect.value} (function-level authority)")
    elif sig.field_role or other_roles:
        cls = AccessClass.ROLE_RESTRICTED
        conf = "medium"
        if sig.field_role:
            signals.append(f"role/privilege field(s): {sig.field_role}")
        if other_roles:
            signals.append(f"role hint: {sorted(set(other_roles))}")
    elif sig.field_tenant:
        cls = AccessClass.TENANT_ISOLATED
        conf = "high"
        signals.append(f"tenant field(s): {sig.field_tenant} → tenant isolation (cross-tenant = critical)")
    elif sig.self_scoped:
        cls = AccessClass.OWNER_ONLY
        conf = "high"
        signals.append("self-scoped path (/me,/self) → clearest owner intent")
    elif sig.field_owner:
        cls = AccessClass.OWNER_ONLY
        conf = "high"
        signals.append(f"owner field(s): {sig.field_owner} → owner-scoped")
    elif _addresses_object(ep):
        cls = AccessClass.OWNER_ONLY
        conf = "medium" if ep.effect in _OWNED_EFFECTS else "low"
        signals.append("addresses a specific object id → presumptively owner-scoped")
        if ep.effect in _OWNED_EFFECTS:
            signals.append(f"object/value effect {ep.effect.value}")
    elif ep.effect != Effect.NONE:
        cls = AccessClass.AUTHENTICATED
        conf = "low"
        signals.append(f"security-relevant effect {ep.effect.value}, no object id")

    tiers = {p.tier.value for p in ep.provenance}
    if ("T1_LIVE" in tiers or "T2_CAPTURED" in tiers) and cls != AccessClass.UNKNOWN:
        if conf == "low":
            conf = "medium"
        signals.append("intent leaked in a live/served source")

    return IntentRule(endpoint_key=ep.key, access_class=cls, confidence=conf,
                      signals=tuple(signals), onyx_effect=ep.effect.value)


def infer_intent(model: SurfaceModel,
                 leakage: dict[str, "AccessClass"] | None = None,
                 joint: bool = False) -> dict[str, IntentRule]:
    """endpoint_key -> IntentRule. Deterministic, provenance-grounded (QL3/QL4).

    `leakage` (optional) maps endpoint_key -> a minimum AccessClass mined from raw
    OpenAPI/GraphQL/HAR evidence; when it is MORE restrictive than the model-derived
    class, it wins (external evidence strengthens intent).

    `joint` (opt-in, default OFF ⇒ byte-identical) runs the IntentGraph refinement
    (Point 3): observed multi-principal PARTITION + learned target privilege
    vocabulary as additional evidence, then MONOTONE structural propagation
    (read≤write, same-object cross-surface, parent→child). It can only RAISE intent —
    never lower — so it reduces false negatives and never creates them."""
    out: dict[str, IntentRule] = {}
    for ep in model.sorted_endpoints():
        rule = _infer_one(ep)
        if leakage and ep.key in leakage:
            lk = leakage[ep.key]
            if RANK.get(lk, -1) > rule.rank:
                rule = IntentRule(endpoint_key=ep.key, access_class=lk,
                                  confidence="high",
                                  signals=rule.signals + (f"raw leakage → {lk.value}",),
                                  onyx_effect=rule.onyx_effect)
        out[ep.key] = rule
    if joint:
        from .intent_graph import refine
        out = refine(model, out)
    return dict(sorted(out.items()))
