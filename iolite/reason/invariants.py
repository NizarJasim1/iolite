"""
reason · invariants — transplant invariants from mature sciences; a violation is a
candidate for a whole CLASS of authz bug that pattern libraries have no name for.

Active detectors (each mapped to an ONYX EffectClass, bounded & non-destructive —
reads / a single altered read, own principals only):
  * cross_surface_consistency   distributed systems — linearizability  → CROSS_SURFACE
  * non_interference_oracle      information theory — non-interference   → FIELD_PROJECTION
  * value_conservation           accounting/physics — conservation       → PRICE
  * grant_freshness              protocol verification — freshness       → STATE_GATE
  * information_flow             type theory — information-flow control   → FIELD_PROJECTION

reason PROPOSES; ONYX DISPOSES (QL5). Deterministic (QL4).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Effect, SurfaceModel
from ..normalize import object_ids as path_object_ids
from .intent import AccessClass, IntentRule, RANK
from .enforcement import EnforcementView
from .differ import ReasonCandidate

_VALIDATION = ("validate", "/check", "exists", "availability", "available",
               "lookup", "/verify", "resolve", "/search", "/find", "is-taken",
               "username", "email-check")
_VALUE_MARKERS = ("checkout", "cart", "/price", "balance", "credit", "wallet",
                  "coupon", "redeem", "transfer", "refund", "topup", "/quote", "/order")
_VALUE_EFFECTS = {Effect.PAYMENT, Effect.PRICE, Effect.INVENTORY, Effect.COUPON}
_VALUE_KEYS = ("amount", "price", "qty", "quantity", "total", "count", "balance",
               "credit", "value", "sum")
_TOKEN_KEYS = ("token", "otp", "code", "nonce", "signature", "sig", "ticket",
               "grant", "ott", "one_time", "access_code")
_EXPAND_KEYS = ("include", "expand", "embed", "fields", "with", "ref", "related",
                "parent", "populate", "join")


@dataclass
class Invariant:
    name: str
    science: str
    description: str
    status: str

    def candidates(self, model: SurfaceModel, intent: dict[str, IntentRule],
                   enf: EnforcementView) -> list[ReasonCandidate]:
        return []


class CrossSurfaceConsistency(Invariant):
    """Linearizability: one object's authz state must be consistent across every
    surface that addresses it. Guarded on A, exposed on looser B → B is the leak."""

    def __init__(self):
        super().__init__("cross_surface_consistency",
                         "distributed systems — linearizability",
                         "same object guarded on one surface, exposed on a looser one",
                         "active")

    def candidates(self, model, intent, enf):
        by_obj: dict[str, dict[str, tuple[int, object]]] = {}
        for acc in model.accesses:
            if not acc.safe_read:
                continue
            for oid in (acc.all_ids or [acc.object_id]):
                if not oid:
                    continue
                rule = intent.get(acc.endpoint_key)
                rank = rule.rank if rule else RANK[AccessClass.UNKNOWN]
                slot = by_obj.setdefault(str(oid), {})
                if acc.endpoint_key not in slot:
                    slot[acc.endpoint_key] = (rank, acc)
        out = []
        for oid in sorted(by_obj):
            surfaces = by_obj[oid]
            if len(surfaces) < 2:
                continue
            ranks = {k: r for k, (r, _a) in surfaces.items()}
            hi, lo = max(ranks.values()), min(ranks.values())
            if hi <= lo or hi < RANK[AccessClass.OWNER_ONLY]:
                continue
            loose_key = sorted(k for k, r in ranks.items() if r == lo)[0]
            strict_key = sorted(k for k, r in ranks.items() if r == hi)[0]
            _r, la = surfaces[loose_key]
            holders = enf.holders_of(oid)
            attackers = [p for p in enf.all_principals if p not in holders]
            if not attackers:
                continue
            out.append(ReasonCandidate(
                endpoint_key=loose_key, method=la.method, path=la.path,
                gap_kind="invariant_cross_surface", intent_class=AccessClass.OWNER_ONLY.value,
                intent_confidence="medium", onyx_effect=Effect.CROSS_SURFACE.value,
                probe_pids=sorted(attackers),
                holder_pid=(sorted(holders)[0] if holders else ""), object_id=oid,
                carrier=la.carrier, family="invariant_cross_surface",
                query=dict(la.query or {}), body=la.body,
                rationale=(f"object {oid} guarded on '{strict_key}' but addressable on looser "
                           f"'{loose_key}' — cross-surface inconsistency; ONYX confirms by Δstate")))
        out.sort(key=lambda c: (c.endpoint_key, c.object_id))
        return out


class NonInterferenceOracle(Invariant):
    """Non-interference: a low-privilege observation must not depend on a
    high-privilege secret. A validation/lookup endpoint that answers differently for
    'exists' vs 'not' is an existence/attribute oracle over other users' secrets."""

    def __init__(self):
        super().__init__("non_interference_oracle",
                         "information theory — non-interference",
                         "validation/lookup endpoint leaks existence/ownership of others' data",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        peers = list(enf.all_principals)
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            low = (acc.path + " " + acc.endpoint_key).lower()
            if not any(m in low for m in _VALIDATION):
                continue
            victims = [p for p in peers if p != acc.principal_id] or [acc.principal_id]
            q = dict(acc.query or {})
            selector = victims[0]
            if q:
                k = sorted(q)[0]
                q[k] = f"probe::{selector}"
            else:
                q["q"] = f"probe::{selector}"
            sig = (acc.endpoint_key, acc.path)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                gap_kind="invariant_non_interference", intent_class="OWNER_ONLY",
                intent_confidence="low", onyx_effect=Effect.FIELD_PROJECTION.value,
                probe_pids=[acc.principal_id], holder_pid="",
                object_id="", carrier="query", family="invariant_non_interference",
                query=q, body=acc.body,
                rationale=("validation/lookup surface; a distinguishable answer for another "
                           "principal's selector leaks existence/ownership (non-interference "
                           "violation) — ONYX confirms by Δstate response delta")))
        return out


class ValueConservation(Invariant):
    """Conservation: total value is conserved across operations. A quote/price
    endpoint that accepts a boundary/negative quantity and returns a non-conserving
    total (negative, overflow) is an economic-authz violation."""

    def __init__(self):
        super().__init__("value_conservation",
                         "accounting/physics — conservation",
                         "value-bearing endpoint yields a non-conserving total (economic authz/TOCTOU)",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            ep = model.endpoints.get(acc.endpoint_key)
            low = (acc.path + " " + acc.endpoint_key).lower()
            valueish = (ep and ep.effect in _VALUE_EFFECTS) or any(m in low for m in _VALUE_MARKERS)
            if not valueish:
                continue
            q = dict(acc.query or {})
            k = next((x for x in q if x.lower() in _VALUE_KEYS), None)
            if not k:
                continue
            sig = (acc.endpoint_key, k)
            if sig in seen:
                continue
            seen.add(sig)
            q2 = dict(q); q2[k] = "-1"
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                gap_kind="invariant_conservation", intent_class="OWNER_ONLY",
                intent_confidence="medium", onyx_effect=Effect.PRICE.value,
                probe_pids=[acc.principal_id], holder_pid=acc.principal_id,
                object_id=str(acc.object_id or ""), carrier="query",
                family="invariant_conservation", query=q2, body=acc.body,
                rationale=(f"value key '{k}' set to -1 on a value-bearing endpoint; a non-conserving "
                           f"total (negative/overflow) breaks value conservation — ONYX confirms by Δstate")))
        return out


class GrantFreshness(Invariant):
    """Freshness: an authorization grant must be fresh and single-use. A token/nonce
    reused across a different object or a second time is a replay/reorder bug."""

    def __init__(self):
        super().__init__("grant_freshness",
                         "protocol verification — freshness/ordering",
                         "authorization token/nonce is replayable or reusable across objects",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            q = dict(acc.query or {})
            tk = next((x for x in q if x.lower() in _TOKEN_KEYS), None)
            ids = path_object_ids(acc.path)
            if not tk or not ids:
                continue
            try:
                neighbor = str(int(ids[-1]) + 1)
            except ValueError:
                continue
            head, _s, tail = acc.path.rpartition(ids[-1])
            if not head:
                continue
            npath = head + neighbor + tail        # SAME token, DIFFERENT object → replay
            sig = (acc.endpoint_key, npath)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=npath,
                gap_kind="invariant_freshness", intent_class="OWNER_ONLY",
                intent_confidence="medium", onyx_effect=Effect.STATE_GATE.value,
                probe_pids=[acc.principal_id], holder_pid=acc.principal_id,
                object_id=neighbor, carrier="query", family="invariant_freshness",
                query=dict(q), body=acc.body,
                rationale=(f"token '{tk}' reused against a different object ({ids[-1]}→{neighbor}); "
                           f"a fresh grant must be bound to one object/use — ONYX confirms by Δstate")))
        return out


class InformationFlow(Invariant):
    """Information-flow control: an object reference from one principal's context must
    not leak into another's response. An expand/include over-fetch can pull a related
    object without re-authorizing it (second-order IDOR)."""

    def __init__(self):
        super().__init__("information_flow",
                         "type theory — information-flow control",
                         "expand/include over-fetch leaks a related object without re-authz",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            ep = model.endpoints.get(acc.endpoint_key)
            q = dict(acc.query or {})
            has_expand = any(x.lower() in _EXPAND_KEYS for x in q)
            objectish = ep and ep.effect in (Effect.OBJECT_ACCESS, Effect.FIELD_PROJECTION)
            if not has_expand and not objectish:
                continue
            k = next((x for x in q if x.lower() in _EXPAND_KEYS), "include")
            q2 = dict(q); q2[k] = "owner,payment_method,internal_notes"
            sig = (acc.endpoint_key, acc.path)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                gap_kind="invariant_information_flow", intent_class="OWNER_ONLY",
                intent_confidence="low", onyx_effect=Effect.FIELD_PROJECTION.value,
                probe_pids=[acc.principal_id], holder_pid=acc.principal_id,
                object_id=str(acc.object_id or ""), carrier="query",
                family="invariant_information_flow", query=q2, body=acc.body,
                rationale=(f"'{k}' over-fetch of related objects (owner/payment/internal); a nested "
                           f"resolver may not re-authorize them (second-order IDOR) — ONYX confirms by Δstate")))
        return out


CATALOG: list[Invariant] = [
    CrossSurfaceConsistency(),
    NonInterferenceOracle(),
    ValueConservation(),
    GrantFreshness(),
    InformationFlow(),
]


def run_invariants(model: SurfaceModel, intent, enf) -> list[ReasonCandidate]:
    out: list[ReasonCandidate] = []
    for inv in CATALOG:
        if inv.status == "active":
            out.extend(inv.candidates(model, intent, enf))
    return out


def catalog_status() -> list[dict]:
    return [{"name": i.name, "science": i.science, "status": i.status,
             "description": i.description} for i in CATALOG]
