"""
reason · differ — compute I △ E and emit candidates (the blind-spot hunter).

Two gap kinds, both of which a scanner (patterns only) and a developer (intent only)
miss:

  1. observed_object_gap  — an object addressed at a restricted-intent endpoint is
     held by one principal; another principal that intent says must be denied is
     emitted as a probe to reach it. (Horizontal/vertical, intent-labelled.)

  2. declared_unreached_gap — a privileged endpoint (ROLE/ADMIN intent) that IOLITE
     mined from intent leakage (JS/GraphQL/OpenAPI) but that NO controlled principal
     legitimately reached. reason emits a probe: your lowest-privilege principal
     attempts it. This is the SHADOW/ADMIN surface — no observed-access generator
     can produce it, because there is no observed access to replay.

Every candidate is a HYPOTHESIS carrying the ONYX EffectClass it will be confirmed
under. reason never decides (QL5). Own principals only (QL6). Deterministic (QL4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import SurfaceModel
from ..surface_model import privilege_scores
from .intent import AccessClass, IntentRule, RANK
from .enforcement import EnforcementView

_TEMPLATE_SEG = re.compile(r"\{[^}/]+\}")


def _fill(path: str, concrete_id: str) -> str:
    """Replace the first templated segment with a concrete id (for a probeable req)."""
    if concrete_id and _TEMPLATE_SEG.search(path):
        return _TEMPLATE_SEG.sub(concrete_id, path, count=1)
    return path


@dataclass
class ReasonCandidate:
    """A blind-spot hypothesis for ONYX to confirm by Δstate. No verdict here."""
    endpoint_key: str
    method: str
    path: str
    gap_kind: str                       # observed_object_gap | declared_unreached_gap
    intent_class: str                   # AccessClass value that E may be violating
    intent_confidence: str              # high | medium | low
    onyx_effect: str                    # EffectClass ONYX confirms under
    probe_pids: list[str]               # YOUR principals that intent says must be denied
    holder_pid: str = ""                # who legitimately holds it ("" if declared/unreached)
    object_id: str = ""
    carrier: str = "path"
    family: str = "intent_gap"          # reason family tag (not replay horizontal/vertical)
    rationale: str = ""
    query: dict = field(default_factory=dict)
    body: object = None
    depth: int = 1                       # CEGAR search depth (1 = initial hypothesis)
    chain_from: str = ""                 # lineage: the confirmed capability that spawned this
    # --- workflow/state dimension (additive; empty for ordinary stateless candidates) ---
    pre_state: dict = field(default_factory=dict)   # object state the probe is run FROM (e.g. {"status":"PENDING"})
    required_predecessor: str = ""       # the DECLARED gate that must run first (e.g. "status==PAID")

    @property
    def cand_key(self) -> str:
        """Stable identity for oracle verdict mapping + dedup across rounds. The
        state tag is appended ONLY when a pre_state is present, so ordinary
        stateless candidates keep byte-identical keys (no perturbation)."""
        pids = ",".join(self.probe_pids)
        base = f"{self.family}|{self.method} {self.path}|{self.object_id}|{pids}"
        if self.pre_state:
            tag = ",".join(f"{k}={self.pre_state[k]}" for k in sorted(self.pre_state))
            base = f"{base}|@{tag}"
        return base

    def to_probe_items(self) -> list[dict]:
        items = []
        for pid in self.probe_pids:
            item = {
                "principal": pid, "method": self.method, "path": self.path,
                "_family": self.family,
                "_replayed_from": self.holder_pid or "(declared-unreached)",
                "_object_id": self.object_id, "_carrier": self.carrier,
                "_reason_gap": self.gap_kind,
                "_reason_intent": self.intent_class,
                "_reason_conf": self.intent_confidence,
                "_reason_effect": self.onyx_effect,
                "_reason_why": self.rationale,
                "_reason_depth": self.depth,
                "_reason_chain_from": self.chain_from,
            }
            if self.pre_state:
                item["_reason_pre_state"] = dict(self.pre_state)
            if self.required_predecessor:
                item["_reason_gate"] = self.required_predecessor
            if self.query:
                item["query"] = dict(self.query)
            if self.body is not None:
                item["body"] = self.body
            items.append(item)
        return items


def _lowest_priv(model: SurfaceModel) -> list[str]:
    priv = privilege_scores(model)
    if not priv:
        return sorted(p.pid for p in model.principals)
    lo = min(priv.values())
    return sorted(pid for pid, s in priv.items() if s == lo)


def diff_intent_enforcement(model: SurfaceModel,
                            intent: dict[str, IntentRule],
                            enf: EnforcementView) -> list[ReasonCandidate]:
    out: list[ReasonCandidate] = []
    priv = privilege_scores(model)

    # --- Gap 1: observed object at a restricted-intent endpoint ---------------
    seen1: set[tuple] = set()
    for acc in sorted(model.accesses,
                      key=lambda a: (a.endpoint_key, str(a.object_id),
                                     tuple(sorted((a.query or {}).items())))):
        if not acc.safe_read:
            continue
        rule = intent.get(acc.endpoint_key)
        if rule is None or rule.rank < RANK[AccessClass.OWNER_ONLY]:
            continue
        ids = acc.all_ids or [acc.object_id]
        holders = set().union(*(enf.holders_of(i) for i in ids)) if ids else set()
        others = [p for p in enf.all_principals if p not in holders]
        # For ROLE/ADMIN intent, the meaningful attacker is a LOWER-privilege peer.
        if rule.rank >= RANK[AccessClass.ROLE_RESTRICTED]:
            hp = priv.get(acc.principal_id, 0)
            others = [p for p in others if priv.get(p, 0) < hp]
            fam = "intent_bfla"
        else:
            fam = "intent_gap"
        sig = (acc.endpoint_key, str(acc.object_id))
        if not others or sig in seen1:
            continue
        seen1.add(sig)
        out.append(ReasonCandidate(
            endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
            gap_kind="observed_object_gap", intent_class=rule.access_class.value,
            intent_confidence=rule.confidence, onyx_effect=rule.onyx_effect,
            probe_pids=sorted(others), holder_pid=acc.principal_id,
            object_id=str(acc.object_id), carrier=acc.carrier, family=fam,
            query=dict(acc.query or {}), body=acc.body,
            rationale=(f"intent={rule.access_class.value} ({rule.confidence}); object held by "
                       f"{acc.principal_id}; {len(others)} other principal(s) must be denied — "
                       f"ONYX confirms by Δstate")))

    # --- Gap 2: declared privileged endpoint NO principal legitimately reached --
    attackers = _lowest_priv(model)
    for key, rule in intent.items():
        if rule.rank < RANK[AccessClass.ROLE_RESTRICTED]:   # ROLE/ADMIN only (shadow surface)
            continue
        obs = enf.per_endpoint.get(key)
        if obs is not None and obs.reached:                 # someone reached it → not a shadow
            continue
        ep = model.endpoints.get(key)
        if ep is None or not attackers:
            continue
        # Build a concrete, probeable request.
        path = ep.path
        obj = ""
        if _TEMPLATE_SEG.search(path):
            borrow = ep.observed_ids[0] if ep.observed_ids else ""
            if not borrow:
                # try any known object id in scope to make it concrete
                borrow = next(iter(sorted(enf.holdings)), "")
            if not borrow:
                continue                                    # not probeable → leave as lead
            path = _fill(path, borrow)
            obj = borrow
        out.append(ReasonCandidate(
            endpoint_key=key, method=ep.method, path=path,
            gap_kind="declared_unreached_gap", intent_class=rule.access_class.value,
            intent_confidence=rule.confidence, onyx_effect=rule.onyx_effect,
            probe_pids=list(attackers), holder_pid="", object_id=obj,
            carrier="path", family="intent_bfla",
            rationale=(f"intent={rule.access_class.value} ({rule.confidence}); mined from leakage "
                       f"but NO controlled principal reached it (shadow/admin surface) — "
                       f"lowest-privilege principal attempts it; ONYX confirms by Δstate")))

    out.sort(key=lambda c: (c.gap_kind, -RANK.get(AccessClass(c.intent_class), -1),
                            c.endpoint_key, c.object_id))
    return out
