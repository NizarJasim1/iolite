"""
reason · workflow_intent — mine the developer's DECLARED workflow guards (the state
dimension of intent leakage), so ONYX's StateGateLaw has a transcription-grade
reference to confirm gate-skips against.

Why this is sound (and why the naive alternative is not)
--------------------------------------------------------------------------------
ONYX (`authpath/state_machine.py`) already refutes "state-machine INFERENCE": an
OBSERVED capture is a SAMPLE, not a specification, so a transition merely unseen in
the capture is NOT a violation. Anomaly-against-a-learned-baseline is forbidden
(RL1). We do NOT do that.

Instead we harvest the guards the developer WROTE DOWN — the same epistemology as
mining OpenAPI `security` or GraphQL `@auth`, lifted to the temporal/state axis:

    if (order.status !== 'PAID') { disableRefund() }   // ← a DECLARED guard:
                                                        //   refund REQUIRES status==PAID

A single client-side comparison DECLARES one gate. It is transcription (a legitimate
reference), not observation. We do not need the whole machine — each mined guard is
a standalone, sound reference. Enum vocabularies mined from JS/GraphQL/OpenAPI
validate the values so a stray string is not mistaken for a state.

reason PROPOSES; ONYX DISPOSES (QL5). Own principals only (QL6). Deterministic (QL4).
Additive-only — never weakens IOLITE or ONYX. When nothing is declared, this module
returns [] and the engine behaves byte-identically to before (honest floor).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..models import SurfaceModel

# --------------------------------------------------------------------------- #
# vocabularies (deterministic, bounded)                                       #
# --------------------------------------------------------------------------- #

# status-typed fields whose value gates a transition (the control-bearing fields)
_STATE_FIELDS = ("status", "state", "stage", "phase", "order_status",
                 "payment_status", "workflow_state", "workflowstate", "step",
                 "lifecycle", "fulfillment_status", "visibility")
# boolean state fields — presence in a guard implies a required boolean pre-state
_BOOL_FIELDS = ("is_paid", "paid", "shipped", "is_shipped", "approved",
                "is_approved", "confirmed", "is_confirmed", "completed",
                "is_completed", "cancelled", "canceled", "is_cancelled",
                "deleted", "is_deleted", "archived", "is_archived",
                "is_active", "active", "locked", "is_locked", "verified",
                "is_verified", "published", "is_published", "settled", "refunded")
# verbs that name a workflow OPERATION (the guarded action)
_OP_VERBS = ("refund", "cancel", "ship", "approve", "reject", "deliver", "pay",
             "checkout", "capture", "settle", "publish", "activate", "deactivate",
             "close", "complete", "submit", "transfer", "payout", "fulfil",
             "fulfill", "void", "release", "confirm", "finalize", "finalise",
             "escalate", "assign", "grant", "revoke", "delete")
# object-type tokens worth naming (kept generic; joined with mined enum names)
_STOP = {"api", "v1", "v2", "v3", "true", "false", "null", "the", "and", "for",
         "get", "post", "put", "patch", "id", "type", "kind", "value", "data"}

_STATE_VALUE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,30}$")
# a declared string-valued guard:  X.status === 'PAID'   /   x.state !== "pending"
_GUARD = re.compile(
    r"(?P<obj>[A-Za-z_$][\w$]*)\s*\.\s*(?P<field>" + "|".join(_STATE_FIELDS) + r")"
    r"\s*(?P<op>===|!==|==|!=)\s*"
    r"(?P<q>['\"])(?P<val>[A-Za-z][A-Za-z0-9_]{1,30})(?P=q)",
    re.IGNORECASE)
# enum-ish value tables:  Status = { PENDING: ..., PAID: ... }   or   ['PENDING','PAID']
_ENUM_OBJ = re.compile(r"([A-Za-z_$][\w$]*)\s*=\s*(?:Object\.freeze\s*\(\s*)?\{([^{}]{0,600})\}")
_ENUM_GQL = re.compile(r"enum\s+([A-Za-z_][\w]*)\s*\{([^{}]{0,600})\}")
_ENUM_KEY = re.compile(r"['\"]?([A-Za-z][A-Za-z0-9_]{1,30})['\"]?\s*[:=]")
_ENUM_ARR = re.compile(r"\[\s*((?:['\"][A-Za-z][A-Za-z0-9_ ]{1,30}['\"]\s*,?\s*){2,})\]")


@dataclass(frozen=True)
class DeclaredGuard:
    """One workflow guard the developer WROTE DOWN. A transcription-grade reference
    (QL3), never an inference from observed traffic."""
    object_hint: str          # e.g. "order" (from enum name / obj var / path token)
    field: str                # "status"
    value: str                # "PAID"
    mode: str                 # "requires" (op needs field==value) | "forbids" (op blocked when field==value)
    operation_hint: str       # "refund" | "" (verb seen near the guard)
    confidence: str           # high | medium | low
    source: str               # js | graphql | openapi
    evidence: str = ""        # human-checkable snippet + locator

    @property
    def gate_predicate(self) -> str:
        rel = "==" if self.mode == "requires" else "!="
        return f"{self.field}{rel}{self.value}"

    def key(self) -> tuple:
        return (self.object_hint, self.field, self.value, self.mode, self.operation_hint)


# --------------------------------------------------------------------------- #
# enum vocabulary (validates that a guard value is really a STATE)             #
# --------------------------------------------------------------------------- #

def _looks_stateish(tok: str) -> bool:
    """A value token that reads like a lifecycle state: UPPER_SNAKE, CapWord, or a
    known lifecycle word. Excludes obvious non-states."""
    t = tok.strip()
    if not _STATE_VALUE.match(t) or t.lower() in _STOP:
        return False
    if t.isupper() and len(t) >= 3:
        return True
    if t[:1].isupper() and t[1:].islower() and len(t) >= 4:      # CapWord
        return True
    return t.lower() in ("pending", "paid", "shipped", "delivered", "cancelled",
                         "canceled", "approved", "rejected", "active", "inactive",
                         "draft", "open", "closed", "complete", "completed",
                         "processing", "refunded", "settled", "confirmed", "new")


def mine_enums(js_texts: list[str], graphql_text: str = "",
               openapi_text: str = "") -> dict[str, list[str]]:
    """object_hint(lower) -> sorted state values. Deterministic. Best-effort; a
    malformed source contributes nothing (QL2)."""
    out: dict[str, set[str]] = {}

    def _add(name: str, vals) -> None:
        nm = (name or "").lower().replace("status", "").replace("state", "").strip("_")
        nm = nm or (name or "").lower()
        keep = {v for v in vals if _looks_stateish(v)}
        if len(keep) >= 2:                       # a real enum has >=2 members
            out.setdefault(nm, set()).update(keep)

    for text in js_texts:
        if not text:
            continue
        for m in _ENUM_OBJ.finditer(text):
            _add(m.group(1), _ENUM_KEY.findall(m.group(2)))
        for m in _ENUM_ARR.finditer(text):
            vals = re.findall(r"['\"]([A-Za-z][A-Za-z0-9_ ]{1,30})['\"]", m.group(1))
            _add("", vals)
    if graphql_text:
        for m in _ENUM_GQL.finditer(graphql_text):
            _add(m.group(1), re.findall(r"[A-Za-z][A-Za-z0-9_]{1,30}", m.group(2)))
    if openapi_text:
        try:
            doc = json.loads(openapi_text)
            _harvest_openapi_enums(doc, out, _add)
        except (ValueError, RecursionError):
            pass
    return {k: sorted(v) for k, v in sorted(out.items()) if v}


def _harvest_openapi_enums(node, out, add, field_name: str = "", depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(node, dict):
        enum = node.get("enum")
        if isinstance(enum, list) and field_name:
            add(field_name, [str(x) for x in enum])
        for k, v in node.items():
            _harvest_openapi_enums(v, out, add, field_name=str(k), depth=depth + 1)
    elif isinstance(node, list):
        for v in node:
            _harvest_openapi_enums(v, out, add, field_name=field_name, depth=depth + 1)


# --------------------------------------------------------------------------- #
# guard miner                                                                 #
# --------------------------------------------------------------------------- #

def _operation_near(text: str, pos: int, window: int = 80) -> str:
    lo, hi = max(0, pos - window), min(len(text), pos + window)
    ctx = text[lo:hi].lower()
    for v in _OP_VERBS:
        if v in ctx:
            return v
    return ""


def _object_hint(obj_var: str, value: str, enums: dict[str, list[str]]) -> str:
    """Best object-type name: the enum whose members include this value, else the
    guard variable name, else "". Deterministic."""
    vl = value.lower()
    for name in sorted(enums):
        if any(v.lower() == vl for v in enums[name]):
            return name
    ov = (obj_var or "").lower()
    return ov if ov and ov not in _STOP else ""


def _guards_from_js(text: str, locator: str, enums: dict[str, list[str]]) -> list[DeclaredGuard]:
    out: list[DeclaredGuard] = []
    known_values = {v.lower() for vs in enums.values() for v in vs}
    for m in _GUARD.finditer(text):
        val = m.group("val")
        # accept the value only if it reads like a state OR appears in a mined enum
        if not (_looks_stateish(val) or val.lower() in known_values):
            continue
        op = m.group("op")
        # `!==`/`!=` guard that blocks ⇒ op REQUIRES field==value.
        # `===`/`==` guard that blocks ⇒ op is FORBIDDEN when field==value.
        mode = "requires" if op in ("!==", "!=") else "forbids"
        oph = _operation_near(text, m.start())
        obj = _object_hint(m.group("obj"), val, enums)
        conf = "high" if (val.lower() in known_values and oph) else (
            "medium" if (val.lower() in known_values or oph) else "low")
        snippet = text[max(0, m.start() - 12):m.end() + 4].replace("\n", " ")
        out.append(DeclaredGuard(
            object_hint=obj, field=m.group("field").lower(), value=val, mode=mode,
            operation_hint=oph, confidence=conf, source="js",
            evidence=f"{snippet.strip()}  @{locator}"))
    return out


def mine_workflow_guards(model: SurfaceModel, js_texts: list[str] | None = None,
                         js_locators: list[str] | None = None,
                         graphql_text: str = "", openapi_text: str = "") -> list[DeclaredGuard]:
    """Return the DECLARED workflow guards, de-duplicated and deterministically
    ordered. `model` is accepted for symmetry/future path-binding; mining itself is
    source-driven. Never raises on malformed input (QL2)."""
    js_texts = js_texts or []
    js_locators = js_locators or [f"js#{i}" for i in range(len(js_texts))]
    enums = mine_enums(js_texts, graphql_text, openapi_text)

    seen: set[tuple] = set()
    guards: list[DeclaredGuard] = []
    for text, loc in zip(js_texts, js_locators, strict=False):
        if not text:
            continue
        for g in _guards_from_js(text, loc, enums):
            if g.key() not in seen:
                seen.add(g.key())
                guards.append(g)
    guards.sort(key=lambda g: (g.object_hint, g.field, g.value, g.mode,
                               g.operation_hint, g.source))
    return guards


def catalog_status(guards: list[DeclaredGuard]) -> list[dict]:
    """Self-describing summary for the `_reason` block (QL3 evidence, no verdict)."""
    return [{"object": g.object_hint, "field": g.field, "value": g.value,
             "mode": g.mode, "operation": g.operation_hint, "predicate": g.gate_predicate,
             "confidence": g.confidence, "source": g.source, "evidence": g.evidence}
            for g in guards]
