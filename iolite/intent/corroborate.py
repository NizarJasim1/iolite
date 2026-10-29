"""
corroborate.py — CONFIRM authorization bugs OFFLINE, from evidence already captured,
sending ZERO new requests.

The sharpest practical gap in v1.15 was that nothing could be confirmed without a live
step. But a hunter who captured two of their OWN accounts' sessions very often ALREADY
holds the proof: if principal B's capture contains a successful response for an object
that principal A owns, and B reproduced A's discriminating private value, that is a
proven BOLA — no packet needs to be sent to confirm it. This module mines exactly that.

It is sound by construction (it only reads captures the operator legitimately holds) and
zero-harm (no requests). Three corroborations:

  * read_bola   B (not the owner) has a 2xx response for A's owned object carrying a
                DISCRIMINATING value identical to A's (an object-specific secret/token,
                not a shared default) -> confirmed cross-user read.
  * tenant      B (tenant T2) has a 2xx for an object owned in tenant T1 -> confirmed
                cross-tenant.
  * bopla       a write exchange SENT a field the schema learned is server-authoritative
                and the response REFLECTED the client's value -> confirmed property
                escalation (the client set a field only the server should set).

Deterministic (QL4). Own principals only (QL6).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .schema_learn import LearnedSchema, learn_schema


@dataclass
class CorroboratedFinding:
    family: str
    object_id: str
    owner: str
    attacker: str
    endpoint_key: str
    evidence: str                     # the human-checkable discriminator
    severity: str = "high"
    cert: dict = field(default_factory=dict)

    @property
    def key(self):
        return (self.family, self.object_id, self.attacker, self.endpoint_key)


def _looks_discriminating(value) -> bool:
    """A value that could be an owner-private secret/token/email/uuid — NOT a shared
    enum word ('active', 'standard') or a bare counter. Requires length + a digit or a
    token separator or high length, so dictionary words are rejected."""
    sv = str(value)
    if len(sv) < 6 or sv.isdigit():
        return False
    return (any(c.isdigit() for c in sv) or any(c in "_-@.:/" for c in sv) or len(sv) >= 16)


def _discriminating_values(exchanges, cid=None) -> dict:
    """value -> set(object_ids) it appeared for. A value is object-specific (a good
    discriminator) when it appears for very few objects and looks like a secret. Object
    ids are canonicalised (cid) so two representations of one object count once."""
    cid = cid or (lambda x: str(x))
    val_objs: dict = {}
    for e in exchanges:
        for v in e.response_fields.values():
            if _looks_discriminating(v):
                val_objs.setdefault(str(v), set()).add(cid(e.object_id))
    return val_objs


def corroborate(exchanges, schema: LearnedSchema | None = None,
                priv_scores: dict | None = None, identity=None) -> list[CorroboratedFinding]:
    schema = schema or learn_schema(exchanges, priv_scores=priv_scores)
    out, seen = [], set()

    # `identity` (opt-in object_identity.IdentityMap): canonicalise object ids so the SAME
    # object under different representations/surfaces (1001 / gid://…/1001 / a cursor) is
    # one node — a non-owner reproducing the owner's private value via a DIFFERENT door is
    # then corroborated as a cross-surface BOLA. The value-presence check still arbitrates.
    def _cid(x):
        return identity.canonical(str(x)) if identity is not None else str(x)

    # owner of each object = the principal that created/owns it (owned=True)
    owner_of: dict = {}
    tenant_of: dict = {}
    for e in exchanges:
        if e.owned and e.object_id and _cid(e.object_id) not in owner_of:
            owner_of[_cid(e.object_id)] = e.principal
        if e.tenant and e.object_id and _cid(e.object_id) not in tenant_of:
            tenant_of[_cid(e.object_id)] = e.tenant

    val_objs = _discriminating_values(exchanges, _cid)

    def emit(f: CorroboratedFinding):
        if f.key in seen:
            return
        seen.add(f.key)
        out.append(f)

    for e in exchanges:
        if not e.ok or not e.object_id:
            continue
        owner = owner_of.get(_cid(e.object_id), "")

        # (1) READ-BOLA corroborated by a shared discriminating value
        if owner and e.principal != owner and not e.owned:
            # a discriminating value present in BOTH this (attacker) response and
            # object-specific (appears for <=2 objects => not a shared default)
            shared = sorted(str(v) for v in e.response_fields.values()
                            if _looks_discriminating(v) and str(v) in val_objs
                            and len(val_objs[str(v)]) <= 2)
            if shared:
                emit(CorroboratedFinding(
                    family="read_bola", object_id=e.object_id, owner=owner,
                    attacker=e.principal, endpoint_key=e.endpoint_key,
                    evidence=f"reproduced owner-specific value(s) {shared[:2]} for {e.object_id}",
                    severity="high",
                    cert={"proof": "non-owner response reproduced an object-specific private "
                                   "value (value-presence Δstate) — corroborated from capture, 0 requests",
                          "object": e.object_id, "owner": owner, "attacker": e.principal,
                          "replayable": True, "write_safe": True}))

        # (2) TENANT corroborated
        t_obj = tenant_of.get(_cid(e.object_id), "")
        if t_obj and e.tenant and e.tenant != t_obj and not e.owned:
            emit(CorroboratedFinding(
                family="tenant", object_id=e.object_id, owner=owner or f"tenant:{t_obj}",
                attacker=e.principal, endpoint_key=e.endpoint_key,
                evidence=f"principal in tenant {e.tenant} received object of tenant {t_obj}",
                severity="critical",
                cert={"proof": "cross-tenant object delivered to a foreign-tenant principal "
                               "— corroborated from capture, 0 requests",
                      "object": e.object_id, "foreign_tenant": e.tenant, "owner_tenant": t_obj,
                      "replayable": True, "write_safe": True}))

        # (3) BOPLA corroborated: client SENT a server-authoritative field and the
        # response REFLECTED that exact value (the server accepted a field it shouldn't)
        if e.mutating:
            for name, val in e.request_fields.items():
                low = name.lower()
                if low in schema.server_auth_fields:
                    reflected = any(str(rv) == str(val) for rk, rv in e.response_fields.items()
                                    if rk.lower() == low)
                    if reflected:
                        emit(CorroboratedFinding(
                            family="bopla_field", object_id=e.object_id or "(new)",
                            owner=owner or e.principal, attacker=e.principal,
                            endpoint_key=e.endpoint_key,
                            evidence=f"server accepted & reflected client-set server-authoritative '{name}={val}'",
                            severity="high",
                            cert={"proof": f"client set server-authoritative field '{name}' and the "
                                           f"server reflected it (BOPLA) — corroborated from capture, 0 requests",
                                  "field": name, "value": str(val), "replayable": True, "write_safe": True}))

        # (4) ACTION-BOLA corroborated: a NON-owner performed a MUTATING action on a
        # holder's object and the server ACCEPTED & REFLECTED it (2xx + echoed value) ->
        # a cross-user STATE CHANGE proven from capture, 0 requests. The effect is read
        # from the DATAFLOW (the fields the action actually changed), not from the verb
        # name; the finding's safety/severity come from the action's reversibility. A
        # mutation with no echoed field stays a live LEAD (honest floor — deletion etc.
        # cannot be proven from capture alone).
        if e.mutating and owner and e.principal != owner and not e.owned:
            from .relation_model import action_safety
            changed = sorted(f"{k}={v}" for k, v in e.request_fields.items()
                             if any(rk.lower() == k.lower() and str(rv) == str(v)
                                    for rk, rv in e.response_fields.items()))
            if changed:
                safety = action_safety(e.method, e.endpoint_key.split(" ", 1)[-1])
                emit(CorroboratedFinding(
                    family="action_bola", object_id=e.object_id, owner=owner,
                    attacker=e.principal, endpoint_key=e.endpoint_key,
                    evidence=(f"non-owner {e.principal} mutated {owner}'s object {e.object_id} "
                              f"(2xx); server echoed {changed[:2]}"),
                    severity=("critical" if safety == "irreversible" else "high"),
                    cert={"proof": "a non-owner's mutating action was accepted on a holder's "
                                   "object and the change was reflected (cross-user state change) "
                                   "— corroborated from capture, 0 requests",
                          "object": e.object_id, "owner": owner, "attacker": e.principal,
                          "changed": changed[:3], "action_safety": safety,
                          "replayable": True,
                          "write_safe": safety in ("reversible", "compensating")}))

    out.sort(key=lambda f: (f.family, f.object_id, f.attacker))
    return out
