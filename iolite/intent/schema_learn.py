"""
schema_learn.py — LEARN the target's own authorization schema from evidence, instead
of matching a hardcoded English wordlist.

This is the direct answer to the sharpest critique of v1.15: "role/status/owner_id" word
lists are themselves a known-shape heuristic — blind to a target whose fields are
`propietario`, `estado`, `nivel`, or `x7`. Here nothing is matched by name; field
SEMANTICS are inferred from how values actually behave across the operator's own
principals and across an object's life:

  * IDENTITY / OWNERSHIP field — its value is constant within one principal and differs
    across principals (it encodes WHO), i.e. it partitions the captures by identity.
  * SERVER-AUTHORITATIVE field — it appears in RESPONSES but the client never sends it
    on writes (the server owns it). Accepting it on a write is BOPLA — by definition,
    not by name.
  * STATE field — low-cardinality value drawn from a small enum that CHANGES over an
    object's life. Its TERMINAL states are learned as the absorbing nodes of the observed
    transition graph (a state after which no mutation is ever observed) — language-
    agnostic workflow-context detection.
  * PRIVILEGE field — an enum whose top value is held by exactly the principal(s) with
    the most privilege-guarded reach.

The wordlist stays only as a weak PRIOR; learned evidence overrides it. Deterministic
(QL4). Pure-stdlib.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LearnedSchema:
    ownership_fields: set = field(default_factory=set)       # encode identity
    server_auth_fields: set = field(default_factory=set)     # server sets, client can't
    state_fields: set = field(default_factory=set)
    terminal_states: set = field(default_factory=set)        # absorbing states (language-agnostic)
    privilege_fields: set = field(default_factory=set)
    field_values: dict = field(default_factory=dict)         # field -> sorted distinct values (evidence)

    def classify(self, name: str) -> str:
        low = str(name).lower()
        if low in self.server_auth_fields:
            return "server_auth"
        if low in self.ownership_fields:
            return "ownership"
        return "plain"


def _is_scalar(v):
    return isinstance(v, (str, int, float, bool))


def learn_schema(exchanges, *, priv_scores: dict | None = None) -> LearnedSchema:
    """Infer field semantics from CapturedExchange evidence. No field is classified by
    its NAME — only by how its values behave. Deterministic."""
    s = LearnedSchema()
    priv_scores = priv_scores or {}

    # gather per-field: values, which principals carried each value, request vs response
    seen_in_request: dict = {}     # field -> set of (endpoint, principal)
    seen_in_response: dict = {}    # field -> set of endpoints
    field_to_values: dict = {}     # field -> set(values)
    field_principal_value: dict = {}  # field -> {principal: set(values)}

    for e in exchanges:
        for name, val in e.request_fields.items():
            if not _is_scalar(val):
                continue
            low = name.lower()
            seen_in_request.setdefault(low, set()).add((e.endpoint_key, e.principal))
            field_to_values.setdefault(low, set()).add(str(val))
            field_principal_value.setdefault(low, {}).setdefault(e.principal, set()).add(str(val))
        for name, val in e.response_fields.items():
            if not _is_scalar(val):
                continue
            low = name.lower()
            seen_in_response.setdefault(low, set()).add(e.endpoint_key)
            field_to_values.setdefault(low, set()).add(str(val))
            field_principal_value.setdefault(low, {}).setdefault(e.principal, set()).add(str(val))

    # per-object-per-field distinct values over time — the signature of a STATE field is
    # that the SAME object takes different values of it across its life.
    obj_field_values: dict = {}     # (object_id, field) -> set(values)
    for e in sorted(exchanges, key=lambda x: x.seq):
        for src in (e.request_fields, e.response_fields):
            for name, val in src.items():
                if _is_scalar(val) and e.object_id:
                    obj_field_values.setdefault((e.object_id, name.lower()), set()).add(str(val))
    fields_that_change = {f for (oid, f), vs in obj_field_values.items() if len(vs) >= 2}

    for fname, values in field_to_values.items():
        s.field_values[fname] = sorted(values)
        pv = field_principal_value.get(fname, {})

        # SERVER-AUTHORITATIVE: in responses, never in any client request
        if fname in seen_in_response and fname not in seen_in_request:
            s.server_auth_fields.add(fname)

        # OWNERSHIP / IDENTITY: each principal carries a DISTINCT, stable value set and
        # the per-principal sets are (near) disjoint across principals -> encodes identity
        if len(pv) >= 2:
            sets = list(pv.values())
            disjoint = all(not (sets[i] & sets[j])
                           for i in range(len(sets)) for j in range(i + 1, len(sets)))
            stable = all(len(vs) <= 2 for vs in sets)      # each principal ~one value
            if disjoint and stable:
                s.ownership_fields.add(fname)

        # STATE: low-cardinality enum (<=8 distinct) that CHANGES for the same object
        # over its life (the defining property — excludes constant secrets/ids/owners)
        if 2 <= len(values) <= 8 and fname in fields_that_change:
            s.state_fields.add(fname)

        # PRIVILEGE: some enum value is carried ONLY by the most-privileged principal(s)
        if 2 <= len(values) <= 8 and priv_scores:
            top = max(priv_scores.values(), default=0)
            top_p = {p for p, sc in priv_scores.items() if sc == top and top > 0}
            low_values = set().union(*(vs for p, vs in pv.items() if p not in top_p)) if top_p else set()
            top_only = set().union(*(vs for p, vs in pv.items() if p in top_p)) - low_values
            if top_p and top_only:
                s.privilege_fields.add(fname)

    s.terminal_states = _absorbing_states(exchanges, s.state_fields)
    return s


def _absorbing_states(exchanges, state_fields) -> set:
    """A state value is TERMINAL (absorbing) when it is the TARGET of an observed
    transition (an object changed INTO it) and NO later mutation on that object is ever
    observed. Being merely an initial value that happens to see no mutation does NOT make
    it terminal. This learns 'archived/closed/revoked' with zero English knowledge —
    purely from the shape of the observed lifecycle graph. Deterministic."""
    if not state_fields:
        return set()
    # per object: ordered timeline of (seq, state_value, mutating)
    timeline: dict = {}
    for e in sorted(exchanges, key=lambda x: x.seq):
        if not e.object_id:
            continue
        st = None
        for src in (e.response_fields, e.request_fields):
            for k, v in src.items():
                if k.lower() in state_fields:
                    st = str(v)
                    break
            if st is not None:
                break
        if st is not None:
            timeline.setdefault(e.object_id, []).append((e.seq, st, e.mutating))

    transition_targets = set()        # values reached via an actual change
    for events in timeline.values():
        events.sort()
        prev = None
        for _, st, _ in events:
            if prev is not None and st != prev:
                transition_targets.add(st)
            prev = st

    candidates = set(transition_targets)
    # drop any value that has a later mutation on the same object after it is reached
    for events in timeline.values():
        events.sort()
        reached_at = {}
        for seq, st, _ in events:
            reached_at.setdefault(st, seq)
        for seq, _st, mut in events:
            if not mut:
                continue
            for value, first_seq in reached_at.items():
                if first_seq < seq:
                    candidates.discard(value)
    return candidates
