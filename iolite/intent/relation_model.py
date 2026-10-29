"""
relation_model.py — the AUTHORIZATION LATTICE (relational intent, Zanzibar-shaped).

The whole-tool leap of v1.15.0. Every prior intent model in IOLITE is PER-ENDPOINT
(endpoint_key -> AccessClass). But the way hyperscale targets actually DECIDE
authorization is relational: a derivation over (principal, relation, object, field,
state, tenant) — the Google-Zanzibar shape `object#relation@user`, usersets, and
rewrite rules (union / intersection / EXCLUSION) computed by graph traversal.

The authorization bugs that still pay on mature targets (the ones every scanner has
already swept for the trivial `GET /obj/{id}` substitution) live in the dimensions a
class-per-endpoint CANNOT express:

  * ACTION      write / delete / trigger on another's object. 41.7% of real BOLA;
                scanners test the read path only and miss ~46% of cases.
  * FIELD       a server-authoritative property (role, price, owner_id, status) the
                owner must not set (BOPLA), or a client-supplied ownership field the
                server trusts (object rebinding).
  * STATE       access that must be EXCLUDED once an object is archived / revoked /
                closed (workflow-context; the Zanzibar "new-enemy" exclusion).
                Stateless scanners cannot see it.
  * TENANT      crossing an org / workspace boundary (namespace isolation).
  * DERIVATION  a permission reachable only along a PATH (parent->child, group
                membership, an id harvested at A and used at B = chained).

This module lifts intent from a class-per-endpoint to a derivation over that whole
tuple space, built ONLY from evidence the target legally exposes (what each of the
operator's own principals legitimately held / saw, the client's own guards, the
object graph). It STATES intent; it never probes and never decides (QL5). Raise-only
/ least-privilege by construction (same safety as reason.intent_graph): it can only
reduce missed hypotheses, never silence a real one — so it cannot create a false
positive on its own (ONYX / the metamorphic oracle still DISPOSES).

Deterministic, pure-stdlib (QL4). No LLM / ML in the decision path.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from ..models import SurfaceModel
from ..reason.intent import AccessClass, RANK, infer_intent
from ..surface_model import privilege_scores

# --------------------------------------------------------------------------- #
# vocabulary (the "rewrite rules" inputs) — deterministic, auditable word sets #
# --------------------------------------------------------------------------- #

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"          # insufficient evidence -> a LEAD, never a claim


class Action(str, Enum):
    READ = "read"
    CREATE = "create"
    WRITE = "write"
    DELETE = "delete"


_ACTION_RANK = {Action.READ: 0, Action.CREATE: 1, Action.WRITE: 2, Action.DELETE: 3}
_METHOD_ACTION = {
    "GET": Action.READ, "HEAD": Action.READ, "OPTIONS": Action.READ,
    "POST": Action.CREATE, "PUT": Action.WRITE, "PATCH": Action.WRITE,
    "DELETE": Action.DELETE,
}

# server-authoritative fields: the OWNER must not be able to set these (BOPLA / API3).
_SERVER_AUTH_FIELDS = (
    "role", "roles", "is_admin", "isadmin", "admin", "is_superuser", "superuser",
    "is_staff", "staff", "internal", "scope", "scopes", "permission", "permissions",
    "grant", "grants", "plan", "subscription", "price", "amount", "balance", "credit",
    "cost", "total", "discount", "fee", "status", "state", "verified", "is_verified",
    "approved", "is_active", "enabled", "quota", "limit", "tier", "level", "rank",
)
# ownership fields: if client-supplied and trusted, the object is REBOUND to another owner.
_OWNERSHIP_FIELDS = (
    "owner_id", "owner", "ownerid", "user_id", "userid", "account_id", "account",
    "tenant_id", "org_id", "organization_id", "organisation_id", "workspace_id",
    "team_id", "created_by", "createdby", "sender", "sender_id", "author_id",
    "customer_id", "assignee_id", "assignee",
)
# terminal / excluded lifecycle states: access must be EXCLUDED here (workflow-context).
_EXCLUDED_STATES = (
    "archived", "deleted", "removed", "revoked", "closed", "cancelled", "canceled",
    "suspended", "expired", "inactive", "disabled", "banned", "frozen", "terminated",
    "void", "refunded", "locked", "deactivated", "retired", "withdrawn",
)
_STATE_FIELDS = ("status", "state", "lifecycle", "stage", "phase")
_TENANT_FIELDS = ("tenant_id", "org_id", "organization_id", "organisation_id",
                  "workspace_id", "team_id", "account_id", "company_id")
_GENERIC_SEG = {"api", "v1", "v2", "v3", "v4", "rest", "graphql", "gql", "bff",
                "gateway", "service", "services", "me", "self", "current", "app",
                "web", "public", "static", "u", "a"}


def _classify_field(name: str, schema=None) -> str:
    """Classify a field. LEARNED evidence (schema) wins over the English wordlist — so a
    target whose fields are `propietario` / `nivel` is still understood. The wordlist is
    only a prior for when there is no behavioural evidence yet."""
    low = str(name).strip().lower()
    if schema is not None:
        learned = schema.classify(low)              # server_auth | ownership | plain
        if learned != "plain":
            return learned
    if low in _OWNERSHIP_FIELDS or any(low == o for o in _OWNERSHIP_FIELDS):
        return "ownership"
    if low in _SERVER_AUTH_FIELDS or any(w == low for w in _SERVER_AUTH_FIELDS):
        return "server_auth"
    # substring fallbacks for common compound names (admin_flag, user_role, ...)
    if any(w in low for w in ("admin", "role", "price", "balance", "permission",
                              "is_verified", "status", "superuser")):
        return "server_auth"
    if any(w in low for w in ("owner", "account_id", "tenant", "created_by")):
        return "ownership"
    return "plain"


def _excluded_state(value) -> bool:
    return str(value).strip().lower() in _EXCLUDED_STATES


def _obj_type_of_path(path: str) -> str:
    """The distinctive object-type token: last non-templated, non-generic segment."""
    best = ""
    for seg in str(path).split("/"):
        s = seg.strip().lower()
        if not s or s.startswith("{") or s.startswith(":") or s in _GENERIC_SEG:
            continue
        if len(s) >= 3 and s.isascii() and s.isalpha():
            best = s.rstrip("s") if len(s) > 4 and s.endswith("s") else s
    return best


def action_of_method(method: str) -> Action:
    return _METHOD_ACTION.get(str(method).upper(), Action.WRITE)


# RPC-style action verbs. The L2 seam: a request's EFFECT is read from WHAT it
# addresses, not from the HTTP verb's NAME. A POST is a CREATE on a collection, but a
# POST that addresses an EXISTING object (…/{id}/refund) or carries an action verb is a
# WRITE/trigger on a foreign object — the dominant shape of the "trigger cross-user"
# half of the 41.7% action-BOLA family, and exactly the surface the generator missed.
# The id-presence rule is language-agnostic and primary; the verb list is a
# deterministic prior for id-less sub-actions (…/orders/bulk/cancel). Extend freely —
# a false "action" only ever adds a candidate the sound oracle discards; it can never
# fabricate a finding (QL5).
_ACTION_VERBS = frozenset((
    "refund", "cancel", "approve", "reject", "promote", "demote", "transfer",
    "send", "resend", "capture", "void", "revoke", "grant", "invite", "assign",
    "unassign", "share", "unshare", "publish", "unpublish", "archive", "unarchive",
    "restore", "retry", "disable", "enable", "lock", "unlock", "close", "reopen",
    "submit", "confirm", "ban", "unban", "suspend", "activate", "deactivate",
    "impersonate", "sudo", "export", "sync", "trigger", "execute", "run", "apply",
    "redeem", "verify", "unverify", "complete", "fulfill", "fulfil", "ship", "pay",
    "charge", "settle", "withdraw", "deposit", "escalate", "release", "rotate",
    "reset", "renew", "upgrade", "downgrade", "subscribe", "unsubscribe", "follow",
    "unfollow", "block", "unblock", "mute", "unmute", "disconnect", "detach", "attach",
))

_ID_SEG = re.compile(r"\{[^}/]+\}|:[A-Za-z_][A-Za-z0-9_]*")


def _has_templated_id(path: str) -> bool:
    return bool(_ID_SEG.search(str(path)))


def post_is_action(path: str) -> bool:
    """True when a POST addresses an EXISTING object (an action / trigger), False when it
    creates into a collection. Deterministic, language-pragmatic:
      • a templated id segment (…/{id}/…) ⇒ acts on an existing object ⇒ True;
      • else the last segment is an action verb AND a non-generic resource segment
        precedes it (…/orders/bulk/cancel) ⇒ True;
      • a bare collection (/api/orders, /api/transfer) ⇒ False (a create — the
        BOPLA/rebinding field families own it, not action-BOLA)."""
    if _has_templated_id(path):
        return True
    segs = [s for s in str(path).split("/") if s]
    if not segs:
        return False
    if segs[-1].strip().lower() in _ACTION_VERBS:
        for s in segs[:-1]:
            t = s.strip().lower()
            if t and not t.startswith(("{", ":")) and t not in _GENERIC_SEG:
                return True
    return False


def resource_type_of(path: str) -> str:
    """The object-TYPE an endpoint acts on, verb/id-aware: the type of the path PREFIX up
    to the first templated id (so POST /orders/{id}/cancel acts on 'order', never creates
    a 'cancel'); else the id-less prefix with a trailing action verb stripped. Additive —
    it never changes the global `_obj_type_of_path` used elsewhere."""
    raw = str(path)
    m = _ID_SEG.search(raw)
    if m:
        t = _obj_type_of_path(raw[:m.start()])
        if t:
            return t
    segs = [s for s in raw.split("/") if s]
    if segs and segs[-1].strip().lower() in _ACTION_VERBS:
        segs = segs[:-1]
    return _obj_type_of_path("/".join(segs))


# Reversibility of a mutating action — the Leap-1 safety tag the EMITTED candidate must
# carry so Scope-Guard / dry-run / the metamorphic oracle can decide safe confirmation
# BEFORE any packet, and so the scheduler can prefer reversible-first. Fail-closed: an
# unrecognised mutation is "unknown" (treated as UNSAFE), never silently reversible.
#   • irreversible  — a real-world or hard-to-undo side effect (money, send, destroy,
#                     privilege grant/revoke, credential reset, data export). Auto-confirm
#                     REFUSED; only an explicit operator opt-in may touch it.
#   • compensating  — a clear inverse exists in the surface (enable↔disable, follow↔unfollow)
#                     so a confirmed write can be net-zero restored by the oracle.
#   • reversible    — a plain-field write whose prior value restores it (PATCH/PUT of a field).
#   • unknown       — an unrecognised action verb -> unsafe by default.
_IRREVERSIBLE_VERBS = frozenset((
    "transfer", "pay", "charge", "refund", "withdraw", "deposit", "settle", "send",
    "resend", "publish", "submit", "confirm", "fulfill", "fulfil", "ship", "redeem",
    "capture", "escalate", "impersonate", "sudo", "grant", "revoke", "reset", "rotate",
    "export", "execute", "run", "trigger", "ban", "suspend", "deactivate", "terminate",
    "purge", "wipe", "close", "void", "release", "renew", "upgrade", "downgrade",
    "promote", "demote", "approve", "reject",
))
_COMPENSATING_VERBS = frozenset((
    "enable", "disable", "lock", "unlock", "block", "unblock", "mute", "unmute",
    "follow", "unfollow", "subscribe", "unsubscribe", "assign", "unassign", "share",
    "unshare", "archive", "unarchive", "attach", "detach", "connect", "disconnect",
    "like", "unlike", "pin", "unpin", "activate", "restore", "reopen", "retry",
))


def _trailing_verb(path: str) -> str:
    for seg in reversed([s for s in str(path).split("/") if s]):
        t = seg.strip().lower()
        if t.startswith(("{", ":")):
            continue
        return t if t in _ACTION_VERBS else ""
    return ""


def action_safety(method: str, path: str = "", field_class: str = "") -> str:
    """Classify the reversibility of a mutating request from its VERB semantics, not just
    its HTTP method. Deterministic, fail-closed."""
    m = str(method).upper()
    if m in ("GET", "HEAD", "OPTIONS"):
        return "reversible"                       # a read changes no state
    verb = _trailing_verb(path)
    if m == "DELETE" or verb in _IRREVERSIBLE_VERBS:
        return "irreversible"
    if verb in _COMPENSATING_VERBS:
        return "compensating"
    if m in ("PATCH", "PUT") and not verb:
        return "reversible"                       # a field write is net-zero restorable
    return "unknown"                              # unrecognised trigger -> unsafe by default


# --------------------------------------------------------------------------- #
# facts assembled from the real SurfaceModel                                   #
# --------------------------------------------------------------------------- #

@dataclass
class TypeFacts:
    name: str
    fields: dict = field(default_factory=dict)     # field_name -> "server_auth"|"ownership"|"plain"
    methods: set = field(default_factory=set)       # HTTP methods observed on this type
    endpoints: set = field(default_factory=set)     # endpoint keys of this type
    states: set = field(default_factory=set)        # lifecycle state values observed


@dataclass
class ObjectFacts:
    oid: str
    otype: str = ""
    holders: set = field(default_factory=set)       # principals that legitimately held it
    tenant: str = ""
    state: str = ""                                  # last observed lifecycle state


@dataclass
class Lattice:
    """The relational intent model. Pure data + a single derivation function."""
    base_url: str
    intent: dict                                     # endpoint_key -> IntentRule (refined/joint)
    types: dict                                      # type_name -> TypeFacts
    objects: dict                                    # oid -> ObjectFacts
    principal_tenant: dict                           # pid -> tenant (best-effort)
    principal_priv: dict                             # pid -> privilege score
    all_pids: list
    terminal_states: set = field(default_factory=set)  # LEARNED absorbing states (language-agnostic)

    # -- helpers ------------------------------------------------------------- #
    def type_of_endpoint(self, key: str) -> str:
        path = key.split(" ", 1)[1] if " " in key else key
        return _obj_type_of_path(path)

    def _is_excluded(self, state) -> bool:
        """A terminal lifecycle state: a hardcoded prior OR one LEARNED from the observed
        transition graph (works for `archivado`/`清算`/any language)."""
        return _excluded_state(state) or str(state).strip().lower() in {
            str(s).strip().lower() for s in self.terminal_states}

    def _base_class(self, endpoint_key: str, otype: str) -> AccessClass:
        """Intended class for a request: the per-endpoint rule, floored by any
        sibling of the same object-type that intent rates stricter (cross-surface
        owner floor — a Zanzibar-style type-level rewrite)."""
        rule = self.intent.get(endpoint_key)
        cls = rule.access_class if rule else AccessClass.UNKNOWN
        best = RANK.get(cls, -1)
        for k2, r2 in self.intent.items():
            if self.type_of_endpoint(k2) == otype and otype and r2.rank > best:
                best, cls = r2.rank, r2.access_class
        return cls

    # -- the one derivation (intent says: may `principal` do `action`?) ------ #
    def intended_decision(self, principal: str, action: Action, *, endpoint_key: str = "",
                          oid: str = "", field_name: str = "", field_value=None,
                          state: str = "") -> tuple[Decision, str]:
        """Return (Decision, derivation) for whether INTENT permits `principal` to
        perform `action` (on object `oid`, optionally setting `field_name`, with the
        object in `state`). DENY = intent means to keep this principal out here —
        i.e. a divergence candidate IF the implementation turns out to allow it.
        Raise-only: every rule can only move toward DENY."""
        otype = self.type_of_endpoint(endpoint_key) if endpoint_key else ""
        obj = self.objects.get(str(oid)) if oid else None

        # (S) STATE EXCLUSION — the "new-enemy" rewrite: a terminal lifecycle state
        # excludes access regardless of ownership (workflow-context family).
        st = state or (obj.state if obj else "")
        if st and self._is_excluded(st) and action != Action.READ:
            return (Decision.DENY,
                    f"state-exclusion: object is '{st}' (terminal) -> mutating action "
                    f"must be excluded once the lifecycle closed (Zanzibar exclusion / workflow-context)")

        # (F) FIELD — server-authoritative property the owner must not set (BOPLA),
        # or a client-supplied ownership field that rebinds the object (rebinding).
        if field_name:
            fclass = self.types.get(otype, TypeFacts(otype)).fields.get(
                str(field_name).lower(), _classify_field(field_name))
            if fclass == "server_auth" and action in (Action.WRITE, Action.CREATE):
                return (Decision.DENY,
                        f"field '{field_name}' is server-authoritative -> not owner-writable "
                        f"(BOPLA / API3:2023); only the server may set it")
            if fclass == "ownership" and action in (Action.WRITE, Action.CREATE):
                # setting an ownership field to someone else = object rebinding
                if field_value is not None and str(field_value) and principal not in (
                        self._principals_named(field_value)):
                    return (Decision.DENY,
                            f"ownership field '{field_name}={field_value}' is client-supplied -> "
                            f"server must not trust it to reassign ownership (object rebinding)")

        # (A) ACTION-LIFTED OWNERSHIP — the core derivation. write >= read: a mutating
        # action on an addressable object is at least as restricted as reading it.
        cls = self._base_class(endpoint_key, otype)
        mutating = _ACTION_RANK[action] >= _ACTION_RANK[Action.CREATE]
        if mutating and oid and RANK.get(cls, -1) < RANK[AccessClass.OWNER_ONLY]:
            cls = AccessClass.OWNER_ONLY  # write>=read lift (action-level family)

        if cls == AccessClass.OWNER_ONLY:
            if obj is None:
                return (Decision.UNKNOWN, "owner-scoped but object ownership unobserved -> lead")
            if principal in obj.holders:
                return (Decision.ALLOW, f"{principal} is a legitimate holder of {oid}")
            verb = action.value
            return (Decision.DENY,
                    f"owner-scoped ({verb}): {oid} held by {sorted(obj.holders)}, "
                    f"{principal} is not a holder -> intent denies {verb}")

        if cls == AccessClass.TENANT_ISOLATED:
            if obj is None or not obj.tenant:
                return (Decision.UNKNOWN, "tenant-isolated but object tenant unobserved -> lead")
            ptenant = self.principal_tenant.get(principal, "")
            if ptenant and ptenant == obj.tenant:
                return (Decision.ALLOW, f"{principal} is in the owning tenant {obj.tenant}")
            return (Decision.DENY,
                    f"tenant-isolated: {oid} belongs to tenant {obj.tenant}; {principal} "
                    f"(tenant {ptenant or '?'}) is outside it -> cross-tenant denied")

        if RANK.get(cls, -1) >= RANK[AccessClass.ROLE_RESTRICTED]:
            hi = self.principal_priv.get(principal, 0)
            maxp = max(self.principal_priv.values(), default=0)
            if hi >= maxp and maxp > 0:
                return (Decision.ALLOW, f"{principal} holds the privilege this guards")
            return (Decision.DENY,
                    f"{cls.value}: function-level privilege required; {principal} is "
                    f"under-privileged (priv={hi} < {maxp}) -> BFLA target")

        if cls in (AccessClass.AUTHENTICATED, AccessClass.PUBLIC):
            return (Decision.ALLOW, f"intent is {cls.value} -> not an authorization boundary")
        return (Decision.UNKNOWN, "no intent signal on this surface -> lead")

    def _principals_named(self, value) -> set:
        """Principals whose id/label matches a field value (so 'owner_id=self' is ALLOW)."""
        v = str(value).strip().lower()
        out = set()
        for pid in self.all_pids:
            if pid.lower() == v:
                out.add(pid)
        return out


# --------------------------------------------------------------------------- #
# builder — assemble the lattice from a real SurfaceModel                       #
# --------------------------------------------------------------------------- #

def _iter_body_fields(body):
    """Yield (name, value) for every scalar field in a request body dict (one level,
    plus a shallow descent into a single nested dict — enough for real API bodies)."""
    if isinstance(body, dict):
        for k, v in body.items():
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    if not isinstance(v2, (dict, list)):
                        yield k2, v2
            elif not isinstance(v, list):
                yield k, v


def build_lattice(model: SurfaceModel, *, rich: bool = True, schema=None,
                  exchanges=None) -> Lattice:
    """Build the relational intent lattice from the acquired surface. Deterministic.

    `schema` / `exchanges` (v1.16): when response-bearing exchanges are available, the
    field/state semantics are LEARNED from the data (schema_learn) and override the
    English wordlist — so the lattice understands a target in any language/vocabulary."""
    intent = infer_intent(model, joint=rich)
    priv = privilege_scores(model)
    all_pids = sorted(p.pid for p in model.principals)

    if schema is None and exchanges:
        from .schema_learn import learn_schema
        schema = learn_schema(exchanges, priv_scores=priv)
    terminal = set(getattr(schema, "terminal_states", set()) or set())

    types: dict = {}
    objects: dict = {}

    def _type(name: str) -> TypeFacts:
        return types.setdefault(name, TypeFacts(name))

    # endpoints -> type methods + fields from params
    for key, ep in model.endpoints.items():
        otype = _obj_type_of_path(ep.path)
        if not otype:
            continue
        tf = _type(otype)
        tf.methods.add(ep.method.upper())
        tf.endpoints.add(key)
        for pname in ep.params:
            tf.fields.setdefault(str(pname).lower(), _classify_field(pname, schema))

    # observed accesses -> holders, fields, states, tenants
    principal_tenant: dict = {}
    for acc in model.accesses:
        otype = _obj_type_of_path(acc.path)
        tf = _type(otype) if otype else None
        for oid in (acc.all_ids or [acc.object_id]):
            if not oid:
                continue
            of = objects.setdefault(str(oid), ObjectFacts(str(oid), otype))
            of.holders.add(acc.principal_id)
            if otype and not of.otype:
                of.otype = otype
        # mine fields / state / tenant from the request body
        for name, value in _iter_body_fields(acc.body):
            low = str(name).lower()
            if tf is not None:
                tf.fields.setdefault(low, _classify_field(name, schema))
            if low in _STATE_FIELDS and value:
                if tf is not None:
                    tf.states.add(str(value).lower())
                for oid in (acc.all_ids or [acc.object_id]):
                    if oid and str(oid) in objects:
                        objects[str(oid)].state = str(value).lower()
            if low in _TENANT_FIELDS and value:
                principal_tenant.setdefault(acc.principal_id, str(value))
                for oid in (acc.all_ids or [acc.object_id]):
                    if oid and str(oid) in objects and not objects[str(oid)].tenant:
                        objects[str(oid)].tenant = str(value)

    # holdings may carry objects not seen in accesses (e.g. from carriers)
    for oid, holders in model.holdings.items():
        of = objects.setdefault(str(oid), ObjectFacts(str(oid)))
        of.holders |= set(holders)

    # v1.16: fold response-bearing exchanges in — learned server-authoritative fields
    # (seen only in responses) and observed object STATE land here so BOPLA/workflow
    # families fire from real evidence, not a wordlist.
    for e in (exchanges or []):
        otype = _obj_type_of_path(e.endpoint_key.split(" ", 1)[-1])
        if otype:
            tf = _type(otype)
            tf.methods.add(e.method.upper())
            for src in (e.request_fields, e.response_fields):
                for name in src:
                    tf.fields.setdefault(str(name).lower(), _classify_field(name, schema))
        # object state from the (learned) state fields
        oid = str(e.object_id)
        if oid and oid in objects:
            for src in (e.response_fields, e.request_fields):
                for name, val in src.items():
                    if name.lower() in (getattr(schema, "state_fields", set()) or set()):
                        objects[oid].state = str(val)
            if e.tenant and not objects[oid].tenant:
                objects[oid].tenant = e.tenant

    return Lattice(base_url=model.base_url, intent=intent, types=types, objects=objects,
                   principal_tenant=principal_tenant, principal_priv=priv, all_pids=all_pids,
                   terminal_states=terminal)


def summarize(lat: Lattice) -> dict:
    """A compact, human-checkable view of the lattice (for the report / dossier)."""
    server_auth = sorted({f"{t}.{n}" for t, tf in lat.types.items()
                          for n, c in tf.fields.items() if c == "server_auth"})
    ownership = sorted({f"{t}.{n}" for t, tf in lat.types.items()
                        for n, c in tf.fields.items() if c == "ownership"})
    excluded = sorted({f"{o.otype or '?'}:{o.state}" for o in lat.objects.values()
                       if o.state and _excluded_state(o.state)})
    return {
        "object_types": sorted(lat.types),
        "objects": len(lat.objects),
        "server_authoritative_fields": server_auth,
        "ownership_fields": ownership,
        "excluded_state_objects": excluded,
        "tenants": sorted({o.tenant for o in lat.objects.values() if o.tenant}),
        "principals": lat.all_pids,
    }


# --------------------------------------------------------------------------- #
# typed privilege — the SUBJECT operand of the authz decision, per DOMAIN      #
# --------------------------------------------------------------------------- #
# A single `privilege_scores` scalar flattens authority: a principal that is an admin of
# ONE resource type and a nobody in another is scored by one number, so a domain-scoped
# BFLA (under-privileged for THIS resource's function, yet globally high) is invisible —
# the global comparison clears it. These read privilege PER resource-type instead.

def privilege_by_type(model) -> dict:
    """priv[pid][otype] = # of distinct privilege-guarded endpoints of that resource type
    this principal legitimately reached. A measured fact (RL1), never assumed."""
    from ..surface_model import _is_privileged
    per: dict = {p.pid: {} for p in model.principals}
    for acc in model.accesses:
        ep = model.endpoints.get(acc.endpoint_key)
        if ep and _is_privileged(ep) and acc.principal_id in per:
            t = _obj_type_of_path(ep.path) or "(global)"
            per[acc.principal_id][t] = per[acc.principal_id].get(t, 0) + 1
    return per


def vertical_candidates_typed(model) -> list:
    """BFLA candidates a FLAT privilege score hides: a principal under-privileged in the
    guarded endpoint's OWN resource type (even if globally high) must be denied that type's
    privileged function. Raise-only — it only ADDS candidates the scalar missed; the sound
    oracle still DISPOSES. Deterministic. Own principals only (QL6)."""
    from ..surface_model import _is_privileged, BolaCandidate
    pbt = privilege_by_type(model)
    out, seen = [], set()
    for acc in model.accesses:
        if not acc.safe_read:
            continue
        ep = model.endpoints.get(acc.endpoint_key)
        if not (ep and _is_privileged(ep)):
            continue
        t = _obj_type_of_path(ep.path) or "(global)"
        hp = pbt.get(acc.principal_id, {}).get(t, 0)
        attackers = sorted(q for q, m in pbt.items()
                           if q != acc.principal_id and m.get(t, 0) < hp)
        sig = (acc.endpoint_key, str(acc.object_id))
        if not attackers or sig in seen:
            continue
        seen.add(sig)
        out.append(BolaCandidate(
            endpoint_key=acc.endpoint_key, object_id=acc.object_id,
            holder_pid=acc.principal_id, probe_pids=attackers, path=acc.path,
            method=acc.method, query=dict(acc.query or {}), body=acc.body,
            carrier=acc.carrier, family="vertical"))
    out.sort(key=lambda c: (c.endpoint_key, str(c.object_id)))
    return out
