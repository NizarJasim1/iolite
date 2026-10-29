"""
reason · intent_graph — IntentGraph: reconstruct the developer's intent as the
TIGHTEST (least-privilege) policy consistent with ALL the evidence, across the whole
surface — not one endpoint at a time from a fixed word list.

Two ideas the per-endpoint first-match ladder cannot express:

  1. EVIDENCE COMBINATION. The strongest, target-specific intent signal is RELATIONAL
     and OBSERVED — the multi-principal capture's PARTITION structure (A sees object
     1001, B sees 2002, never each other's ⇒ owner-scoped) and the target's OWN
     learned privilege vocabulary. Grounded in least-privilege ABAC policy mining,
     inverted: we mine the tightest intent to CONTRAST with enforcement, not to
     reproduce it.

  2. MONOTONE STRUCTURAL PROPAGATION. Intent flows along SOUND relations, RAISE-ONLY:
       · write ≥ read              (mutating an object is ≥ as restricted as reading it)
       · cross-surface owner floor (an object-addressing surface mis-rated public,
                                    while a sibling proves the object is owner-scoped,
                                    is raised to OWNER — capped, never to ADMIN)
       · parent → child            (a sub-resource of a guarded resource is guarded)

SAFETY BY CONSTRUCTION: every operation can only RAISE intent, never lower it. So this
engine can only REDUCE false negatives (missed hypotheses) — it can never silence a
real bug by down-rating an endpoint to "public". Its worst case is over-classification
⇒ wasted probes (ONYX still guards validity ⇒ never a false positive). Sample-based
evidence (partition) only RAISES with confidence tied to sample size — never asserts,
never lowers (a sample is not a specification).

reason PROPOSES; ONYX DISPOSES (QL5). Deterministic (QL4). Opt-in, additive — the
default `infer_intent` path is unchanged.
"""

from __future__ import annotations

from .intent import AccessClass, RANK, IntentRule

_GENERIC = {"api", "v1", "v2", "v3", "rest", "graphql", "gql", "bff", "gateway",
            "service", "me", "self", "current", "app", "web", "public", "static"}
_MUTATING = ("POST", "PUT", "PATCH", "DELETE", "MUTATION")
_CONF = {"low": 0, "medium": 1, "high": 2}
_SEPARATES = {
    AccessClass.OWNER_ONLY: ("other-users",),
    AccessClass.TENANT_ISOLATED: ("other-tenants",),
    AccessClass.ROLE_RESTRICTED: ("lower-privilege-roles",),
    AccessClass.ADMIN_ONLY: ("non-admin-principals",),
}


def _obj_token(path: str) -> str:
    """The distinctive object-type token of a path (last non-templated, non-generic
    segment of length ≥4). Deterministic."""
    best = ""
    for seg in path.split("/"):
        s = seg.strip().lower()
        if not s or s.startswith("{") or s.startswith(":") or s in _GENERIC:
            continue
        if len(s) >= 4 and s.isascii():
            best = s
    return best


def _addresses_object(key: str) -> bool:
    return "{" in key or key.rstrip("/").count("/") >= 2


def _mutating(key: str) -> bool:
    return key.split(" ", 1)[0].upper() in _MUTATING


def _path_of(key: str) -> str:
    return key.split(" ", 1)[1] if " " in key else key


def _raise(rules: dict, key: str, cls: AccessClass, conf: str, signal: str) -> bool:
    """Monotone raise: only ever increases class (or confidence at equal class).
    Returns True if it changed the rule."""
    cur = rules.get(key)
    if cur is None:
        return False
    if RANK[cls] > cur.rank:
        rules[key] = IntentRule(cur.endpoint_key, cls, conf,
                                cur.signals + (signal,), cur.onyx_effect, cur.separates)
        return True
    if RANK[cls] == cur.rank and _CONF.get(conf, 0) > _CONF.get(cur.confidence, 0):
        rules[key] = IntentRule(cur.endpoint_key, cur.access_class, conf,
                                cur.signals + (signal,), cur.onyx_effect, cur.separates)
        return True
    return False


# --------------------------------------------------------------------------- #
# evidence: observed multi-principal partition (least-privilege owner signal)  #
# --------------------------------------------------------------------------- #

def _partition_evidence(model, rules: dict) -> None:
    by_key: dict[str, dict[str, set]] = {}
    for acc in model.accesses:
        ids = {str(i) for i in (acc.all_ids or [acc.object_id]) if i}
        if not ids:
            continue
        by_key.setdefault(acc.endpoint_key, {}).setdefault(acc.principal_id, set()).update(ids)
    for key in sorted(by_key):
        who = by_key[key]
        if len(who) < 2:
            continue
        sets = list(who.values())
        disjoint = all(not (sets[i] & sets[j])
                       for i in range(len(sets)) for j in range(i + 1, len(sets)))
        n_objs = len(set().union(*sets))
        if disjoint and n_objs >= 2:
            conf = "high" if n_objs >= 4 else "medium"
            _raise(rules, key, AccessClass.OWNER_ONLY, conf,
                   f"observed partition: {len(who)} principals hold {n_objs} disjoint "
                   f"objects here → owner-scoped (least-privilege, sample={n_objs})")


# --------------------------------------------------------------------------- #
# evidence: learned target-specific privilege vocabulary                       #
# --------------------------------------------------------------------------- #

def _learn_vocabulary(model, rules: dict) -> set[str]:
    priv: set[str] = set()
    for key, rule in rules.items():
        if rule.rank >= RANK[AccessClass.ROLE_RESTRICTED]:
            tok = _obj_token(_path_of(key))
            if len(tok) >= 5 and tok not in _GENERIC:
                priv.add(tok)
        ep = model.endpoints.get(key)
        if ep:
            for r in ep.role_hints:
                for t in r.lower().replace("-", " ").split():
                    if len(t) >= 5 and t not in _GENERIC:
                        priv.add(t)
    return priv


def _vocabulary_evidence(model, rules: dict, priv: set[str]) -> None:
    if not priv:
        return
    for key in sorted(rules):
        if rules[key].rank >= RANK[AccessClass.ROLE_RESTRICTED]:
            continue
        low = key.lower()
        hit = next((t for t in sorted(priv) if t in low), "")
        if hit:
            _raise(rules, key, AccessClass.ROLE_RESTRICTED, "medium",
                   f"learned target privilege vocabulary: '{hit}' (guarded elsewhere)")


# --------------------------------------------------------------------------- #
# monotone structural propagation (RAISE-only, sound relations, fixpoint)      #
# --------------------------------------------------------------------------- #

def _propagate_once(model, rules: dict) -> bool:
    changed = False
    keys = sorted(rules)

    # write ≥ read (same path template): raise mutating methods to the read's rank
    read_rank_by_path: dict[str, tuple[int, AccessClass]] = {}
    for key in keys:
        if not _mutating(key):
            path = _path_of(key)
            r = rules[key]
            cur = read_rank_by_path.get(path)
            if cur is None or r.rank > cur[0]:
                read_rank_by_path[path] = (r.rank, r.access_class)
    for key in keys:
        if _mutating(key):
            rr = read_rank_by_path.get(_path_of(key))
            if rr and rr[0] > rules[key].rank:
                changed |= _raise(rules, key, rr[1], "medium",
                                  f"write ≥ read: the read on {_path_of(key)} is {rr[1].value}")

    # cross-surface OWNER floor: an object-addressing endpoint rated ≤ AUTHENTICATED,
    # whose object-type sibling is OWNER+ , is raised to OWNER (capped — never ADMIN)
    owner_tokens: dict[str, AccessClass] = {}
    for key in keys:
        tok = _obj_token(_path_of(key))
        if tok and RANK[AccessClass.OWNER_ONLY] <= rules[key].rank <= RANK[AccessClass.TENANT_ISOLATED]:
            prev = owner_tokens.get(tok)
            if prev is None or rules[key].rank > RANK[prev]:
                owner_tokens[tok] = rules[key].access_class
    for key in keys:
        if rules[key].rank > RANK[AccessClass.AUTHENTICATED]:
            continue
        if not _addresses_object(key):
            continue
        tok = _obj_token(_path_of(key))
        floor = owner_tokens.get(tok)
        if floor is not None:
            changed |= _raise(rules, key, floor, "medium",
                              f"cross-surface floor: object '{tok}' is {floor.value} on a sibling surface")

    # parent → child: a sub-resource inherits ≥ its parent's rank
    paths = sorted({_path_of(k) for k in keys})
    for key in keys:
        cp = _path_of(key)
        best = None
        for pp in paths:
            if pp != cp and cp.startswith(pp.rstrip("/") + "/"):
                if best is None or len(pp) > len(best):
                    best = pp
        if best:
            # the strongest rule among endpoints on the parent path
            prank, pcls = 0, None
            for k2 in keys:
                if _path_of(k2) == best and rules[k2].rank > prank:
                    prank, pcls = rules[k2].rank, rules[k2].access_class
            if pcls is not None and prank > rules[key].rank:
                changed |= _raise(rules, key, pcls, "medium",
                                  f"parent→child: sub-resource of {best} ({pcls.value})")
    return changed


def refine(model, base: dict) -> dict:
    """Return a refined intent map: RAISE-only over `base`. Deterministic; converges
    in a bounded number of rounds (real authz lattices are shallow)."""
    rules = dict(base)
    _partition_evidence(model, rules)
    _vocabulary_evidence(model, rules, _learn_vocabulary(model, rules))
    for _ in range(6):                       # bounded fixpoint
        if not _propagate_once(model, rules):
            break
    # attach the separation set intent means to enforce (sharpens the differ + writeup)
    for key in sorted(rules):
        r = rules[key]
        sep = _SEPARATES.get(r.access_class, ())
        if sep and sep != r.separates:
            rules[key] = IntentRule(r.endpoint_key, r.access_class, r.confidence,
                                    r.signals, r.onyx_effect, sep)
    return dict(sorted(rules.items()))
