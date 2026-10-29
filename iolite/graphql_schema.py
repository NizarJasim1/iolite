"""
③ GraphQL introspection → endpoints.

A published introspection result maps the entire object graph: every Query,
Mutation, their arguments and return types. We turn each root field into an
Endpoint whose key matches ONYX's GraphQL endpoint_key form: `QUERY <field>` /
`MUTATION <field>`. Queries that take an id-like argument are prime BOLA surface;
mutations touching the authority graph or value are flagged accordingly.

Pure JSON parse; conservative effect hints (wrong-but-safe, never wrong-but-FP).
"""

from __future__ import annotations

from .models import Effect, Endpoint, Provenance, SourceKind

_ID_ARGS = {"id", "uid", "uuid", "gid", "ref", "key", "slug", "number", "no",
            "userid", "user_id", "accountid", "account_id", "orderid", "order_id"}
_GRANT_WORDS = ("role", "permission", "grant", "privilege", "admin", "scope", "acl")
_PAY_WORDS = ("pay", "refund", "charge", "settle", "payout", "transfer", "price")


def _unwrap(t: dict) -> str:
    """Resolve a possibly NON_NULL/LIST-wrapped type to its named type."""
    seen = 0
    while isinstance(t, dict) and t.get("ofType") and seen < 20:
        t = t["ofType"]
        seen += 1
    return (t or {}).get("name") or ""


def _field_effect(op_type: str, name: str, args: list[str], returns_list: bool) -> Effect:
    low = name.lower()
    if op_type == "MUTATION":
        if any(w in low for w in _GRANT_WORDS):
            return Effect.AUTHORITY_GRANT
        if any(w in low for w in _PAY_WORDS):
            return Effect.PAYMENT
        return Effect.STATE_GATE
    # QUERY
    if any(a.lower() in _ID_ARGS for a in args):
        return Effect.OBJECT_ACCESS
    if returns_list:
        return Effect.FIELD_PROJECTION       # a list view may over-expose a field
    return Effect.NONE


def parse_introspection(doc: dict, locator: str = "graphql") -> list[Endpoint]:
    schema = None
    if isinstance(doc, dict):
        schema = ((doc.get("data") or {}).get("__schema")
                  or doc.get("__schema") or doc.get("data") or doc)
    if not isinstance(schema, dict):
        return []
    types = {t.get("name"): t for t in (schema.get("types") or []) if isinstance(t, dict)}
    roots = []
    for op_key, op_type in (("queryType", "QUERY"), ("mutationType", "MUTATION")):
        rt = (schema.get(op_key) or {}).get("name")
        if rt and rt in types:
            roots.append((op_type, types[rt]))

    out: dict[str, Endpoint] = {}
    for op_type, tdef in roots:
        for f in (tdef.get("fields") or []):
            if not isinstance(f, dict):
                continue
            name = f.get("name")
            if not name:
                continue
            args = [a.get("name", "") for a in (f.get("args") or []) if isinstance(a, dict)]
            ret = f.get("type") or {}
            returns_list = _is_list(ret)
            effect = _field_effect(op_type, name, args, returns_list)
            ep = Endpoint(
                method=op_type, path=name, effect=effect, params=sorted(args),
                provenance=[Provenance.of(SourceKind.GRAPHQL, f"{locator}:{op_type} {name}")],
            )
            out[ep.key] = ep
    return [out[k] for k in sorted(out)]


def _is_list(t: dict) -> bool:
    seen = 0
    while isinstance(t, dict) and seen < 20:
        if t.get("kind") == "LIST":
            return True
        t = t.get("ofType") or {}
        seen += 1
    return False
