"""
Client-derived GraphQL operations — recover the GraphQL surface WITHOUT introspection.

`graphql_schema.py` needs a published introspection result; a hardened target
DISABLES introspection, so that source goes dark. But the client still ships and
sends its operations: gql`...` tagged templates, inline `query {...}` strings,
and persisted-query maps. Executing the client deobfuscates them; here we recover
them statically from the bundle you already hold. Same ONYX endpoint_key form as
introspection (`QUERY <field>` / `MUTATION <field>`), so they flow into the model
unchanged.

Pure stdlib, deterministic (QL4). Bounded. Passive — reads bytes you already have,
sends nothing. Conservative effect hints (wrong-but-safe, never wrong-but-FP).
"""

from __future__ import annotations

import json
import re

from .models import Effect, Endpoint, Provenance, SourceKind
from .limits import MAX_JS_BYTES

_ID_ARGS = {"id", "uid", "uuid", "gid", "ref", "key", "slug", "number", "no",
            "userid", "user_id", "accountid", "account_id", "orderid", "order_id"}
_GRANT_WORDS = ("role", "permission", "grant", "privilege", "admin", "scope", "acl",
                "impersonate", "assign", "revoke")
_PAY_WORDS = ("pay", "refund", "charge", "settle", "payout", "transfer", "price",
              "checkout", "invoice", "wallet", "credit")
_OP_HEAD = re.compile(r"^\s*(query|mutation|subscription)\b", re.IGNORECASE)
# a tagged-template or inline document opener
_TAG = re.compile(r"(?:gql|graphql)\s*`", re.IGNORECASE)
_INLINE = re.compile(r"""(['"])\s*(query|mutation|subscription)?\s*[A-Za-z0-9_]*\s*"""
                     r"""(?:\([^)]*\))?\s*\{""", re.IGNORECASE)


def _effect(op_type: str, name: str, args: list[str]) -> Effect:
    low = name.lower()
    if op_type == "MUTATION":
        if any(w in low for w in _GRANT_WORDS):
            return Effect.AUTHORITY_GRANT
        if any(w in low for w in _PAY_WORDS):
            return Effect.PAYMENT
        return Effect.STATE_GATE
    if any(a.lower() in _ID_ARGS for a in args):
        return Effect.OBJECT_ACCESS
    return Effect.NONE


def _read_delim(text: str, i: int, open_ch: str, close_ch: str) -> tuple[str, int]:
    """text[i]==open_ch. Return (inner, index_after_close). Backtick/quote aware only
    for the simple case; used for backtick template bodies."""
    n = len(text)
    j = i + 1
    buf = []
    while j < n:
        c = text[j]
        if c == "\\" and j + 1 < n:
            buf.append(text[j + 1]); j += 2; continue
        if c == close_ch:
            return "".join(buf), j + 1
        buf.append(c); j += 1
    return "".join(buf), n


def _root_fields(body: str) -> list[tuple[str, str, list[str]]]:
    """Parse the ROOT selection of a GraphQL document → [(op_type, field, [arg_names])].
    A bounded brace/paren scanner; tolerant of variables and aliases."""
    m = _OP_HEAD.match(body)
    op = (m.group(1).lower() if m else "query")
    op_type = {"mutation": "MUTATION", "subscription": "SUBSCRIPTION"}.get(op, "QUERY")
    i = body.find("{")
    if i < 0:
        return []
    n = len(body)
    depth = 0
    paren = 0
    j = i
    out: list[tuple[str, str, list[str]]] = []
    while j < n and len(out) < 100:
        c = body[j]
        if c == "(" and depth == 1:
            paren += 1; j += 1; continue
        if c == ")" and depth == 1 and paren > 0:
            paren -= 1; j += 1; continue
        if c == "{":
            depth += 1; j += 1; continue
        if c == "}":
            depth -= 1
            if depth == 0:
                break
            j += 1; continue
        if depth == 1 and paren == 0 and (c.isalpha() or c == "_"):
            k = j
            while k < n and (body[k].isalnum() or body[k] == "_"):
                k += 1
            ident = body[j:k]
            p = k
            while p < n and body[p] in " \t\r\n":
                p += 1
            if p < n and body[p] == ":":            # alias — real field follows
                j = p + 1
                continue
            args: list[str] = []
            if p < n and body[p] == "(":
                q, pd = p + 1, 1
                while q < n and pd > 0:
                    if body[q] == "(":
                        pd += 1
                    elif body[q] == ")":
                        pd -= 1
                    q += 1
                argtext = body[p + 1:q - 1]
                args = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:", argtext)
            if ident.lower() not in ("query", "mutation", "subscription", "fragment",
                                     "on", "true", "false", "null"):
                out.append((op_type, ident, args))
            j = k
            continue
        j += 1
    return out


def _documents(text: str) -> list[str]:
    """Every GraphQL document body in a JS blob: tagged templates + inline strings.
    Bounded scan (QL4)."""
    docs: list[str] = []
    seen: set[str] = set()

    for m in _TAG.finditer(text):
        body, _ = _read_delim(text, m.end() - 1, "`", "`")
        if "{" in body and body.strip() not in seen:
            seen.add(body.strip()); docs.append(body)

    for m in _INLINE.finditer(text):
        q = m.group(1)
        start = m.start(1)
        body, _ = _read_delim(text, start, q, q)
        if "{" in body and _OP_HEAD.match(body) and body.strip() not in seen:
            seen.add(body.strip()); docs.append(body)
    return docs


def _persisted(text: str) -> list[str]:
    """A persisted-query map {hash: documentString} → the document strings."""
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return []
    out: list[str] = []
    if isinstance(doc, dict):
        for v in doc.values():
            if isinstance(v, str) and "{" in v and _OP_HEAD.match(v):
                out.append(v)
            elif isinstance(v, dict):
                q = v.get("query") or v.get("document")
                if isinstance(q, str) and "{" in q:
                    out.append(q)
    return out


def extract_graphql_operations(text: str, locator: str) -> list[Endpoint]:
    """Recover GraphQL root operations from a client artifact → Endpoints keyed
    `QUERY <field>` / `MUTATION <field>`. Deterministic, deduplicated, sorted."""
    if not text:
        return []
    if len(text) > MAX_JS_BYTES:
        text = text[:MAX_JS_BYTES]
    bodies = _documents(text) + _persisted(text)
    # also accept a BARE document string (e.g. handed straight from a runtime hook)
    if _OP_HEAD.match(text) and "{" in text:
        bodies.append(text)
    out: dict[str, Endpoint] = {}
    for body in bodies:
        for op_type, field, args in _root_fields(body):
            ep = Endpoint(
                method=op_type, path=field, effect=_effect(op_type, field, args),
                params=sorted(set(args)),
                provenance=[Provenance.of(SourceKind.JS, f"{locator}:gql {op_type} {field}",
                                          note="client-derived GraphQL (no introspection)")])
            if ep.key in out:
                out[ep.key].merge(ep)
            else:
                out[ep.key] = ep
    return [out[k] for k in sorted(out)]
