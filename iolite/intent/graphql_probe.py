"""
graphql_probe.py — the concrete techniques that actually find authz bugs on the biggest,
most-hunted GraphQL targets (Shopify / GitLab / HackerOne-class).

Three things pattern-scanners do not do and that pay on mature GraphQL APIs:

  1. GLOBAL-ID ENUMERATION. Relay global ids are base64("Type:123") or "gid://app/Type/123".
     Decode -> increment/decrement the numeric part -> re-encode: a ready list of
     neighbouring object ids to test cross-principal. (The documented decode/increment/
     re-encode BOLA pattern.)
  2. ALIAS-BATCH PACKING. One GraphQL document can request N aliased copies of the same
     field, each with a different id. That tests dozens of objects in ONE request —
     defeating per-request rate limits and object-count throttling, which is how BOLA is
     actually confirmed at scale on throttled targets.
  3. NESTED-OBJECT AUTHORIZATION. The root field may be guarded while a SENSITIVE type is
     reachable through a nested edge (order -> customer -> paymentMethods). Servers that
     authorize the root but not the traversal leak the nested object. We find those paths
     from the type graph.

Pure-stdlib, deterministic (QL4). Generates PROPOSALS (candidate operations / ids); it
sends nothing — the gated live step does, under scope + governor.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass

_GID_COLON = re.compile(r"^([A-Za-z][A-Za-z0-9_]*):(\d+)$")           # "Type:123"
_GID_URI = re.compile(r"^gid://[^/]+/([A-Za-z0-9_]+)/(\d+)$")          # "gid://app/Type/123"


@dataclass
class DecodedGID:
    style: str          # "b64colon" | "uri" | "rawcolon"
    type: str
    num: int
    prefix: str = ""    # for uri style: the "gid://app/" prefix


def decode_global_id(gid: str) -> DecodedGID | None:
    """Decode a Relay/global object id to (type, numeric). Handles base64('Type:123'),
    raw 'Type:123', and 'gid://app/Type/123'. Returns None if it isn't a global id."""
    s = str(gid)
    m = _GID_URI.match(s)
    if m:
        pre = s[: s.index(m.group(1))]
        return DecodedGID("uri", m.group(1), int(m.group(2)), prefix=pre)
    m = _GID_COLON.match(s)
    if m:
        return DecodedGID("rawcolon", m.group(1), int(m.group(2)))
    # try base64
    try:
        pad = s + "=" * (-len(s) % 4)
        dec = base64.b64decode(pad, validate=False).decode("utf-8", "replace")
    except Exception:
        return None
    m = _GID_COLON.match(dec)
    if m:
        return DecodedGID("b64colon", m.group(1), int(m.group(2)))
    return None


def encode_global_id(d: DecodedGID, num: int) -> str:
    if d.style == "b64colon":
        return base64.b64encode(f"{d.type}:{num}".encode()).decode()
    if d.style == "uri":
        return f"{d.prefix}{d.type}/{num}"
    return f"{d.type}:{num}"


def neighbor_gids(gid: str, span: int = 5) -> list[str]:
    """Candidate neighbouring ids (decode/±/re-encode). Empty if `gid` isn't a global id.
    These are PROPOSALS to test cross-principal; none is sent here."""
    d = decode_global_id(gid)
    if d is None:
        return []
    out = []
    for delta in range(-span, span + 1):
        if delta == 0:
            continue
        n = d.num + delta
        if n > 0:
            out.append(encode_global_id(d, n))
    return out


def alias_batch_query(field_name: str, ids: list[str], selection: str = "id") -> str:
    """One GraphQL query testing many ids at once via aliases. Confirms/denies N objects
    in a SINGLE request -> bypasses per-request rate limits and object throttling."""
    parts = []
    for i, oid in enumerate(ids):
        safe = oid.replace('"', '\\"')
        parts.append(f'  a{i}: {field_name}(id: "{safe}") {{ {selection} }}')
    return "query IoliteBatch {\n" + "\n".join(parts) + "\n}"


# --------------------------------------------------------------------------- #
# nested-object authorization paths                                            #
# --------------------------------------------------------------------------- #

_SENSITIVE = ("payment", "card", "token", "secret", "ssn", "address", "phone",
              "email", "invoice", "balance", "apikey", "api_key", "password",
              "credential", "bank", "tax", "dob", "passport")


@dataclass
class NestedPath:
    path: list                 # ["order", "customer", "paymentMethods"]
    sensitive_type: str
    why: str = ""

    def as_query(self, root_id_var: str = "$id") -> str:
        inner = "id"
        for hop in reversed(self.path[1:]):
            inner = f"{hop} {{ {inner} }}"
        return f"query IoliteNested({root_id_var}: ID!) {{ {self.path[0]}(id: {root_id_var}) {{ {inner} }} }}"


def nested_authz_paths(schema: dict, *, sensitive_fields: set | None = None,
                       max_depth: int = 4) -> list[NestedPath]:
    """Given a type graph {Type: {field: TargetType}}, find traversals from a root field
    to a SENSITIVE type/field. These are leads: a server that guards the root but not the
    edge leaks the nested object. Deterministic BFS, bounded depth."""
    sensitive_fields = {s.lower() for s in (sensitive_fields or set())}
    # roots: fields on the Query type (or every type if no Query given)
    roots = schema.get("Query", {})
    if not roots:
        return []

    def is_sensitive(type_name: str, field_name: str) -> bool:
        t, f = type_name.lower(), field_name.lower()
        return (any(w in t for w in _SENSITIVE) or any(w in f for w in _SENSITIVE)
                or f in sensitive_fields)

    out: list[NestedPath] = []
    seen: set = set()
    for root_field, root_type in sorted(roots.items()):
        # BFS from the root type
        stack = [([root_field], root_type)]
        while stack:
            path, cur_type = stack.pop(0)
            if len(path) > max_depth:
                continue
            for fname, ftype in sorted(schema.get(cur_type, {}).items()):
                npath = path + [fname]
                if is_sensitive(cur_type, fname) and len(npath) >= 2:
                    key = tuple(npath)
                    if key not in seen:
                        seen.add(key)
                        out.append(NestedPath(
                            path=npath, sensitive_type=ftype,
                            why=f"sensitive '{fname}' on {cur_type} reachable via "
                                f"{' -> '.join(path)} (nested-object authz)"))
                elif ftype in schema and ftype != cur_type and len(npath) < max_depth:
                    stack.append((npath, ftype))
    out.sort(key=lambda p: (len(p.path), p.path))
    return out
