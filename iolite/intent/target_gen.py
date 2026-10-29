"""
target_gen.py — auto-derive the engine's intervention config (`target.json`) from captures.

The write/field/state families confirm by INTERVENTION (create objects as your own accounts,
then check cross-principal access) via `iolite.intent.engine.run_target`, which needs a small
`target.json` describing login + one create/read pair per object type. Hand-writing it is the
friction that kept the write path from being one click. This module proposes it automatically
from the captured exchanges — and marks every uncertain field with `_TODO` so the operator
reviews it before any live, write-capable run.

Safety: the generated config defaults to the operator's OWN accounts (static auth headers you
supply) and is only ever consumed by the gated engine (ScopeGuard + own-principals + dry-run on
writes). This module writes a file for review; it sends nothing and runs nothing.
"""
from __future__ import annotations

import json
import re

_ID_KEYS = ("id", "_id", "uuid", "gid")
_SECRETISH = ("secret", "token", "private", "ssn", "card", "cvv", "password", "key", "note")
_TITLEISH = ("title", "name", "label", "subject", "text", "description", "content", "message")
_TEMPLATE = re.compile(r"\{[^}/]+\}")


def _mutate_path_to_engine(path_t: str) -> str:
    """Turn IOLITE's `{id}` template into the engine's `{{id}}` substitution token."""
    return _TEMPLATE.sub("{{id}}", path_t)


def _body_template(request_fields: dict) -> dict:
    """Build a create-body template: a title-ish field → {{title}}, a secret-ish field →
    {{secret}} (so the engine can plant and detect a unique private value), others kept as-is."""
    body = {}
    used_title = used_secret = False
    for k, v in (request_fields or {}).items():
        lk = str(k).lower()
        if not used_secret and any(s in lk for s in _SECRETISH):
            body[k] = "{{secret}}"; used_secret = True
        elif not used_title and any(t in lk for t in _TITLEISH):
            body[k] = "{{title}}"; used_title = True
        else:
            body[k] = v
    if not used_title:
        body["title"] = "{{title}}"      # ensure a plantable field exists
    if not used_secret:
        body["secret"] = "{{secret}}"    # _TODO: confirm the real private field name
    return body


def generate_target(exchanges, *, principal_auth: dict | None = None,
                    program: str = "authorized target", base_url: str = "") -> dict:
    """Propose a target.json from captured exchanges. Deterministic. Review before live use."""
    host = ""
    for e in exchanges:
        h = getattr(e, "host", "") or ""
        if h:
            host = h; break
    base = base_url or (f"https://{host}" if host else "https://TODO-host")

    # group by object type; find a create (POST→2xx with an id) + a read (GET /type/{id})
    by_type: dict = {}
    for e in exchanges:
        t = _type_of(e.endpoint_key)
        if not t:
            continue
        by_type.setdefault(t, {"create": None, "read": None})
        m = e.method.upper()
        if m == "POST" and 200 <= e.status < 300 and e.object_id and by_type[t]["create"] is None:
            by_type[t]["create"] = e
        if m == "GET" and e.object_id and "{id}" in e.endpoint_key and by_type[t]["read"] is None:
            by_type[t]["read"] = e

    kinds = []
    todo = []
    for t, pair in sorted(by_type.items()):
        c, r = pair["create"], pair["read"]
        if not (c and r):
            if r and not c:
                todo.append(f"type '{t}': found a read but no observed create — add a create "
                            f"request to enable intervention, or test it read-only via --replay")
            continue
        id_key = next((k for k in (c.response_fields or {}) if str(k).lower() in _ID_KEYS), "id")
        kinds.append({
            "name": t,
            "create": {"method": c.method.upper(),
                       "path": c.endpoint_key.split(" ", 1)[-1],
                       "body": _body_template(c.request_fields)},
            "read": {"method": "GET", "path": _mutate_path_to_engine(r.endpoint_key.split(" ", 1)[-1])},
            "_id_field": id_key,
            "_note": "review: confirm the create body and that the read path keys off the create's id",
        })

    principals = _principals(principal_auth)
    cfg = {
        "name": program,
        "base_url": base,
        "host": host or "TODO-host",
        "min_interval": 0.5,                 # advisory; the adaptive pacer governs live
        "auth": {},                          # {} = static-credential mode (headers below)
        "principals": principals,
        "kinds": kinds,
        "_TODO": ([f"{len(kinds)} kind(s) derived; review each create/read pair before any live run"]
                  + todo + ([] if principal_auth else
                            ["supply your OWN accounts' auth headers via --principals-file "
                             "(A and B) — intervention uses your accounts only"])),
        "_safety": "Consumed only by the gated engine (ScopeGuard + own-principals). Writes stay "
                   "dry-run until you attest. Review every field; this was auto-derived.",
    }
    return cfg


def _principals(principal_auth: dict | None) -> dict:
    out = {}
    labels = ["A", "B"]
    items = sorted((principal_auth or {}).items())
    for i, (pid, hdrs) in enumerate(items[:2]):
        out[labels[i]] = {"label": pid, "headers": dict(hdrs)}
    for lbl in labels:
        out.setdefault(lbl, {"label": f"TODO-{lbl}", "headers": {"authorization": "Bearer TODO"}})
    return out


def _type_of(endpoint_key: str) -> str:
    from .relation_model import _obj_type_of_path
    return _obj_type_of_path(endpoint_key.split(" ", 1)[-1])


def to_json(cfg: dict) -> str:
    return json.dumps(cfg, indent=2, sort_keys=False)
