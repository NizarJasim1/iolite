"""
object_identity.py — resolve the SAME underlying object across surfaces and id
REPRESENTATIONS into ONE identity (the OBJECT operand of the authz decision).

IOLITE keys objects by the raw id string, so the same object addressed as `1001` on REST
and `gid://app/Order/1001` or a base64 cursor on GraphQL becomes TWO objects — its holder
sets split, and a cross-surface over-permission (A holds it via one door, B reaches it via
another) is invisible. This module unifies the representations, from LEGAL evidence only:

  • co-disclosure   one object's own response carries another representation of itself
                    (…/orders/1001 returns {"id":1001,"gid":"gid://app/Order/1001"}).
  • encoded id      a base64 token that DECODES to an already-observed id.
  • canonical ref   a GID / URN whose trailing object key equals an observed numeric id.

Sound by construction: a link is asserted only from direct evidence (a shared record, a
decode, a canonical ref) — never from a loose resemblance (two slugs that merely end in the
same digits are NOT merged cross-corpus). Unlinked ids stay separate (honest floor). A wrong
merge can at worst add a candidate the metamorphic oracle then DISPOSES by value-presence —
never a fabricated finding. Deterministic, pure-stdlib (QL4). Own evidence only (QL6).
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

_GID_TAIL = re.compile(r"(?:gid://|urn:)\S*?(\d{2,})\s*$", re.IGNORECASE)
_B64ISH = re.compile(r"^[A-Za-z0-9+/_=-]{8,}$")

# Response field names that are an ALTERNATE REPRESENTATION of the record's OWN id (safe to
# unify on co-disclosure). A reference to another object (customer_id, owner_id, parent_id)
# is deliberately excluded — unifying those would merge DIFFERENT objects.
_SELF_ID_FIELDS = frozenset((
    "id", "gid", "global_id", "globalid", "_id", "uuid", "guid", "node_id", "nodeid",
    "slug", "ref", "canonical_id", "public_id", "publicid", "external_id", "externalid",
    "objectid", "object_id",
))


def _gid_key(s: str) -> str:
    """The trailing numeric object key of a GID/URN ref, else ''."""
    m = _GID_TAIL.match(str(s).strip())
    return m.group(1) if m else ""


def _b64_decode_id(s: str) -> str:
    """If `s` is a base64 token that decodes to a clean ascii id (digits or a short
    identifier), return that id; else ''. Tolerant of url-safe + missing padding."""
    t = str(s).strip()
    if not _B64ISH.match(t) or t.isdigit():
        return ""
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = dec(t + "=" * (-len(t) % 4))
        except (binascii.Error, ValueError):
            continue
        try:
            txt = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            continue
        # a cursor like "Order:1001" or "1001" -> take the trailing id token
        m = re.search(r"([A-Za-z0-9._-]{1,64})$", txt)
        if m and (txt.isprintable()):
            tok = m.group(1)
            # a bare number, or a "<Type>:<n>" / "<Type>-<n>" cursor
            return tok if (tok.isdigit() or re.fullmatch(r"[A-Za-z0-9._-]+", tok)) else ""
    return ""


@dataclass
class IdentityMap:
    """A resolved view: every known representation -> a stable canonical id."""
    parent: dict = field(default_factory=dict)      # union-find
    _canon_cache: dict = field(default_factory=dict)

    def _find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:                # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def _union(self, a: str, b: str) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra == rb:
            return
        # deterministic representative: shortest, then lexicographically smallest
        lo, hi = sorted((ra, rb), key=lambda s: (len(s), s))
        self.parent[hi] = lo

    def canonical(self, oid) -> str:
        s = str(oid)
        if not s:
            return s
        return self._find(s)

    def aliases(self, oid) -> list:
        c = self.canonical(oid)
        return sorted(k for k in self.parent if self._find(k) == c)

    @property
    def groups(self) -> dict:
        out: dict = {}
        for k in self.parent:
            out.setdefault(self._find(k), set()).add(k)
        return {c: sorted(v) for c, v in sorted(out.items())}


def _same_object_links(ids) -> list:
    """Cross-corpus links provable WITHOUT a shared record: a base64 token that decodes to
    a seen id, or a GID/URN whose object key equals a seen numeric id."""
    ids = sorted({str(i) for i in ids if str(i)})
    idset = set(ids)
    links = []
    for s in ids:
        gk = _gid_key(s)
        if gk and gk in idset and gk != s:
            links.append((s, gk))
        dec = _b64_decode_id(s)
        if dec and dec in idset and dec != s:
            links.append((s, dec))
    return links


def resolve(exchanges=None, accesses=None, extra_ids=None) -> IdentityMap:
    """Build the identity map from captured evidence. `exchanges` give co-disclosure (a
    response that carries another representation of its own object); `accesses`/`extra_ids`
    widen the id corpus for the encoded/canonical-ref links."""
    imap = IdentityMap()
    corpus: set = set()

    def note(x):
        x = str(x)
        if x:
            corpus.add(x)
            imap.parent.setdefault(x, x)

    for e in (exchanges or []):
        oid = str(getattr(e, "object_id", "") or "")
        if oid:
            note(oid)
        # co-disclosure: a SELF-identity field in this record (id/gid/slug/uuid…, never a
        # *_id reference to another object) is another representation of the SAME object.
        for name, v in getattr(e, "response_fields", {}).items():
            if str(name).strip().lower() in _SELF_ID_FIELDS:
                sv = str(v)
                if sv and sv != oid:
                    note(sv)
                    if oid:
                        imap._union(oid, sv)
        # disclosed ids are OTHER objects (chaining) — add to the corpus for encoded/GID
        # resolution among themselves, but never union them with this record's object.
        for v in (getattr(e, "response_ids", []) or []):
            note(v)

    for acc in (accesses or []):
        note(getattr(acc, "object_id", ""))
        for i in (getattr(acc, "all_ids", None) or []):
            note(i)
    for i in (extra_ids or []):
        note(i)

    for a, b in _same_object_links(corpus):
        imap._union(a, b)
    return imap


def unify_holdings(model, imap: IdentityMap) -> dict:
    """A holdings map re-keyed by canonical id — holders of EVERY representation of an
    object merged, so cross-surface reach is one node. Pure; does not mutate the model."""
    merged: dict = {}
    for oid, holders in model.holdings.items():
        merged.setdefault(imap.canonical(oid), set()).update(holders)
    return {k: set(v) for k, v in merged.items()}
