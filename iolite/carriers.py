"""
Object-id carrier extraction — faithful to ONYX's `HTTPRequest._compute_object_ids`.

An object id that authorises a request can ride in any of several carriers, and a
production IDOR very often hides in a carrier that is NOT the path:

  * path segment            /api/orders/1001
  * query parameter         /api/search?userId=501
  * identity header         X-Customer-Id: 501
  * JWT identity claim       Authorization: Bearer <...sub=501...>   (decoded, NOT verified)
  * GraphQL variable        {variables: {id: 501}}
  * request-body id field    {"orderId": 501}

A miner that only reads the path is blind to the majority of real BOLA surface.
Everything here is decode + parse; the JWT is treated purely as a CLAIM (ONYX's
Δstate read-back still decides truth). Deterministic (QL4).
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

from .normalize import object_ids as _path_ids

_ID_NAMES = {"id", "uid", "uuid", "gid", "pid", "guid", "objectid", "object_id",
             "userid", "user_id", "accountid", "account_id", "orderid", "order_id",
             "customerid", "customer_id", "tenantid", "tenant_id", "orgid", "org_id",
             "memberid", "member_id", "ref", "key", "no", "number"}
_IDENTITY_HEADERS = {"x-user-id", "x-customer-id", "x-account-id", "x-tenant-id",
                     "x-org-id", "x-member-id", "x-owner-id", "x-actor-id"}
_JWT_CLAIMS = ("sub", "user_id", "uid", "tenant_id", "org_id", "account_id",
               "customer_id", "member_id")
_ID_SUFFIX = re.compile(r"(?:_id|Id)$")


@dataclass(frozen=True)
class Carrier:
    carrier: str          # path | query | header | jwt | gql-var | body
    name: str             # segment index / param / header / claim / variable / field
    value: str


def _is_id_name(name: str) -> bool:
    n = name.lower()
    return n in _ID_NAMES or n.endswith("_id") or name.endswith("Id") or bool(_ID_SUFFIX.search(name))


def _scalar(v) -> bool:
    return isinstance(v, (str, int, float)) and not isinstance(v, bool)


def decode_jwt_claims(authorization: str) -> dict:
    """Decode (NOT verify) a Bearer JWT payload; return only identity claims."""
    if not authorization:
        return {}
    token = authorization.split()[-1]
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: data[k] for k in _JWT_CLAIMS if k in data and _scalar(data[k])}


def object_ids(method: str, path: str, query: dict | None = None,
               headers: dict | None = None, body=None) -> list[Carrier]:
    """All object ids this request addresses, across every carrier. De-duplicated
    by (carrier, name, value); deterministic order (carrier, name)."""
    out: list[Carrier] = []
    seen = set()

    def add(carrier, name, value):
        if value is None or value == "":
            return
        v = str(value)
        sig = (carrier, str(name), v)
        if sig not in seen:
            seen.add(sig)
            out.append(Carrier(carrier, str(name), v))

    # path
    for i, seg in enumerate(_path_ids(path)):
        add("path", str(i), seg)
    # query
    for k, v in (query or {}).items():
        if _is_id_name(k):
            for item in (v if isinstance(v, list) else [v]):
                add("query", k, item)
    # identity headers
    for hk, hv in (headers or {}).items():
        lk = hk.lower()
        if lk in _IDENTITY_HEADERS:
            add("header", hk, hv)
        if lk == "authorization":
            for ck, cv in decode_jwt_claims(str(hv)).items():
                add("jwt", ck, cv)
    # body: graphql variables + top-level id-ish fields
    if isinstance(body, dict):
        variables = body.get("variables")
        if isinstance(variables, dict):
            for k, v in variables.items():
                if _is_id_name(k):
                    if _scalar(v):
                        add("gql-var", k, v)
                    elif isinstance(v, list):
                        for it in v:
                            if _scalar(it):
                                add("gql-var", k, it)
        for k, v in body.items():
            if k == "variables":
                continue
            if _is_id_name(k) and _scalar(v):
                add("body", k, v)
    return out


def primary_and_all(carriers: list[Carrier]) -> tuple[str | None, list[str]]:
    """(primary object id, all ids). Primary = first path id, else first of any."""
    if not carriers:
        return None, []
    path_ids = [c.value for c in carriers if c.carrier == "path"]
    all_ids = []
    for c in carriers:
        if c.value not in all_ids:
            all_ids.append(c.value)
    primary = path_ids[0] if path_ids else all_ids[0]
    return primary, all_ids
