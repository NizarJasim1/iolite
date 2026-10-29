"""
reason · signals — extract INTENT signals already latent in the acquired model.

The vision reconstructs the developer's intent from every legal leakage. IOLITE
already mines endpoints, params, role hints and JWT identity claims; this module
reads the intent hidden in them that plain effect/role classification misses:

  * field names            owner_id / account_id / user_id  → owner-scoped
                           tenant_id / org_id               → tenant-isolated
                           is_admin / role / permission     → role/privilege
  * self-scoped path       /me /self /current               → owner-scoped (strongest)
  * JWT role claims        role / scope / groups / perms     → the app is role-based

Pure, deterministic, provenance-friendly. States signals only — intent.py decides.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

from ..models import Endpoint, Principal
from ..normalize import object_ids, SELF_ALIASES

_OWNER_FIELDS = ("owner_id", "ownerid", "user_id", "userid", "uid", "account_id",
                 "accountid", "customer_id", "member_id", "actor_id", "created_by",
                 "author_id", "user")
_TENANT_FIELDS = ("tenant_id", "tenantid", "org_id", "orgid", "organization_id",
                  "company_id", "workspace_id", "team_id", "account", "realm")
_ROLE_FIELDS = ("is_admin", "isadmin", "role", "roles", "is_staff", "isstaff", "staff",
                "permission", "permissions", "scope", "scopes", "access_level",
                "privilege", "privileges", "user_type", "account_type", "is_superuser")
_ADMIN_WORDS = ("admin", "internal", "staff", "root", "superuser", "console", "mgmt",
                "backoffice", "sysadmin")
_JWT_ROLE_CLAIMS = ("role", "roles", "scope", "scp", "groups", "grp", "permissions",
                    "perms", "authorities", "realm_access", "resource_access")


def _norm(names) -> set[str]:
    return {str(n).strip().lower().lstrip("$").strip("{}:<>") for n in names if n}


def _match(names: set[str], vocab) -> list[str]:
    out = []
    for n in sorted(names):
        for v in vocab:
            if n == v or n.endswith("_" + v) or v in n:
                out.append(n)
                break
    return out


@dataclass
class IntentSignals:
    self_scoped: bool = False
    field_owner: list[str] = field(default_factory=list)
    field_tenant: list[str] = field(default_factory=list)
    field_role: list[str] = field(default_factory=list)
    admin_words: list[str] = field(default_factory=list)
    other_role_words: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def _jwt_payload(authorization: str) -> dict:
    """Decode (NOT verify) a Bearer JWT payload → all claims. Defensive."""
    tok = str(authorization).split()[-1]
    parts = tok.split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1]
    seg += "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg.encode()).decode("utf-8", "replace"))
    except Exception:      # noqa: BLE001
        return {}


def jwt_role_based(principals: list[Principal]) -> bool:
    """True if any operator principal's token carries a ROLE/scope claim — evidence
    the app enforces role-based authz (informs privileged-intent classification)."""
    for p in principals or []:
        for hv in (p.auth or {}).values():
            claims = _jwt_payload(hv)
            if any(c.lower() in _JWT_ROLE_CLAIMS for c in claims):
                return True
    return False


def endpoint_signals(ep: Endpoint) -> IntentSignals:
    sig = IntentSignals()
    # self-scoped path (strongest ownership intent)
    for oid in object_ids(ep.path):
        if oid.strip("{}").lower() in SELF_ALIASES:
            sig.self_scoped = True
    if any(seg.strip("/").lower() in SELF_ALIASES for seg in ep.path.split("/")):
        sig.self_scoped = True

    names = _norm(ep.params)
    sig.field_owner = _match(names, _OWNER_FIELDS)
    sig.field_tenant = _match(names, _TENANT_FIELDS)
    sig.field_role = _match(names, _ROLE_FIELDS)

    for r in ep.role_hints:
        rl = r.lower()
        if any(w in rl for w in _ADMIN_WORDS):
            sig.admin_words.append(r)
        else:
            sig.other_role_words.append(r)

    if sig.self_scoped:
        sig.reasons.append("self-scoped path (/me,/self) → owner intent")
    if sig.field_owner:
        sig.reasons.append(f"owner field(s) {sig.field_owner} → owner-scoped")
    if sig.field_tenant:
        sig.reasons.append(f"tenant field(s) {sig.field_tenant} → tenant-isolated")
    if sig.field_role:
        sig.reasons.append(f"role/privilege field(s) {sig.field_role} → privileged")
    if sig.admin_words:
        sig.reasons.append(f"admin role hint {sorted(set(sig.admin_words))}")
    return sig
