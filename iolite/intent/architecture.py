"""
architecture.py — model the TARGET'S authorization architecture, and aim ONYX at the
seam where its authz actually lives.

Research ranks a program by fit; it never says HOW the target decides authorization, so
ONYX pressed blindly. To find a zero-day in a specific giant you must know where its
boundaries ARE: is authz a GraphQL/gateway layer over bare REST services (so the bug is at
the un-gatewayed service), relationship-based (ReBAC: owner/tenant/parent), or role-based
(RBAC)? who issues identity? This modeller infers that from LEGAL public signals already
acquired (the surface shape, the intent lattice's field classes, the federation surface)
and emits the enforcement topology, the authz pattern, the identity provider, and ranked
PRESSURE POINTS — each the ONYX EffectClass + the exact surface to press.

The sharpest, most empirically-grounded pressure point: when the same object-type is
reachable BOTH through a gateway/GraphQL layer AND directly, authz enforced at the gateway
is bypassed at the service — "test the non-gateway path." Propose-only triage, no verdict
(QL5). Deterministic (QL4).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .relation_model import build_lattice, resource_type_of

_GQL = ("/graphql", "/gql")
_GATEWAY_SEGS = {"bff", "gateway", "edge", "proxy"}


@dataclass
class ArchitectureModel:
    topology: str = "unknown"          # graphql-gateway-over-rest | api-gateway/BFF | direct-service
    authz_pattern: str = "unknown"     # ReBAC… | ownership-scoped | RBAC… | unknown
    provider: str = ""                 # identity provider (from federation)
    protocol: str = ""                 # OIDC | OAuth2 | SAML
    issuer: str = ""
    identity_claims: list = field(default_factory=list)
    pressure_points: list = field(default_factory=list)   # [{surface, onyx_effect, why}]
    notes: list = field(default_factory=list)


def _paths(model):
    return [getattr(ep, "path", "") for ep in getattr(model, "endpoints", {}).values()]


def _is_gql(p):
    return any(g in p.lower() for g in _GQL)


def model_architecture(model, *, lattice=None, federation=None) -> ArchitectureModel:
    lat = lattice or build_lattice(model)
    am = ArchitectureModel()
    paths = _paths(model)

    # ---- enforcement topology ------------------------------------------------
    has_gql = any(_is_gql(p) for p in paths)
    rest_paths = sorted({p for p in paths if p and not _is_gql(p)})
    rest_types = {resource_type_of(p) for p in rest_paths if resource_type_of(p)}
    gateway = any(seg in _GATEWAY_SEGS for p in paths for seg in p.lower().split("/"))
    if has_gql and rest_types:
        am.topology = "graphql-gateway-over-rest"
    elif gateway:
        am.topology = "api-gateway/BFF"
    elif paths:
        am.topology = "direct-service"

    # ---- authz pattern (from the intent lattice's learned field classes) -----
    server_auth = any(c == "server_auth" for tf in lat.types.values() for c in tf.fields.values())
    ownership = any(c == "ownership" for tf in lat.types.values() for c in tf.fields.values())
    tenant = bool({o.tenant for o in lat.objects.values() if o.tenant}) or any(
        "tenant" in n or "org" in n for tf in lat.types.values() for n in tf.fields)
    role = server_auth or any("admin" in (r or "").lower()
                              for ep in getattr(model, "endpoints", {}).values()
                              for r in getattr(ep, "role_hints", []))
    if tenant and ownership:
        am.authz_pattern = "ReBAC/relationship (tenant + ownership)"
    elif ownership:
        am.authz_pattern = "ownership-scoped (per-object)"
    elif role:
        am.authz_pattern = "RBAC (role / function-level)"

    # ---- identity (folded from the federation surface) -----------------------
    if federation is not None:
        am.provider, am.protocol = federation.provider, federation.protocol
        am.issuer, am.identity_claims = federation.issuer, list(federation.identity_claims)

    # ---- ranked pressure points (where ONYX should press) --------------------
    pp = am.pressure_points
    if am.topology in ("graphql-gateway-over-rest", "api-gateway/BFF") and rest_paths:
        pp.append({"surface": rest_paths[0], "onyx_effect": "CROSS_SURFACE",
                   "why": "same object-type reachable off the gateway → authz enforced at "
                          "the gateway/GraphQL layer is bypassed at the service; press the "
                          "non-gateway REST path, not the gateway"})
    if tenant:
        tt = sorted({o.otype or "?" for o in lat.objects.values() if o.tenant}) or ["(tenant-scoped)"]
        pp.append({"surface": f"tenant-scoped types: {tt[:4]}", "onyx_effect": "CROSS_SURFACE",
                   "why": "relationship/tenant boundary → cross-tenant object access is the "
                          "highest-value seam for this pattern"})
    if role:
        pp.append({"surface": "role/admin-guarded functions", "onyx_effect": "AUTHORITY",
                   "why": "function-level (BFLA) — a lower-privilege principal reaching a "
                          "privileged action, scoped PER resource-domain (see typed BFLA)"})
    if federation is not None and federation.present:
        pp.append({"surface": (federation.leads[:3] or ["(identity endpoints)"]),
                   "onyx_effect": "AUTHORITY_GRANT",
                   "why": f"identity layer ({am.provider or 'IdP'} / {am.protocol or '?'}) — "
                          "token audience / claim-trust / issuer validation, where 2025's "
                          "critical authz zero-days lived"})
    if not pp:
        am.notes.append("thin signal — acquire more surface (mobile/partner, federation) "
                        "before committing an architecture hypothesis (honest floor)")
    return am


def summarize(am: ArchitectureModel) -> dict:
    return {
        "topology": am.topology, "authz_pattern": am.authz_pattern,
        "identity": {"provider": am.provider, "protocol": am.protocol, "issuer": am.issuer,
                     "claims": am.identity_claims},
        "pressure_points": am.pressure_points, "notes": am.notes,
    }
