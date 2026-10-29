"""
IOLITE — core data models.

Pure-stdlib, deterministic. These types are the shared vocabulary every stage
speaks. Nothing here learns or scores by an anomaly model (QL4). Every fact that
enters the model carries its Provenance and an EvidenceTier (QL3).

The EffectClass strings are kept byte-identical to ONYX/AuthPath
(`authpath/models.py`) so the emitted contract is valid for ONYX's `scan` without
translation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Effect classes — MUST match authpath.models.EffectClass string values        #
# --------------------------------------------------------------------------- #

class Effect(str, Enum):
    OBJECT_ACCESS = "OBJECT_ACCESS"     # a GET that returns an addressable object (IDOR/BOLA surface)
    OWNERSHIP = "OWNERSHIP"             # mutation of a server-authoritative field (BOPLA)
    AUTHORITY = "AUTHORITY"             # function-level privileged action (BFLA)
    AUTHORITY_GRANT = "AUTHORITY_GRANT" # edit to the authority graph (IAM)
    PAYMENT = "PAYMENT"
    PRICE = "PRICE"
    STATE_GATE = "STATE_GATE"          # privileged state reachable only via a predecessor
    INVENTORY = "INVENTORY"
    COUPON = "COUPON"
    FIELD_PROJECTION = "FIELD_PROJECTION"
    CROSS_SURFACE = "CROSS_SURFACE"
    NONE = "NONE"                      # no security-relevant effect (dropped from contract)


# --------------------------------------------------------------------------- #
# Provenance & evidence tiers (QL3)                                            #
# --------------------------------------------------------------------------- #

class SourceKind(str, Enum):
    HAR = "har"                        # your authenticated capture
    JS = "js"                          # served frontend bundle
    SOURCEMAP = "sourcemap"            # .js.map (richest legal source)
    GRAPHQL = "graphql"                # introspection result
    OPENAPI = "openapi"                # exposed contract
    ARCHIVED_JS = "archived_js"        # historical bundle (wayback/commoncrawl)
    OSINT_CT = "osint_ct"              # certificate transparency
    OSINT_WAYBACK = "osint_wayback"    # historical URL feed
    OSINT_GITHUB = "osint_github"      # public code search
    MOBILE = "mobile"                  # your own installed app (APK/IPA)


class EvidenceTier(str, Enum):
    """Source-derived, never chosen. Higher = closer to a live authenticated fact."""
    T1_LIVE = "T1_LIVE"                # observed live in your authenticated session
    T2_CAPTURED = "T2_CAPTURED"        # present in a capture / served source you hold
    T3_ARCHIVED = "T3_ARCHIVED"        # historical / third-party archive (may be stale)
    T4_INFERRED = "T4_INFERRED"        # inferred from shape (weakest — needs confirmation)


# tier assigned by source, deterministically (QL3/QL4)
_TIER_BY_SOURCE = {
    SourceKind.HAR: EvidenceTier.T1_LIVE,
    SourceKind.JS: EvidenceTier.T2_CAPTURED,
    SourceKind.SOURCEMAP: EvidenceTier.T2_CAPTURED,
    SourceKind.GRAPHQL: EvidenceTier.T2_CAPTURED,
    SourceKind.OPENAPI: EvidenceTier.T2_CAPTURED,
    SourceKind.MOBILE: EvidenceTier.T2_CAPTURED,
    SourceKind.ARCHIVED_JS: EvidenceTier.T3_ARCHIVED,
    SourceKind.OSINT_WAYBACK: EvidenceTier.T3_ARCHIVED,
    SourceKind.OSINT_CT: EvidenceTier.T3_ARCHIVED,
    SourceKind.OSINT_GITHUB: EvidenceTier.T3_ARCHIVED,
}


def tier_for(source: SourceKind) -> EvidenceTier:
    return _TIER_BY_SOURCE.get(source, EvidenceTier.T4_INFERRED)


@dataclass(frozen=True)
class Provenance:
    """Where a fact provably came from (QL3). Immutable so it cannot drift."""
    source: SourceKind
    locator: str                       # file/url/offset — human-checkable
    tier: EvidenceTier = EvidenceTier.T4_INFERRED
    note: str = ""

    @staticmethod
    def of(source: SourceKind, locator: str, note: str = "") -> "Provenance":
        return Provenance(source=source, locator=locator, tier=tier_for(source), note=note)


# --------------------------------------------------------------------------- #
# Principals (ONYX-compatible)                                                 #
# --------------------------------------------------------------------------- #

@dataclass
class Principal:
    """An identity the OPERATOR controls (never fabricated — QL6)."""
    pid: str
    label: str
    auth: dict[str, str] = field(default_factory=dict)          # secret identity headers
    is_anonymous: bool = False
    profile_headers: dict[str, str] = field(default_factory=dict)  # coherent browser profile

    def to_spec(self, redact: bool = True) -> dict:
        auth = {k: f"$TOKEN_{self.pid}" for k in self.auth} if (redact and self.auth) else dict(self.auth)
        d = {"pid": self.pid, "label": self.label, "auth": auth}
        if self.is_anonymous:
            d["is_anonymous"] = True
        if self.profile_headers:
            d["profile_headers"] = dict(self.profile_headers)
        return d


# --------------------------------------------------------------------------- #
# Endpoints & the surface model                                               #
# --------------------------------------------------------------------------- #

@dataclass
class Endpoint:
    """A normalised endpoint: `METHOD /path/with/{id}` — the ONYX endpoint_key form."""
    method: str
    path: str                          # template form, id segments as {id}
    effect: Effect = Effect.NONE
    params: list[str] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)
    observed_ids: list[str] = field(default_factory=list)   # concrete ids seen for this template
    role_hints: list[str] = field(default_factory=list)     # e.g. "admin", "internal"
    # ranking (filled by triage.py) — transparent integer + reasons (QL4)
    risk: int = 0
    risk_reasons: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"

    @property
    def best_tier(self) -> EvidenceTier:
        order = [EvidenceTier.T1_LIVE, EvidenceTier.T2_CAPTURED,
                 EvidenceTier.T3_ARCHIVED, EvidenceTier.T4_INFERRED]
        seen = {p.tier for p in self.provenance}
        for t in order:
            if t in seen:
                return t
        return EvidenceTier.T4_INFERRED

    def merge(self, other: "Endpoint") -> None:
        """Fold another observation of the same key into this endpoint."""
        self.provenance.extend(other.provenance)
        for oid in other.observed_ids:
            if oid not in self.observed_ids:
                self.observed_ids.append(oid)
        for r in other.role_hints:
            if r not in self.role_hints:
                self.role_hints.append(r)
        for p in other.params:
            if p not in self.params:
                self.params.append(p)
        # keep the strongest (non-NONE) effect hint
        if self.effect == Effect.NONE and other.effect != Effect.NONE:
            self.effect = other.effect


@dataclass
class ObservedAccess:
    """A concrete legitimate access seen in a capture: principal read object_id at
    key. Carries the full request descriptor (path + query + body + carrier) so a
    cross-principal probe can reproduce the exact request as another principal."""
    principal_id: str
    endpoint_key: str
    object_id: str
    path: str
    method: str
    provenance: Provenance
    query: dict = field(default_factory=dict)
    body: Any = None
    carrier: str = "path"                       # which carrier held the primary id
    all_ids: list[str] = field(default_factory=list)  # every id this request addressed
    safe_read: bool = True                      # a read (GET, or a GraphQL query POST)


@dataclass
class SurfaceModel:
    """The full acquired surface — deterministic, provenance-carrying."""
    base_url: str = ""
    host: str = ""
    principals: list[Principal] = field(default_factory=list)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)   # key -> Endpoint
    accesses: list[ObservedAccess] = field(default_factory=list)
    # object graph: object_id -> set of principal_ids that legitimately held it
    holdings: dict[str, set[str]] = field(default_factory=dict)
    ghost_keys: set[str] = field(default_factory=set)              # endpoints only in archived sources
    hosts_seen: set[str] = field(default_factory=set)              # concrete in-scope hosts (for spec emission)
    notes: list[str] = field(default_factory=list)

    def add_endpoint(self, ep: Endpoint) -> None:
        cur = self.endpoints.get(ep.key)
        if cur is None:
            self.endpoints[ep.key] = ep
        else:
            cur.merge(ep)

    def add_access(self, acc: ObservedAccess) -> None:
        self.accesses.append(acc)
        for oid in (acc.all_ids or [acc.object_id]):
            self.holdings.setdefault(oid, set()).add(acc.principal_id)

    def sorted_endpoints(self) -> list[Endpoint]:
        # deterministic: risk desc, then key asc
        return sorted(self.endpoints.values(), key=lambda e: (-e.risk, e.key))
