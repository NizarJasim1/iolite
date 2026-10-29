"""
policy_learn.py — LEARN the authorization policy by CONTRAST, from deep observations.

This is the stronger, precise intent builder the self-critique demanded. Instead of guessing
intent from field names, it learns the access-control FUNCTION from what actually happened:

  * OWNERSHIP is read, not guessed — from the server-stated `owner_id` matched to a
    principal's JWT subject (`sub`). The object's owner is a fact, not a heuristic.
  * The BOUNDARY is learned by CONTRAST — owner gets ALLOW+value while another principal gets
    403/401/404 on the same object/type ⇒ an ENFORCED owner-scoped boundary (confidence grows
    with every confirming observation). This is the single most reliable authz signal and v1.18
    ignored it entirely.
  * A VIOLATION is the opposite contrast — a non-owner gets ALLOW and reproduces the owner's
    private value ⇒ BOLA, now pinned to the explicit owner where known (far fewer false links).
  * ENUMERATION exposure — a principal's list/nested response embeds objects owned by OTHERS
    ⇒ it can harvest foreign ids (the chained-BOLA precursor).

Deterministic, incremental (QL4). Own accounts only (QL6).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .defense import is_authz_denial


@dataclass
class Signal:
    kind: str            # corroborated | boundary_learned | enforcement_denial | enumeration_leak
    severity: str
    title: str
    detail: str = ""
    data: dict = field(default_factory=dict)


@dataclass
class TypePolicy:
    otype: str
    owner_allow: int = 0      # owner got ALLOW+value
    nonowner_deny: int = 0    # a non-owner was denied (boundary enforced here)
    violations: int = 0       # a non-owner got the owner's value
    tenant_scoped: int = 0
    role_guarded: int = 0

    @property
    def intent(self) -> str:
        if self.role_guarded and self.role_guarded >= self.owner_allow:
            return "role_restricted"
        if self.tenant_scoped:
            return "tenant_isolated"
        if self.owner_allow:
            return "owner_scoped"
        return "unknown"

    @property
    def enforced(self) -> bool:
        return self.nonowner_deny > 0

    @property
    def confidence(self) -> str:
        n = self.owner_allow + self.nonowner_deny
        return "high" if n >= 4 else ("medium" if n >= 2 else "low")


class PolicyLearner:
    def __init__(self):
        self.sub_principal: dict = {}       # JWT sub -> principal label
        self.principal_sub: dict = {}
        self.principal_role: dict = {}
        self.principal_tenant: dict = {}
        self.obj_owner: dict = {}           # oid -> owning principal (resolved)
        self.obj_owner_ref: dict = {}       # oid -> server-stated owner id
        self.obj_tenant: dict = {}
        self.obj_type: dict = {}
        self.obj_state: dict = {}
        self.obj_values: dict = {}          # oid -> {principal: set(disc)}
        self.types: dict = {}               # otype -> TypePolicy
        self._boundary_said: set = set()
        self._finding: set = set()
        self._enum_said: set = set()
        self.violations: list = []          # corroborated findings (dicts)

    # ------------------------------------------------------------------ update
    def _type(self, t: str) -> TypePolicy:
        return self.types.setdefault(t or "?", TypePolicy(t or "?"))

    def _resolve_owner(self, obs) -> str:
        """Who owns obs.object_id — explicit owner_ref matched to a principal, else the
        principal whose own sub equals owner_ref, else a tentative first-allow owner."""
        oid = obs.object_id
        if not oid:
            return ""
        if oid in self.obj_owner:
            return self.obj_owner[oid]
        # explicit server-stated owner
        if obs.owner_ref:
            self.obj_owner_ref[oid] = obs.owner_ref
            if obs.sub and obs.owner_ref == obs.sub:
                self.obj_owner[oid] = obs.principal
                return obs.principal
            if obs.owner_ref in self.sub_principal:
                self.obj_owner[oid] = self.sub_principal[obs.owner_ref]
                return self.obj_owner[oid]
        # tentative: a successful create, or the first principal to legitimately read+value
        if obs.enforce == "ALLOW" and obs.got_value and (not obs.owner_ref or obs.owner_ref == obs.sub):
            self.obj_owner.setdefault(oid, obs.principal)
            return self.obj_owner.get(oid, "")
        return self.obj_owner.get(oid, "")

    def update(self, obs) -> list:
        sig: list = []
        # identity
        if obs.sub:
            self.principal_sub[obs.principal] = obs.sub
            self.sub_principal[obs.sub] = obs.principal
        if obs.role:
            self.principal_role[obs.principal] = obs.role
        if obs.tenant:
            self.principal_tenant[obs.principal] = obs.tenant
        # enumeration runs even for collection responses (which address no single object)
        self._check_enumeration(obs, sig)
        if not obs.object_id:
            # still learn role-guarded endpoints from denials on privileged paths
            self._maybe_role_guard(obs, sig)
            return sig

        oid = obs.object_id
        self.obj_type[oid] = obs.object_type
        if obs.state:
            self.obj_state[oid] = obs.state
        self.obj_values.setdefault(oid, {}).setdefault(obs.principal, set()).update(obs.disc_values)

        owner = self._resolve_owner(obs)
        tp = self._type(obs.object_type)
        is_owner = (owner == obs.principal) or (obs.owner_ref and obs.sub and obs.owner_ref == obs.sub)

        # tenant of the object: the OWNER's stated tenant is authoritative; also learn the
        # acting principal's tenant from the objects they own (or their JWT claim).
        if obs.tenant_ref:
            if is_owner:
                self.obj_tenant[oid] = obs.tenant_ref
                self.principal_tenant.setdefault(obs.principal, obs.tenant_ref)
            else:
                self.obj_tenant.setdefault(oid, obs.tenant_ref)

        # owner success
        if obs.enforce == "ALLOW" and obs.got_value and is_owner:
            tp.owner_allow += 1

        # boundary enforced: a NON-owner is CLEANLY denied (a WAF/bot/challenge/expiry block is
        # NOT an authorization boundary and must not teach one — the key precision fix for
        # hardened targets).
        clean_denial = is_authz_denial(obs.defense) or obs.enforce == "MASKED"
        if owner and owner != obs.principal and clean_denial:
            tp.nonowner_deny += 1
            sig.append(Signal("enforcement_denial", "info",
                              f"boundary evidence: {obs.principal} denied ({obs.status}) on {owner}'s {oid}",
                              f"{obs.object_type} enforces ownership here", {"type": obs.object_type}))
            key = ("boundary", obs.object_type)
            if tp.owner_allow > 0 and key not in self._boundary_said:
                self._boundary_said.add(key)
                sig.append(Signal("boundary_learned", "info",
                                  f"intent LEARNED: {obs.object_type} is owner-scoped AND enforced "
                                  f"(owner allowed, non-owner denied) [{tp.confidence}]",
                                  "a confirmed, enforced boundary — not a guess",
                                  {"type": obs.object_type, "confidence": tp.confidence}))

        # VIOLATION: a non-owner got the value
        if owner and owner != obs.principal and obs.enforce == "ALLOW" and obs.got_value:
            owner_vals = self.obj_values.get(oid, {}).get(owner, set())
            hit = sorted((obs.disc_values & owner_vals)) or (
                [f"owner_id={obs.owner_ref}"] if obs.owner_ref and obs.owner_ref != obs.sub else [])
            if hit:
                fkey = ("bola", oid, obs.principal)
                if fkey not in self._finding:
                    self._finding.add(fkey)
                    tp.violations += 1
                    v = {"family": "read_bola", "object_id": oid, "owner": owner,
                         "attacker": obs.principal, "endpoint_key": obs.endpoint_key,
                         "evidence": f"{obs.principal} reproduced {owner}'s private value(s) {hit[:2]} for {oid}",
                         "severity": "high",
                         "cert": {"proof": "non-owner reproduced the owner's object-specific private "
                                           "value (value-presence Δstate); owner read from server-stated "
                                           "owner_id where present — observed live, 0 crafted requests",
                                  "object": oid, "owner": owner, "attacker": obs.principal,
                                  "replayable": True, "write_safe": True}}
                    self.violations.append(v)
                    sig.append(Signal("corroborated", "high",
                                      f"BOLA confirmed live: {obs.principal} read {owner}'s {oid}",
                                      v["evidence"], {"family": "read_bola", "object": oid}))

        # cross-tenant: a principal outside the object's owning tenant received it (ALLOW).
        # Crossing the namespace is itself the bug, so no private value is required.
        ot = self.obj_tenant.get(oid, "")
        accessor_tenant = obs.tenant or self.principal_tenant.get(obs.principal, "") or obs.tenant_ref
        if (ot and accessor_tenant and accessor_tenant != ot and obs.enforce == "ALLOW"
                and (owner != obs.principal or not owner)):
            fkey = ("tenant", oid, obs.principal)
            if fkey not in self._finding:
                self._finding.add(fkey)
                tp.tenant_scoped += 1
                v = {"family": "tenant", "object_id": oid, "owner": f"tenant:{ot}",
                     "attacker": obs.principal, "endpoint_key": obs.endpoint_key,
                     "evidence": f"principal in tenant {accessor_tenant} received object {oid} of tenant {ot}",
                     "severity": "critical",
                     "cert": {"proof": "cross-tenant object delivered to a foreign-tenant session — live",
                              "object": oid, "foreign_tenant": accessor_tenant, "owner_tenant": ot,
                              "replayable": True, "write_safe": True}}
                self.violations.append(v)
                sig.append(Signal("corroborated", "critical",
                                  f"cross-tenant confirmed live: {oid} {ot}→{obs.tenant}",
                                  v["evidence"], {"family": "tenant", "object": oid}))

        return sig

    def _check_enumeration(self, obs, sig):
        """A principal's list/nested response embeds objects owned by OTHERS ⇒ it can harvest
        foreign ids (the chained-BOLA precursor). Runs for collections too (no single oid)."""
        for emb in obs.embedded:
            eo = emb.get("owner", "")
            eowner = self.sub_principal.get(eo, "") if eo else ""
            if (eo and obs.sub and eo != obs.sub) or (eowner and eowner != obs.principal):
                k = ("enum", obs.object_type, obs.principal)
                if k not in self._enum_said:
                    self._enum_said.add(k)
                    sig.append(Signal("enumeration_leak", "medium",
                                      f"enumeration exposure: {obs.principal} can list ids owned by others "
                                      f"via {obs.endpoint_key}",
                                      "harvested foreign object ids (chained-BOLA precursor)",
                                      {"type": obs.object_type, "sample_id": emb.get("id", "")}))
                break

    def _maybe_role_guard(self, obs, sig):
        pl = obs.url_path.lower()
        if ("/admin" in pl or "/internal" in pl or "/staff" in pl):
            tp = self._type(obs.object_type or "admin")
            if obs.enforce == "ALLOW":
                tp.role_guarded += 1
            elif obs.enforce in ("AUTHZ_DENY", "AUTHN_DENY"):
                tp.nonowner_deny += 1

    # ----------------------------------------------------------------- summary
    def summary(self) -> dict:
        pol = {}
        for t, tp in sorted(self.types.items()):
            pol[t] = {"intent": tp.intent, "enforced": tp.enforced,
                      "confidence": tp.confidence, "owner_allow": tp.owner_allow,
                      "nonowner_deny": tp.nonowner_deny, "violations": tp.violations}
        return {
            "principals": {p: {"role": self.principal_role.get(p, ""),
                               "tenant": self.principal_tenant.get(p, ""),
                               "sub": self.principal_sub.get(p, "")} for p in self.principal_sub},
            "object_types": pol,
            "relationships": {"owners_known": len(self.obj_owner),
                              "tenanted_objects": len(self.obj_tenant)},
            "violations": len(self.violations),
        }
