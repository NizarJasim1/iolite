"""
Rules-of-Engagement — the legal ceiling, made explicit and carried with every run.

A IOLITE run is only legal because a human asserted an authorisation basis. `roe.py`
turns that assertion into a structured, signed-off declaration that:
  * builds the ScopeConfig the Scope-Guard enforces,
  * is embedded in the emitted ONYX spec (`_engagement`) so a reviewer can see the
    authorisation basis of the whole corpus,
  * refuses to produce a live/replay-capable scope unless the operator has
    explicitly attested to authorisation.

IOLITE cannot verify your authorisation for you (QL1 boundary). It CAN refuse to
run request-bearing stages until you have attested, in writing, that you hold it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict

from .scope_guard import ScopeConfig


@dataclass
class Engagement:
    """A signed-off rules-of-engagement declaration."""
    program: str = ""                          # e.g. "Acme VDP (HackerOne)"
    authorized_by: str = ""                    # the authorisation basis (scope URL / grant)
    operator: str = ""                         # who is running this
    in_scope_hosts: list[str] = field(default_factory=list)
    out_of_scope_hosts: list[str] = field(default_factory=list)
    automation_permitted: bool = False
    allow_destructive: bool = False
    dry_run: bool = True
    own_accounts_only: bool = True             # cross-principal proof uses only your accounts
    max_requests_per_min: int = 30             # human-paced ceiling (advisory to live layer)
    attestation: str = ""                      # operator's explicit written attestation

    # ---- construction --------------------------------------------------- #
    @staticmethod
    def template() -> "Engagement":
        return Engagement(
            program="<program name, e.g. Acme VDP>",
            authorized_by="<public scope URL or explicit written permission>",
            operator="<you>",
            in_scope_hosts=["api.example.com"],
            out_of_scope_hosts=["internal.example.com"],
            automation_permitted=False,
            allow_destructive=False,
            dry_run=True,
            own_accounts_only=True,
            max_requests_per_min=30,
            attestation="I confirm I am authorised to test the in-scope hosts and "
                        "that all accounts used are mine, within the target's ToS.",
        )

    @staticmethod
    def load(path: str) -> "Engagement":
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        known = {f for f in Engagement.__dataclass_fields__}
        return Engagement(**{k: v for k, v in d.items() if k in known})

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2, sort_keys=True)

    # ---- enforcement ---------------------------------------------------- #
    def scope_config(self) -> ScopeConfig:
        return ScopeConfig(
            allowed_hosts=list(self.in_scope_hosts),
            denied_hosts=list(self.out_of_scope_hosts),   # out-of-scope wins (QL1)
            dry_run=bool(self.dry_run),
            automation_permitted=bool(self.automation_permitted),
            allow_destructive=bool(self.allow_destructive),
        )

    def attested(self) -> bool:
        """A live/replay-capable run requires a non-placeholder attestation and a
        real authorisation basis. Fail-safe: missing ⇒ not attested."""
        att = (self.attestation or "").strip()
        auth = (self.authorized_by or "").strip()
        placeholder = att.startswith("<") or auth.startswith("<") or not att or not auth
        return not placeholder

    def as_manifest(self) -> dict:
        """The block embedded into the emitted ONYX spec for auditability."""
        return {
            "program": self.program,
            "authorized_by": self.authorized_by,
            "operator": self.operator,
            "own_accounts_only": self.own_accounts_only,
            "automation_permitted": self.automation_permitted,
            "allow_destructive": self.allow_destructive,
            "dry_run": self.dry_run,
            "attested": self.attested(),
        }
