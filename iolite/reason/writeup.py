"""
reason · writeup — the last mile to payout. Turn a candidate (a hypothesis, or an
ONYX-confirmed capability) into a submission-ready BOLA/BFLA report.

Offline, a write-up is a DRAFT clearly marked "pending ONYX live confirmation" — it
never claims a finding reason did not prove. A live CEGAR run marks the confirmed
ones as ONYX-Δstate-confirmed. Own-accounts / in-scope language is always included.

Deterministic (QL4). No verdict is invented (QL5).
"""

from __future__ import annotations

from dataclasses import dataclass

from .differ import ReasonCandidate
from .amplify import ImpactScore
from ..roe import Engagement

# family → (vuln class label, one-line mechanism, remediation)
_CLASS = {
    "intent_gap": ("Broken Object Level Authorization (BOLA / IDOR)",
                   "a peer principal reads an object it does not own"),
    "observed_object_gap": ("Broken Object Level Authorization (BOLA / IDOR)",
                            "a peer principal reads an object it does not own"),
    "intent_bfla": ("Broken Function Level Authorization (BFLA)",
                    "a lower-privilege principal reaches a privileged function"),
    "declared_unreached_gap": ("Broken Function Level Authorization (BFLA)",
                               "a lower-privilege principal reaches an admin endpoint mined from leakage"),
    "assumption_internal": ("Broken Function Level Authorization (BFLA)",
                            "an internal/debug endpoint is reachable by a normal user"),
    "assumption_client_role": ("Privilege escalation via client-trusted role",
                               "the server honors a client-supplied role/permission"),
    "assumption_enum": ("IDOR via identifier enumeration",
                        "sequential ids let a user read adjacent objects"),
    "assumption_nested_child": ("Second-order IDOR (nested resource)",
                                "the child of an owned parent is not re-authorized"),
    "invariant_information_flow": ("Second-order IDOR (over-fetch / expand)",
                                   "an expand/include leaks a related object without re-authz"),
    "assumption_lifecycle": ("Broken object-lifecycle authorization",
                             "a deleted/archived object is still accessible"),
    "invariant_conservation": ("Business-logic / value manipulation",
                               "a value-bearing endpoint yields a non-conserving total"),
    "invariant_freshness": ("Authorization token replay",
                            "a grant/token is reusable across objects or uses"),
    "invariant_non_interference": ("Authorization side-channel (existence oracle)",
                                   "responses leak existence/ownership of others' data"),
    "invariant_cross_surface": ("Cross-surface authorization inconsistency (BOLA)",
                                "an object guarded on one surface is exposed on another"),
    "assumption_export": ("Export authorization bypass",
                          "an export/report does not re-apply the query's authorization"),
    "assumption_webhook": ("Webhook secret disclosure (BOLA)",
                           "a peer reads a webhook resource that leaks its signing secret"),
    "chain_cross_surface": ("Chained BOLA (cross-surface escalation)",
                            "a proven access is extended to another surface"),
    "chain_privilege_lateral": ("Chained BFLA (privilege-lateral)",
                                "a proven privileged access unlocks sibling admin endpoints"),
    "chain_disclosure": ("Chained BOLA (identifier disclosure)",
                         "an id leaked by one access is used to reach another object"),
    "amplify_scale": ("BOLA at scale",
                      "adjacent ids demonstrate the blast radius is the whole collection"),
}
_DEFAULT = ("Broken authorization", "an access-control gap between intent and enforcement")

_REMEDIATION = (
    "Derive object ownership from the authenticated session server-side on every "
    "request; scope authorization at the database query layer, not after retrieval. "
    "Never read ownership/role from a request body, query param or header. "
    "Re-evaluate authorization on lifecycle changes (archive/delete) and on every "
    "surface that addresses the object (web, GraphQL, mobile API, export)."
)


@dataclass
class Writeup:
    title: str
    severity: str
    markdown: str


def _repro(c: ReasonCandidate) -> str:
    holder = c.holder_pid or "the owner"
    attacker = c.probe_pids[0] if c.probe_pids else "your second account"
    q = ("?" + "&".join(f"{k}={v}" for k, v in sorted((c.query or {}).items()))) if c.query else ""
    lines = [
        f"1. Authenticate as **account {holder}** (yours) and observe the legitimate "
        f"request `{c.method} {c.path}{q}` returning that account's object"
        + (f" `{c.object_id}`." if c.object_id else "."),
        f"2. Authenticate as **account {attacker}** (also yours, different principal).",
        f"3. Replay the exact request `{c.method} {c.path}{q}` as account {attacker}.",
        "4. Observe that account " + attacker + " receives "
        + ("account " + holder + "'s object" if c.holder_pid else "data it is not authorized to see")
        + " — confirmed by ONYX Δstate read-back (the returned state changed for a "
          "principal that must be denied).",
    ]
    return "\n".join(lines)


def writeup(candidate: ReasonCandidate, engagement: Engagement,
            impact: ImpactScore | None = None, confirmed: bool = False,
            evidence: str = "") -> Writeup:
    band = (impact.band if impact else "medium").upper()
    label, mech = _CLASS.get(candidate.family, _DEFAULT)
    status = ("**Confirmed by ONYX Δstate.**" if confirmed
              else "**DRAFT — pending ONYX live confirmation** (run with `--cegar` and an "
                   "attested engagement against the live target).")
    prog = engagement.program or "the target"
    title = f"{label} on {candidate.method} {candidate.path}"
    md = f"""# {title}

**Severity (estimated): {band}**  ·  Program: {prog}  ·  {status}

## Summary
A {label} was identified: {mech}. The endpoint `{candidate.method} {candidate.path}`
is intended to be **{candidate.intent_class}** (evidence: reconstructed intent), but
enforcement allows a principal that should be denied. ONYX confirms the gap by
deterministic Δstate read-back (zero false positives).

## Steps to reproduce (own accounts only, in scope)
{_repro(candidate)}

## Impact
{impact.narrative if impact else 'Unauthorized cross-principal access to protected objects.'}

## Evidence
{evidence or 'ONYX Δstate: the response state for the unauthorized principal changed to reveal the protected object (see attached ONYX report / spec probe `' + candidate.cand_key + '`).'}

## Remediation
{_REMEDIATION}

## Authorization & scope
All testing used only accounts I control, strictly within the program's written
scope, read-only where possible, non-destructive. No third-party data was accessed.
"""
    return Writeup(title=title, severity=band, markdown=md)


def writeups_from_report(rep, engagement: Engagement, confirmed_keys=None,
                         top: int = 5) -> list[Writeup]:
    """Draft write-ups for the top EXPECTED-PAYOUT candidates (impact × novelty);
    mark any in `confirmed_keys` (from a live CEGAR trace) as ONYX-confirmed."""
    confirmed_keys = set(confirmed_keys or [])
    outs = []
    for c in rep.ranked_by_priority()[:top]:
        outs.append(writeup(c, engagement, impact=rep.impact.get(c.cand_key),
                            confirmed=c.cand_key in confirmed_keys))
    return outs


def quickwin_writeup(q, engagement: Engagement) -> Writeup:
    """A short report for a passive quick-win finding (self-evident evidence)."""
    prog = engagement.program or "the target"
    lead = ("\n\n> This is a LEAD — confirm the resource is live/accessible before "
            "reporting." if getattr(q, "is_lead", False) else "")
    title = q.kind
    md = f"""# {title}

**Severity (estimated): {q.severity.upper()}**  ·  Program: {prog}  ·  **Passive finding (self-evident evidence — not an ONYX Δstate confirmation).**

## Summary
{q.kind} observed in legally-captured, publicly-served material.{lead}

## Evidence
Location: `{q.where}`
Detail: {q.evidence}
Confidence: {q.confidence}

## Impact
Depending on the value exposed, this can enable account/service compromise, data
disclosure, or further attacks. Validate the concrete impact before submission.

## Remediation
Rotate/revoke any exposed credential immediately; remove secrets from client-served
assets and load them server-side only. Restrict CORS to explicit trusted origins and
never combine a wildcard/reflected origin with credentials. Return generic errors to
clients and log details server-side. Block access to sensitive paths.

## Authorization & scope
Found passively in material the target serves publicly / in my own captured session,
strictly within the program's scope. No exploitation was performed.
"""
    return Writeup(title=title, severity=q.severity.upper(), markdown=md)
