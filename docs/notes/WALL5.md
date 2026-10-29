# WALL-5 — the relational authorization lattice (speaking the target's own authz mathematics)

> Goal of this wall: stop hunting known vulnerability *shapes* and start hunting the
> **divergence between intent and implementation** across the full authorization tuple
> space — the dimensions a class-per-endpoint model cannot express, which are exactly
> the ones that still pay on hyperscale targets after every scanner has swept the
> trivial `GET /obj/{id}` substitution.

## 1. Why the model had to change

Every earlier intent view in IOLITE (`reason.intent`, `reason.intent_graph`) is
**per-endpoint**: `endpoint_key -> AccessClass`. That is enough for classic horizontal
read-BOLA, and it is already strong. But the way large systems actually *decide*
authorization is **relational** — the Google-Zanzibar shape:

```
object#relation@user            e.g.  vault:1001#owner@alice
                                       report:7007#viewer@group:tenantT1#member
```

Permissions are **derived** from relation tuples through **rewrite rules** built from
set operations — union, intersection, and crucially **exclusion** — and computed by
**graph traversal** (owner ⊇ editor ⊇ viewer; viewer-of-parent ⇒ viewer-of-child;
member-of-tenant; *except* revoked/archived). See Zanzibar (Pang et al.), SpiceDB /
OpenFGA, AWS Cedar, OPA.

The bugs that survive on mature targets live in the dimensions a per-endpoint class is
structurally blind to:

| dimension | the bug it hides | per-endpoint class sees it? |
|---|---|---|
| **action** | write / delete / trigger on another's object | no — class is verb-agnostic |
| **field** | owner sets a server-authoritative property (BOPLA); client-supplied ownership field rebinds the object | no |
| **state** | access that should be excluded once archived / revoked / closed | no — class is stateless |
| **tenant** | crossing an org / workspace namespace | partially |
| **derivation** | a permission reachable only along a path (parent→child, group, id harvested at A used at B) | no |

Wall-5 lifts intent from a class per endpoint to a **derivation over the whole
`(principal, action, object, field, state, tenant)` tuple space**, built only from
evidence the target legally exposes.

## 2. The empirical target (what actually pays)

Grounded in an empirical taxonomy of 100+ bug-bounty BOLA disclosures. Six families,
and **five of them are documented automated-scanner blind spots**:

| family | share of real BOLA | scanner blind spot |
|---|---|---|
| direct read BOLA | 36.9% | — (this is the one tools catch) |
| **action-level** (write/delete/trigger) | **41.7%** | yes — most suites test GET only, miss ~46% |
| tenant isolation | 8.3% | yes — needs per-tenant sessions |
| **workflow-context** (state) | 6.0% | yes — stateless scanners cannot see it |
| **chained** (harvest id → reuse) | 4.8% | yes — needs cross-endpoint id tracking |
| **object rebinding** (ownership field) | 2.4% | yes — needs request-schema analysis |

85.7% horizontal, 11.9% vertical; deletion ~15.5% (high-impact, often irreversible);
35.7% High/Critical, concentrated in action-level. The boundary between API1 (BOLA) and
API5 (BFLA) is where real-world clustering now happens — so Wall-5 models both as one
lattice.

## 3. The lattice — `relation_model.py`

`build_lattice(SurfaceModel)` assembles, deterministically and from observed evidence
only:

- **object-types** from endpoint path tokens; **fields** from request bodies + params,
  each classified `server_auth` (role, price, status, is_admin, …), `ownership`
  (owner_id, account_id, tenant_id, …) or `plain`;
- **objects** with their **holders** (who legitimately held the id), **tenant**, and last
  observed **lifecycle state**;
- per-endpoint **intent** (reusing `reason.infer_intent`, joint/refined).

One derivation answers everything:

```
intended_decision(principal, action, *, endpoint_key, oid, field_name, field_value, state)
      -> (ALLOW | DENY | UNKNOWN, derivation)
```

Rules (raise-only, least-privilege — can only move toward DENY, so it can never silence
a real bug; worst case is a wasted probe the oracle discards):

1. **state exclusion** — a terminal state (`archived/revoked/closed/…`) denies mutation
   regardless of ownership (the Zanzibar exclusion / "new-enemy" rule).
2. **field** — a `server_auth` field is not owner-writable (BOPLA); an `ownership` field
   set to another principal is object rebinding.
3. **action-lift** — `write ≥ read`: a mutating action on an addressable object is at
   least owner-scoped even if the read looked weak (the action-level family).
4. **ownership / tenant / privilege** — owner-only ⇒ only a holder; tenant-isolated ⇒
   only the owning tenant; role/admin ⇒ only the privileged principal.

`UNKNOWN` (no signal / unobserved holder) becomes a **lead**, never a silent ALLOW.

## 4. The wide enumerator — `divergence.py`

`enumerate_divergences(model, lattice)` walks every observed legitimate access (a
reproducible request) and every type with a write surface, and emits every **reachable
tuple the lattice DENIES**, each carrying its derivation as a *proof obligation*. Eight
families: `read_bola, action_bola, bopla_field, rebinding, workflow_state, chained,
tenant, vertical`. Generators only **PROPOSE** (QL5); own principals only (QL6);
deterministic (QL4). EV priors rank them for scheduling (deletion/tenant/BFLA highest).

## 5. The one sound oracle — `metamorphic.py`

Generators propose widely; a **single** gate disposes, so widening recall can never
raise the false-positive rate. The gate is a **metamorphic relation**, not an absolute
oracle (no one can enumerate the "correct" response of a hyperscale target, but everyone
can state a relation two executions must satisfy):

> **MR_authz** — replay the same request as two principals. For a resource the attacker
> cannot legitimately reach, the responses MUST differ on the security-bearing value. A
> VIOLATION is when the denied principal reproduces the holder's private value — proven
> by **value presence, never a status code**.

Composed with the false-positive filters from the metamorphic-security-testing
literature and IOLITE's own walls, every one of which turns uncertainty into
ABSTAIN/LEAD rather than a claim:

- **surface-reachability** — the attacker must be outside intent (not authorized via its
  own surface), else it is not a boundary;
- **privilege hierarchy** — the attacker must not legitimately supervise the holder;
- **error filtering** — the holder's baseline request must be valid/non-error;
- **stability + causal** — the value must be stable across draws (flaky → ABSTAIN),
  independent controls must agree (observer-dependent → ABSTAIN), and a no-relationship
  control must be denied (if a control also gets in, the relationship is not the cause →
  public-by-design → ABSTAIN);
- **write safety (Wall-3)** — an irreversible write is REFUSED before execution; a
  confirmed write must be net-zero restored or the run HALTs.

Result: FP=0 by construction, no harm by construction, and a **replayable certificate**
on every CONFIRMED finding.

## 6. The wired kill-chain — `kill_chain.py`

```
GENERATE (wide, from the real SurfaceModel)
  → REDUCE   (authorization-equivalence quotient — representatives, not instances)
  → SCHEDULE (EV priority under a hard budget; the rest are ranked leads)
  → CONFIRM  (the one metamorphic gate; provider = offline evidence OR live ONYX Δstate)
  → CERTIFY  (replayable certificate)
  → REPORT   (EV-ranked dossiers + per-family coverage + lattice summary)
```

**Separation of powers.** GENERATE is fully wired and runs offline on the real model.
CONFIRM is a pluggable `evidence_provider`: offline it is honest — it emits LEADs
carrying the exact live probe and the intent-deny derivation, REFUSES irreversible
writes, and marks a legitimately-authorized attacker CLEAN; it never fabricates a
confirmation. Live, ONYX's Δstate is the provider. This is IOLITE's founding invariant
("IOLITE proposes, ONYX disposes") made literal.

Run it: `python3 -m iolite.intent killchain`.

## 7. Legal + safety invariants (unchanged, load-bearing)

Scope-guard on every request; own principals only; non-destructive by default; the
rate governor; preflight fail-closed; nothing fires without the operator. Wall-5 adds no
new network capability — it is a smarter *generator* feeding the same gated, human-driven
live step. Authorized-testing Rules of Engagement still bound every run.

## 8. Honest floor

Offline the engine PROPOSES; the live ONYX Δstate DISPOSES. Recall is bounded by which
generators and controls exist and by budget; chained detection is bounded by observed
id-disclosure; the field T1 run and the matched-control provisioning for live causal
falsification remain. The transfer gap is **narrowed** — the generator now speaks the
target's own authorization mathematics instead of a fixed payload list — never
eliminated.

## References

- Pang et al., *Zanzibar: Google's Consistent, Global Authorization System* (USENIX ATC 2019).
- OWASP API Security Top 10 (2023): API1 BOLA, API3 BOPLA, API5 BFLA.
- Empirical BOLA taxonomy from 100+ bug-bounty disclosures (families + scanner blind spots).
- Mai et al., *Metamorphic Security Testing for Web Systems* (metamorphic relations + FP filters).
- AuthScope (CCS 2017) — differential authorization testing.
- SpiceDB / OpenFGA / AWS Cedar / OPA — relationship- and policy-based access control in practice.
