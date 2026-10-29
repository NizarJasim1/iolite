# Wall-1 — the deny-signal / recall wall: critique, breakthroughs, status

## The wall (precise)
The sound decision rule fires a finding only when **every** intent consistent with
the evidence denies an access that enforcement permits. Bounding intent from above
needs **negative evidence** (intent-deny). The strongest targets volunteer almost
none: well-behaved clients emit few 403s, least-privilege serializers hide owner
markers, behaviour is uniform. So the rule abstains → recall collapses exactly
where we need it. Root cause is epistemic: identifying a concept from **positive
data only is underdetermined** (Gold); observation is confounded (Pearl's ladder).

## The break — interventional identification (seeing → doing)
We do not wait for the target to reveal intent; we **act**. Owning the principals,
we exercise the app's own authorization affordances (create a private object as A;
later: share/revoke/transfer). Using a "private" affordance is the developer's own
**declaration** that the object is denied to outsiders — a ground-truth negative we
manufacture on demand, on any target, soundly. This is RL1-safe (constructed/declared,
not induced) and climbs from confounded observation to identifiable intervention.
It is also an active-learning move: we manufacture the labels passive capture cannot.

## The four root ideas (developed across the Wall-1 sessions)
1. **Version-space decision (Mitchell).** Don't reconstruct one intent; bound the
   set of consistent intents by [S,G] and fire only when the most-general consistent
   intent still denies. Sound ⇒ zero-FP; abstains under ambiguity. (`evidence/wall1_construction.py`)
2. **Value-presence Δstate with a discriminating guard.** A leak is proven iff B
   reproduces a value **unique to A's object** (A1 vs A2 vs B1 differential, minus
   probe-supplied keys). Kills the shared-default false positive. (`src/authz_engine.py`)
3. **Metamorphic non-interference oracle.** Perturb A's OWN secret, observe B; if
   B's observable depends on it → leak, even when no verbatim value appears
   (derived/aggregate/boolean channels). Catches what value-presence cannot.
   (`evidence/metamorphic_kernel_v2.py`)
4. **Bounded capability reachability (HRU / take-grant).** Emergent multi-step
   over-grants as a forbidden capability reachable within k affordance operations;
   witness = the path. (`evidence/intent_kernel.py`)

## What is SOLVED (verified on an independent target)
- The recall-killer is broken: intent-deny is **manufactured by intervention**, so
  the engine finds real BOLA on a target it did not author (OWASP VAmPI), end-to-end,
  with a sound value-presence proof and zero-FP on secure endpoints.

## What is NOT solved here (honest, deferred)
- **Operational dependency on Wall-3 (safe mutation):** construction = writes;
  cleanup of created test objects and the transactional perturb→restore for the
  metamorphic oracle belong to Wall-3 (next).
- **Conditional soundness:** the manufactured negative is sound relative to an
  isolation the operator establishes and can verify (cross-org / explicit private
  affordance), not an absolute.
- **Provisioning:** needs ≥2 owned principals (ideally 2 orgs); privileged
  principals you cannot provision are an honest coverage boundary.
- **Novelty ceiling:** verbatim + derived leaks are covered; broader/novel classes
  need the dependency-algebra + reachability work (later walls).

## Verdict
Wall-1's **core** (sound negatives on opaque targets, confirmed by Δstate) is
solved and demonstrated against an independent target — not absolute closure. The
mutation-safety seam is precisely **Wall-3**.
