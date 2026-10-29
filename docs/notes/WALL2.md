# Wall-2 — scale / decidability: make the sound engine WORK on a large target

Walls 1/3/4 make the engine SOUND; Wall-2 makes it TRACTABLE at real-target scale,
without which the rest is unusable. Three leaps, each a runnable kernel:

## 1. Quotient reduction (`wall2_scale.py`)
Authorization is almost always uniform by (role-class × object-TYPE × field-class),
not per instance. Test ONE representative per class → the millions-wide
`principal×instance×field` space collapses to dozens (**480,000 → 36, 13,333×**). Sound;
and a violated uniformity assumption is ITSELF a finding (per-instance inconsistency).
Best-first under a hard budget; unspent candidates stay ranked leads (graceful, never
silent truncation). Decidable fragment + bounded depth stated; outside ⇒ abstain, never hang.

## 2. Learned partition + EV bandit (`wall2_deep.py`)
- The partition is **discovered from observed behavior** (same behavior-signature ⇒ same
  class) and CEGAR-split; a misbehaving cohort inside a type is auto-flagged as a finding.
- A **UCB bandit** spends the scarce confirmation budget to maximize **expected value ($)**,
  learned online — budget flows to the services that actually yield. **+45% bounty at equal
  budget** vs uniform allocation. Output: an EV worklist + a coverage report.

## 3. Zero-FP + widened detection (`wall2_zerofp.py`)
The architectural invariant: **PROPOSE widely, DISPOSE through one sound certifying gate.**
- **Zero-FP (measured):** a finding carries a replayable **certificate** that an
  **independent verifier** must re-derive from a second evidence draw (else DROP); a
  continuous **decoy stream** measures the live FP rate at **0** — incl. flaky,
  observer-dependent and unreproducible adversarial decoys.
- **Wider detection:** multiple generators (single-step, chained/HRU, cross-surface,
  state-gated) all funnel into the same gate → detection widened **1→4 classes at FP=0**.
  Adding a generator **cannot raise FP** (FP is a property of the gate alone).

## Honest floor (not closed)
- Recall is bounded by which generators/controls exist (a frontier of unmodeled classes)
  and by the confirmation budget; a single needle instance can evade sampling.
- "Zero-FP" = **measured** on decoys + certificate-gated + independently re-derived, not a
  proof for every possible adversarial input (a perfectly-reproducible liar is the residual,
  and the certificate makes even that auditable).
- Wall-2 is a SCHEDULING/ABSTRACTION layer: it is structurally incapable of creating an FP
  (the sound gate is the only disposer), so all its limits are recall/efficiency bounds.

## Verdict
The sound engine now scales to large targets (quotient), spends budget to maximize bounty
(EV bandit), and widens detection while holding FP at a measured zero (propose/dispose).
This is the last of the four walls.
