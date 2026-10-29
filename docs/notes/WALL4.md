# Wall-4 — soundness: zero-FP must not depend on the hypothesis algebra

## The wall
The version-space rule ("fire iff every H-consistent intent denies") is sound ONLY if the
true policy π_true is expressible in the hypothesis algebra H. Real authz uses predicates
outside any fixed H (team/project, time, geo, risk). If π_true ∉ H the rule FALSE-POSITIVES
on a legitimate access — fatal, because zero-FP is the entire value in bug bounty.

## The breaks (each proven by a runnable kernel in `docs/wall4_evidence/`)
1. **H-independent findings** (`wall4_soundness.py`): a FINDING rests ONLY on an
   interventionally CONSTRUCTED intent-deny + Δstate; H-inferences are demoted to LEADS,
   never findings. Zero-FP becomes independent of H's completeness.
2. **Causal (not correlational) falsification** (`wall4_causal.py`): don't ask "does a
   relationship exist?" ask "is the relationship the CAUSE?" — via a NO-RELATIONSHIP
   CONTROL principal. If the control also gets in → the relationship is not the cause →
   real BOLA (recovers recall the naive gate loses to over-abstention). If only the
   related principal gets in → benign → abstain. No FP either way.
3. **Hardening, from new angles** (`wall4.py` = the engine module):
   - **Stability voting** — every probe is repeated; a flaky/non-deterministic target
     yields no quorum → ABSTAIN (never a flaky false positive).
   - **Declared-privacy anchor** — intent-deny is anchored to the app's own
     `visibility=private` declaration, not to "a control was denied". This catches a
     UNIVERSAL BOLA on a private object while NOT flagging objects the app designs public.
   - **Multi-control agreement** — ≥2 controls must agree; disagreement ⇒
     observer-dependent/adversarial target ⇒ ABSTAIN + flag.
   - **Bug-bounty dossier** — provenance tiers (only T2+ submittable) + blast-radius + EV
     ranking + the refuted benign explanations (boosts triage acceptance).

## What is / isn't closed
- **Soundness (zero-FP) is CLOSED**: H-independent, causal, and robust to non-determinism,
  adversarial responses, and auto-share design — any uncertainty ⇒ ABSTAIN.
- **Recall is BOUNDED (not a soundness gap)** by which confounding relationships we can
  provision *matched controls* for, and by needing a declared-privacy affordance to anchor
  the intent-deny. These are measurable limits, not false-positive risks.
- Residual shared with Wall-1: operator must correctly establish the construction/controls.

Verdict: the zero-FP pillar of the goal is now protected against targets whose authz we
cannot express — the algebraic threat is removed; the remaining limit is control
provisioning (recall), not soundness.
