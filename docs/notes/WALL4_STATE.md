# PROJECT_STATE — Wall-4 (soundness) ledger

APEX T3. Additive to IOLITE; shipped in v1.12.0.

## Requirements
- REQ-41 Findings H-independent (construction + Δstate), H-inferences are leads only. **[done, proven]**
- REQ-42 Causal falsification via no-relationship control (cause, not correlation). **[done, proven]**
- REQ-43 Stability voting on every probe; flaky ⇒ ABSTAIN. **[done]**
- REQ-44 Declared-privacy anchor (catches universal BOLA on private objects; spares design-public). **[done]**
- REQ-45 Multi-control agreement; disagreement ⇒ observer-dependent ⇒ ABSTAIN. **[done]**
- REQ-46 Bug-bounty: provenance tiers (T2+ submittable) + EV/blast-radius dossier. **[done]**
- NFR-41 Zero-FP under non-determinism, adversarial responses, auto-share. **[holds — any uncertainty ⇒ ABSTAIN]**

## Decisions
- D41 Zero-FP rests on construction+Δstate+causal-control, NEVER on algebra H completeness.
- D42 Falsification is interventional: vary the one relationship (matched control), hold the rest.
- D43 Intent-deny is anchored to the app's DECLARED privacy, not to "control denied"
     (resolves the universal-BOLA vs auto-share ambiguity).

## Verified (kernels, deterministic)
- `wall4_soundness.py`: pure-H rule FALSE-POSITIVES when π_true∉H; sound engine abstains, still finds real bug.
- `wall4_causal.py`: naive (correlational) gate FALSE-NEGATIVES; causal (control) gate recovers it, no FP.
- `wall4.py` (hardened): universal-BOLA-on-private caught; flaky / observer-dependent / design-public all ABSTAIN.

## Open items
- Matched-control provisioning (factorial, one relationship at a time) → recall bound, not soundness.
- Wire over HTTP against real relationship configs; pooled reusable controls + cached relationship graph.
- Wall-2 (scaling/decidability) remains, the last of the four.

## Files
- `iolite/intent/wall4.py` — hardened engine (stability + anchor + multi-control + dossier)
- `docs/wall4_evidence/{wall4_soundness,wall4_causal,wall4_hardened}.py` — the three proofs
