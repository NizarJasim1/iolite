# The unified intent kill-chain (`iolite/intent/pipeline.py`)

The whole-tool leap: the four walls stop being isolated kernels and become stages of
ONE engine with a single entry point, preserving every guarantee (nothing weakened).

```
GENERATE  wide: read/write-BOLA, BOPLA-write, delete-BOLA, chained(HRU), cross-surface   [W2 widening]
 → REDUCE  authorization-equivalence quotient — representatives, not instances           [W2 scale]
 → SCHEDULE EV priority under a hard budget; the rest are ranked leads (graceful)         [W2 bandit]
 → CONFIRM constructed intent-deny + Δstate; safe-mutation saga for writes;
            causal falsification + stability voting                                       [W1·W3·W4]
 → CERTIFY replayable certificate re-derived by an INDEPENDENT verifier (else DROP)       [W2 zero-FP]
 → REPORT  EV-ranked triage dossiers + coverage + safety ledger
```

**The load-bearing invariant (why widening never costs precision):** generators only
PROPOSE; the single certifying CONFIRM gate DISPOSES. Adding a generator can only raise
recall, never FP. Writes are net-zero (saga-restored) or REFUSED (irreversible) — never harm.

## Proven in one run (`python3 -m iolite.intent pipeline`; `tests/test_pipeline.py`)
- 60 raw candidates → 11 equivalence representatives (quotient).
- **6 distinct bug classes caught in a single run** (read-BOLA, write-BOLA, BOPLA-write,
  delete-BOLA, chained, cross-surface) — the WIDTH the isolated kernels could not show together.
- **FP = 0** through the unified gate; the irreversible write REFUSED for safety; every
  write finding net-zero-restored; budget respected.
- Deterministic; run log in `docs/notes/wall2_evidence/unified_pipeline_run.txt`.

## Honest floor (unchanged by the unification)
- The pipeline composes the walls over evidence that mirrors each wall (each live-verified
  separately: Wall-1 + Wall-3 saga on VAmPI, Wall-3 benchmark). The full LIVE end-to-end
  run of the composed pipeline against one real multi-class target is the integration step.
- GENERATE must be populated from IOLITE's real surface model (acquisition wiring); EV from
  calibrated payout/dup data; CONFIRM from ONYX's real confirmer. These are wirings, not gaps
  in the composition.
- FN frontier (concurrency/TOCTOU, deep GraphQL) and the field T1 run remain.

Nothing was weakened: the unification changed no wall's logic; it composed them, and the
regression asserts all guarantees hold together (FP=0 ∧ net-zero ∧ refuse ∧ reduce ∧ 6 classes).
