# PROJECT_STATE — Wall-2 (scale / decidability) ledger

APEX T3. Additive to IOLITE; shipped in v1.13.0. Completes the four walls.

## Requirements
- REQ-21 Quotient the coordinate space by authz-equivalence; test representatives. **[done: 13,333×]**
- REQ-22 Best-first confirmation under a hard budget; graceful degradation (ranked leads). **[done]**
- REQ-23 Learn the partition from behavior; CEGAR-split; flag cohort inconsistency. **[done]**
- REQ-24 EV bandit scheduler maximizing bounty ($) per budget. **[done: +45% vs uniform]**
- REQ-25 Zero-FP: certificate + independent re-derivation + continuous decoy measurement. **[done: FP=0 measured]**
- REQ-26 Widen detection via multiple generators through one gate. **[done: 1→4 classes at FP=0]**
- NFR-21 Scheduling/abstraction CANNOT create an FP (sound gate is the only disposer). **[structural]**

## Decisions
- D21 Authorization is type/role-uniform; quotient by equivalence class; violations are findings.
- D22 PROPOSE widely, DISPOSE through one certifying gate → detection extensible, FP pinned.
- D23 Budget allocated by EV (UCB bandit), not static priority → maximize bounty/effort/risk.

## Verified (deterministic kernels)
- `wall2_scale.py`: 480,000 → 36 (13,333×); class- + cohort-level bugs under budget.
- `wall2_deep.py`: learned partition (5000→5, cohort flagged); EV-bandit +45% vs uniform.
- `wall2_zerofp.py`: FP=0 on 66 decoys (incl. adversarial); detection 1→4 classes.

## Open items (the "after the walls" layers)
- Static-first partition bootstrap (schema/idformat) before behavior refinement.
- Multi-dimensional budget governor (rate/writes/detection-risk/time); incremental re-scan
  with persisted yields + freshness; anytime decidability guard; EV calibration from real
  payout/dup data (research.py/collision).
- Uncovered classes: concurrency/TOCTOU, deep GraphQL.
- Wire into `iolite.reason`; the field T1 run.

## Files
- `iolite/intent/wall2_scale.py` · `wall2_deep.py` · `wall2_zerofp.py`
- `docs/wall2_evidence/{scale,deep,zerofp}_run.txt`
