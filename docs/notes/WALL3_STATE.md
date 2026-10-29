# PROJECT_STATE — Wall-3 (safe mutation) ledger

APEX T3. Additive to IOLITE; existing modules untouched.

## Requirements
- REQ-31 Refine fail-safe: perform only provably-safe mutations. **[done]**
- REQ-32 Empirical reversibility rehearsal on a sacrificial own object. **[done, verified]**
- REQ-33 Three-gate defense (static screen → rehearsal → saga). **[done; gate0 forced by a run-exposed flaw]**
- REQ-34 Full write-surface sweep: write-BOLA, BOPLA-write, delete-BOLA; auto-cleanup; ledger. **[done, in-process]**
- REQ-35 Durable on-disk WAL with crash recovery over HTTP. **[done, verified live]**
- REQ-36 Confirm a real write-side authz bug on INDEPENDENT code. **[done: VAmPI register mass-assignment]**
- NFR-31 Net-zero harm: every mutation restored / every test object deleted. **[holds — verified: 0 residual users, 0 external effects]**
- NFR-32 Allowlist-gated; operator asserts no external effect per op; conservative screen. **[holds]**

## Verified facts
- VAmPI write surface (from source): email self-scoped (not BOLA); delete admin-gated;
  books no update. Real write bug = register honours `admin` → mass-assignment.
- Live: attacker.admin=True vs control.admin=False via /users/v1/_debug read-back;
  WAL persisted pending deletes; cleanup net-zero; crash recovery replayed 1 undo.
- Run-exposed flaw: rehearsing an external op triggers it → added non-executing
  static screen as gate 0 (defense in depth).

## Decisions
- D31 Confirm write-side via NON-DESTRUCTIVE read-back where possible (debug admin
  differential) — avoids needing a destructive admin action to prove privilege.
- D32 create↔delete is the compensating pair; all created users are our own and
  deleted; WAL on disk guarantees cleanup across a crash.
- D33 Side-effect safety is an ALLOWLIST + operator assertion (undecidable to infer);
  the keyword screen is a conservative secondary check.

## Open items (deferred)
- Generalize saga adapters to OpenAPI-declared mutating ops (config-driven), wire
  into `iolite.reason`; optimistic-concurrency restore; idempotency keys;
  state-gated/sequenced writes; concurrency/TOCTOU; MailHog/OOB external-effect
  sensing during rehearsal; confirm on more independent targets.

## Verification of effectiveness
Since VAmPI has no write-BOLA, effectiveness is measured two ways:
- **Fair labeled benchmark** (`wall3_benchmark_app.py` + `wall3_bench_runner.py`),
  composition from the REAL distribution (arXiv:2605.25865): **PRECISION 1.000,
  RECALL 1.000 on the findable write-authz subset** (write-BOLA, BOPLA/mass-assign,
  object-rebinding, delete-BOLA), unsafe ops (hard-delete, external notify) REFUSED,
  a state-gated write MISSED by design (honest FN), **0 external effects, 0 litter**.
  Fairness: contains decoys (noop, shared-default) → precision is a real test, and
  misses the engine is not built for → not a circular 100%. Log: `wall3_evidence/benchmark_run.txt`.
- **Independent live anchor:** VAmPI register mass-assignment confirmed by the HTTP
  saga (`wall3_evidence/vampi_write_run.txt`).
- **Field runbook:** `wall3_evidence/CRAPI_RUNBOOK.md` (verify on crAPI on the operator's box).

## Files
- `iolite/intent/wall3_saga.py` — HTTP saga + durable WAL + allowlist (VAmPI-verified)
- `iolite/intent/wall3_benchmark_app.py` + `wall3_bench_runner.py` — fair labeled benchmark + generalized HTTP engine
- `iolite/intent/wall3_sweep.py` — in-process sweep + empirical rehearsal + 3-gate
- `docs/wall3_evidence/wall3_safe_mutation.py` — single-op safety kernel (crash-recovery)
- `docs/wall3_evidence/vampi_write_run.txt` — the live VAmPI run log
