# PROJECT_STATE — AuthZ Intent Engine (ledger)

APEX T3. Append-only decisions + spec + verified facts + open items.

## Mission
Reconstruct a target's authorization intent as a mathematical object and prove
where enforcement diverges from it (V = π_enf \ π_intent), deterministically
(no LLM/ML in the decision path), zero-FP, legal-by-construction. This repo is
the **Wall-1** component (the deny-signal / recall wall).

## Requirements
- REQ-01 Interventional intent: manufacture ground-truth intent-deny by exercising
  the app's own affordances as owned principals. **[done, verified: VAmPI + offline]**
- REQ-02 Sound value-presence Δstate confirmation with a discriminating-value
  guard (kills shared-default FP; excludes probe-supplied keys). **[done, verified]**
- REQ-03 Config-driven targets, zero target-specific code; client-key OR
  server-id read keys; login OR static auth. **[done, verified: VAmPI(title)+local(id)]**
- REQ-04 Submittable finding report (PoC + Δstate proof + OWASP class). **[done]**
- NFR-01 Deterministic verdicts; no LLM/ML in decision path. **[holds]**
- NFR-02 Legal-by-construction: ScopeGuard every request; own principals only;
  dry-run blocks cross-principal writes; politeness governor. **[done]**
- NFR-03 Verified against an INDEPENDENT (not self-authored) target. **[done: OWASP VAmPI]**

## Verified facts (evidence)
- VAmPI `GET /books/v1/{title}` is BOLA when vuln=1 (confirmed from source + live).
- Engine autonomously: register→login→create→cross-principal probe→value-presence
  → FINDING on VAmPI (`evidence/vampi_run.md`). Bob reproduced Alice's secret.
- Offline: notes=FINDING, cards=CLEAN (`tests/test_offline.py` green).
- Toolchain: py3.13; VAmPI deps installed relaxed (connexion==2.14.2, flask<2.3,
  werkzeug<2.3) — the pinned markupsafe==2.1.2 fails to build on 3.13.
- VAmPI run pattern: `python3 app.py` (as __main__) — circular import (`models`→
  `from app import vuln`) only resolves that way; patched run line to
  127.0.0.1/debug off/no reloader.

## Decisions
- D1 Interventional (not observational) identification is the Wall-1 root fix
  (passive positive-only data is underdetermined; Gold / causal confounding).
- D2 Confirmation is value-presence of a DISCRIMINATING value, computed by a
  3-sample differential (A1 vs A2 vs B1) minus probe-supplied keys. A 200 is
  never a finding.
- D3 Engine lives toward IOLITE's `reason/`; stays deterministic (no LLM) → QL4 safe.
- D4 Metamorphic oracle (derived-channel leaks) proven in
  `evidence/metamorphic_kernel_v2.py`; to be folded into the engine later.

## Bugs found and fixed (by running against the independent target)
- B1 Over-subtraction: treated the secret as a "probe-supplied key" → killed the
  discriminating value → false ABSTAIN. Fixed: subtract only keys present in the
  READ path template. (Surfaced ONLY on VAmPI, never on the self-authored toy —
  the value of an independent target.)
- B2 Duplicate-title rejection across runs → SKIP. Fixed: per-run nonce in markers.

## Open items (honest residuals → next walls)
- Wall-3 (next): safe mutation = test-object cleanup; write/delete BOLA (mutating
  others' objects, dry-run-gated); transactional perturb→restore for metamorphic.
- Integrations: IOLITE surface auto-discovery (replace hand-declared kinds);
  ONYX confirmer with stability voting (replace the local value-presence);
  DPoP/CSRF/refresh sessions.
- Coverage: multi-step/chained & emergent bugs (reachability/HRU wall).
- Novelty ceiling: value-presence + metamorphic cover verbatim + derived leaks;
  broader classes need the dependency-algebra work (documented in docs/WALL1.md).

## How to verify
`bash verify.sh`  (offline regression; and VAmPI if it is running on :5000)
