# iolite.intent — Wall-1 interventional BOLA engine (additive, opt-in)

Lives inside IOLITE; changes nothing about IOLITE's defaults. Deterministic,
legal-by-construction. Reconstructs authorization intent by **intervention**
(create objects as your own principals, read cross-principal) and confirms an
over-permission by a **value-presence Δstate** — never a status code.

## Run

```bash
# offline regression (boots a local vulnerable app)
python3 tests/test_intent_offline.py          # from the IOLITE project root

# independent target (OWASP VAmPI) — reproduces the live finding
bash iolite/intent/targets/get_vampi.sh &      # clones+boots VAmPI on :5000
sleep 8
python3 -m iolite.intent iolite/intent/targets/vampi.json --report /tmp/vampi_run.md
```

A target is one JSON file (`targets/*.json`): base_url, auth (login or static
headers), the principals you own, and the object kinds (producer `create` +
consumer `read`, keyed by a client value or a server-assigned id). Zero
target-specific code.

## Status
Verified against an INDEPENDENT target (VAmPI BOLA found autonomously) and an
offline regression (notes=FINDING, cards=CLEAN, zero-FP). Deferred to Wall-3:
test-object cleanup, write/delete BOLA, transactional perturb→restore for the
metamorphic oracle. To wire later: IOLITE surface auto-discovery, ONYX confirmer
(stability voting), DPoP/CSRF sessions. Full critique + the four breakthroughs:
`docs/notes/WALL1.md`; ledger: `docs/notes/WALL1_STATE.md`; proofs: `docs/notes/wall1_evidence/`.
