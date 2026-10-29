# reason — changelog

## v0.13.0 — IOLITE 1.10.0  (Point 3: IntentGraph + Point 4: EV operating layer)

Suite 176 → 191 passed, 0 failed. Additive; **ONYX untouched (728/0)**; every new path
opt-in ⇒ default byte-identical.

**Point 3 — IntentGraph (`intent_graph.py`).** Reconstructs intent as the tightest
(least-privilege) policy consistent with ALL evidence across the whole surface, not
one endpoint at a time from a fixed word list. Grounded in least-privilege ABAC policy
mining, INVERTED (mine the tight intent to contrast with enforcement, not to reproduce
it). Adds two evidence sources the first-match ladder can't use — observed
multi-principal PARTITION (disjoint holdings ⇒ owner-scoped, confidence ∝ sample) and
the target's OWN learned privilege vocabulary — then MONOTONE structural propagation
(write ≥ read; cross-surface owner floor, capped at OWNER never ADMIN; parent → child).
**Raise-only by construction**: it can only reduce false negatives, never silence a bug
by down-rating; worst case is wasted probes (ONYX still guards validity). `IntentRule`
gains `separates` (whom intent means to keep out). `infer_intent(..., joint=True)` /
`reason(..., rich_intent=True)` / CLI `--rich-intent`. Default OFF.

**Point 4 — the expected-value operating layer.** "Low-luck income" is a STATISTICAL
property, not a per-bug hope; these make it one.
- `collision.py` — the SOUND half of dedup. Duplicate-ness is unknowable offline, so we
  never predict it; we score observable collision PROXIES (crowding, freshness) and a
  labelled `p_original`. Built on novelty + KB freshness.
- `readiness.py` — the EV submission gate: EV = P(valid)·P(scope)·P(non-informational)·
  P(original)·E[payout]. GO / HOLD / DROP. An UNCONFIRMED finding can NEVER be GO (you
  cannot submit what ONYX has not proven) — HOLD at best. `reason … --readiness`.
- `econ.py` — the measured ledger: realized $/hour + acceptance per program → FOCUS /
  ROTATE / DROP with a bounded EXPLORE nudge for un-tried programs. Measured fact, never
  prediction. CLI `iolite econ`. (Serves goal 5 too.)
- `kb.py` — cross-session knowledge: FRESH endpoints + guard REGRESSIONS (a gate that
  weakened since last session ⇒ a freshly-introduced, very-low-collision bug — the
  highest-EV signal). `reason … --kb PATH`.
These recover the absent 1.8.0 econ/readiness/kb AND upgrade them with the EV/collision
framing. Honest floor preserved: dup is irreducible (never claimed eliminated); offline,
nothing is GO.

## v0.11.0 — IOLITE 1.9.0  (Point 1: declared workflow guards → state-indexed hypotheses)

The state/temporal axis the stateless differ lacked — the deepest, most AI-resistant,
highest-payout ground (payment/approval/fulfilment bypass). Suite 164 → 176 passed,
0 failed. Additive; **ONYX untouched (still 728/0)**; default path byte-identical.

- `workflow_intent.py` — the DECLARED-guard miner. ONYX (`state_machine.py`) forbids
  treating an OBSERVED capture as a spec (RL1: a sample is not a specification). So we
  do NOT infer a machine from traffic. We harvest the guards the developer WROTE DOWN
  — `if (order.status !== 'PAID')`, GraphQL/OpenAPI state enums — exactly as leakage
  mines OpenAPI `security`, lifted to the state axis. Each guard is a transcription-
  grade reference (QL3), validated against mined enum vocabularies. `DeclaredGuard`.
- `sequence.py` — three state-indexed hypothesis families, each mapped to an OWASP
  Top-10-for-Business-Logic-Abuse (2025) class and to an ONYX EffectClass ONYX ALREADY
  confirms: H1 gate-skip (BLA2/BLA6 → STATE_GATE), H2 state-conditional (BLA9/BLA3 →
  STATE_GATE), H3 privileged-transition usurpation (BLA9 → AUTHORITY). Confirmation is
  ONYX's dormant StateGateLaw/Δstate — reason only generates the hypothesis it was
  missing. `ReasonCandidate` gains `pre_state` + `required_predecessor` (additive;
  stateless keys unchanged).
- The write/read-only tension ONYX names is resolved by division of labour: the
  OPERATOR establishes the pre-state on their OWN object during capture; ONYX tests
  ONE altered transition under attestation. No fabricated sequence, no foreign object.
- Emission: `_reason.declared_state_gates` (only when guards mined ⇒ default spec
  byte-identical). CLI: `iolite reason … --sequence`. Opt-in (`with_workflow`), default
  OFF. When nothing is declared → nothing emitted (honest floor: observed-only is a
  coverage record, never a violation).

## v0.9.0 — IOLITE 1.7.8  (yield boosters: novelty/dupe filter + passive quick-wins)

Two money-focused additions that raise the PAID rate for both critical and ordinary
bugs. Suite 156 → 164 passed, 0 failed. Additive, passive, ONYX/IOLITE untouched.

- `novelty.py` — the dupe filter. A confirmed bug that is a DUPLICATE pays $0; ONYX
  guards validity, this guards ORIGINALITY. Deterministic score from signals that a
  bug is still un-found (ghost/fresh endpoint, deep chain, rare class, shadow surface,
  tenant break) minus crowded signals (sequential-IDOR on a mainstream object).
  **priority = impact + novelty** now ranks candidates and write-ups by EXPECTED
  PAYOUT, so effort goes to bugs that will pay, not just confirm.
- `quickwins.py` — a passive income stream from already-captured material (served JS,
  your own HAR): secrets in JS (AWS/Google/Stripe/GitHub/Slack/private-key/JWT, with
  redaction), verbose-error/stack-trace disclosure, CORS misconfig (wildcard/reflected
  + credentials), and exposed sensitive-path references. No packets sent; each finding
  cites its artifact and is clearly labelled PASSIVE (not an ONYX Δstate confirmation).
  Flows into the report, spec (`_reason.quickwins`) and `--writeup` (quickwin_*.md).

## v0.8.0 — IOLITE 1.7.7  (submission write-up generator — the last mile to payout)

`writeup.py` turns a candidate into a submission-ready BOLA/BFLA report: family →
vulnerability class + mechanism, estimated severity (from the amplifier), steps to
reproduce (own accounts, exact request + swap), the impact narrative, ONYX Δstate
evidence, remediation (from the empirical taxonomy), and an authorization/scope note.
Offline runs produce clearly-marked DRAFTS ("pending ONYX live confirmation"); a live
CEGAR run marks the confirmed ones as ONYX-Δstate-confirmed (honesty by construction).
CLI: `iolite reason --dir … --writeup findings/ [--writeup-top N]`. Suite 150 → 156
passed, 0 failed. Additive; ONYX/IOLITE untouched.

Money loop now complete: research → acquire → reason (I△E + invariants + assumptions)
→ CEGAR (ONYX confirms) → amplify (severity) → coverage (recall) → write-up (submit).

## v0.7.0 — IOLITE 1.7.6  (last leakage gaps closed + recall meter)

Closes the two named honest gaps and adds a recall signal. Suite 144 → 150 passed,
0 failed. Additive; ONYX/IOLITE untouched.

- `leakage.py` — feature-flag miner (`featureFlags.canDeleteUsers` → the feature is
  meant to be gated, often client-side only → reachable), plus mobile-app-strings and
  public-commit-log miners. Camel/snake tokenizer matches leaked evidence to endpoints.
  Wired through `reason(model, inputs, mobile_paths, commits_paths)` + CLI `--mobile`
  / `--commits`. JS/sourcemap bundles are now also scanned for flags.
- `coverage.py` — the honest recall signal. ONYX owns PRECISION; this reports RECALL:
  restricted endpoints covered / total (%), the untested restricted endpoints to
  acquire, and CRUD method gaps on object resources (likely-unobserved surface). In
  the dossier and `_reason.coverage`. Answers the 90% ambition honestly: it shows how
  much of the meant-to-be-restricted surface was actually probed.

Coverage vs the design is now complete except two out-of-input-scope sources
(feature flags = done; mobile/commits = done via text dumps). Remaining: live
real-target validation.

## v0.6.0 — IOLITE 1.7.5  (deep intent reconstruction — every leakage source)

Comprehensive intent-depth upgrade: the whole thesis is I△E, so a richer I is the
leverage point. Closes every leakage source the design names. Suite 133 → 144
passed, 0 failed. Additive; ONYX/IOLITE untouched.

- `signals.py` — intent latent in the acquired model: owner/tenant/role FIELD names
  (owner_id, tenant_id, is_admin…), self-scoped paths (/me,/self), and JWT ROLE
  claims (role/scope/groups → role-based app).
- `intent.py` — consumes signals; new `AccessClass.TENANT_ISOLATED` (cross-tenant =
  critical); self-scoped and owner-field endpoints now OWNER_ONLY at HIGH confidence;
  role/admin fields → ROLE/ADMIN. `infer_intent` accepts a `leakage` overlay.
- `leakage.py` — mines raw legal leakage the model doesn't carry: OpenAPI `security`
  + scopes, GraphQL `@auth/@hasRole` directives, and HAR responses (401/403 +
  ownership phrases "not the owner"/"forbidden"). Produces a minimum AccessClass per
  endpoint; wins when more restrictive. Wired through `reason(model, inputs)` + CLI.
- `assumptions.py` — 7th HAZOP: `webhook_origin_trusted` (peer reads a webhook/
  callback resource → signing-secret disclosure). Catalog now 7/7.

Coverage vs the design: intent leakage (JS/sourcemaps ·, GraphQL @auth ·, OpenAPI
security ·, JWT roles ·, field names ·, self-scoped ·, error messages ·) all wired.

## v0.5.0 — IOLITE 1.7.4  (impact amplifier — Medium → Critical)

The engine is now complete. `amplify.py` turns each candidate into a deterministic
severity (effect × sensitivity × scale/enumerability × direction × chain-depth ×
tenant) with named reasons, a band (low/medium/high/critical), and a Critical
narrative for the report; plus bounded `scale_probes` to demonstrate blast radius.
Candidates are now ranked by likely impact in the report and spec (`_reason.impact_bands`,
per-candidate `impact_band`/`impact_score`). Suite 127 → 133 passed, 0 failed.

Full engine: intent (I) · enforcement (E) · I△E differ (+shadow-admin) · 5 invariants ·
6 assumptions · CEGAR loop (ONYX oracle) · impact amplifier. reason PROPOSES; ONYX
DISPOSES. Remaining: real-target (inDrive) live validation.

## v0.4.0 — IOLITE 1.7.3  (CEGAR loop — ONYX as oracle in-search)

The closed loop that makes reason a "Critical maker": hypothesize → ONYX Δstate →
refine → deepen, to bounded depth k. Suite 121 → 127 passed, 0 failed. ONYX/IOLITE
behavior untouched (the loop only *calls* ONYX; it never modifies it).

- `oracle.py` — ONYX-as-verdict abstraction:
  * `LiveOnyxOracle` — shells out to `authpath scan --export`, parses findings, maps
    confirmations back to candidates. Runs only under an **attested** engagement with
    restored tokens against a reachable target (the operator's machine).
  * `StaticOracle` — offline: verify-only, returns UNKNOWN for every candidate. Never
    fabricates a confirmation (honesty by construction).
  * `SimulatedOracle` — deterministic fake verdicts for tests / dry planning.
- `cegar.py` — `refine_search(model, engagement, oracle, depth=k)`:
  * denied → prune the branch (recorded, never re-emitted).
  * confirmed → a CONFIRMED CAPABILITY → the **chain composer** `_escalate` spawns
    depth+1 candidates: cross-surface escalation, privilege-lateral (a confirmed BFLA
    unlocks sibling admin endpoints), and leaked-id disclosure chains.
  * bounded to depth k (real authz chains are short); deterministic; own principals.
- `ReasonCandidate` gains `depth` + `chain_from` (lineage) and a stable `cand_key`.
- CLI: `iolite reason --dir … --cegar --depth K`. Offline uses StaticOracle and says
  so; a live attested run drives the real ONYX loop. The trace (rounds, confirmed
  chain, pruned) is written into the spec's `_reason.cegar` block.

Remaining roadmap: real-target validation (inDrive), impact amplifier / severity.

## v0.3.0 — IOLITE 1.7.2  (invariant catalog completed)

All five transplanted-science invariants are now active — each a real candidate
generator mapped to an ONYX EffectClass, bounded & non-destructive. Suite
116 → 121 passed, 0 failed. ONYX/IOLITE behavior untouched.

- `cross_surface_consistency` (linearizability) → CROSS_SURFACE
- `non_interference_oracle` (information theory) → FIELD_PROJECTION — validation/
  lookup surface leaks existence/ownership of others' data.
- `value_conservation` (accounting/physics) → PRICE — value-bearing endpoint set to
  a boundary/negative value yields a non-conserving total (economic authz/TOCTOU).
- `grant_freshness` (protocol verification) → STATE_GATE — a token/nonce replayed
  against a different object (fresh grants must be single-object/use).
- `information_flow` (type theory) → FIELD_PROJECTION — expand/include over-fetch of
  related objects without re-authorization (second-order IDOR).

Also: `intent._addresses_object` now recognizes a templated `{id}` segment as
object-addressing (owner-scoped presumption), independent of observed ids.

Catalog status: invariants 5/5 active · assumptions 6/6 active.
Remaining roadmap: the CEGAR loop (ONYX oracle in-search), real-target validation,
impact amplifier / chain composer.

## v0.2.0 — IOLITE 1.7.1  (assumption library completed)

The HAZOP assumption library is now fully active — all 6 detectors, each a real
candidate generator mapped to an ONYX EffectClass, bounded & non-destructive, own
principals only. Suite 111 → 116 passed, 0 failed. No ONYX/IOLITE behavior touched.

- `endpoint_internal_only` → reach an internal/debug/private-marked, unreached
  endpoint as the lowest-privilege principal (effect = endpoint's own / OBJECT_ACCESS).
- `client_sends_true_role` → resend a read with a client-supplied role param elevated
  to `admin` (↔ AUTHORITY / BFLA).
- `deleted_stays_inaccessible` → flip a lifecycle param to `deleted` (↔ STATE_GATE).
- `child_reinherits_authz` → keep the owned parent id, swap the child id (nested-path
  second-order IDOR ↔ OBJECT_ACCESS).
- `export_inherits_query_authz` → a peer principal requests the same export/report
  surface (↔ CROSS_SURFACE).

Remaining roadmap: 4 planned invariants, the CEGAR loop, real-target validation,
impact amplifier / chain composer.

## v0.1.0 (seed) — IOLITE 1.7.0

First cut of the grey-box **authorization reasoning engine** — the "brain" that
sits between IOLITE (acquisition) and ONYX (proof). Additive-only: **zero edits to
ONYX; the only IOLITE edits are one new `reason` subcommand, a version bump, this
changelog.** Existing suite unchanged (102 → 111 passed, 0 failed).

New (`iolite/reason/`):
- `intent.py` — reconstruct the developer's INTENDED access policy I from mined
  role guards, effects, provenance and endpoint shape (an addressable object is
  presumptively owner-scoped). Every rule carries evidence + confidence (QL3).
- `enforcement.py` — measure the OBSERVED enforced policy E (who reached what; the
  holdings graph). The live E is never assumed — it is emitted as an ONYX probe.
- `differ.py` — compute **I △ E**. Two gap kinds:
  * `observed_object_gap` — cross-principal reach of a restricted object.
  * `declared_unreached_gap` — the **shadow/admin surface**: privileged endpoints
    mined from leakage that NO controlled principal reached (no observed-access
    generator can produce these — there is nothing to replay).
- `invariants.py` — transplant invariants from mature sciences; a violation is a
  candidate for a bug class pattern libraries can't name. **Active:**
  `cross_surface_consistency` (linearizability ↔ ONYX CROSS_SURFACE). **Planned**
  (zero candidates, never claimed): non-interference, conservation, freshness,
  information-flow.
- `assumptions.py` — HAZOP: negate the developer's unquestioned assumptions.
  **Active:** `ids_unguessable` (sequential-id neighbour probe ↔ OBJECT_ACCESS).
  **Planned:** internal-only, client-sends-true-role, deleted-stays-inaccessible,
  child-reinherits-authz, export-inherits-query-authz.
- `engine.py` — orchestrate → `ReasonReport` → ONYX-ready plan (reuses IOLITE's
  emitter) → enriched spec with a self-describing `_reason` block.
- `report.py` — human dossier, with the honesty ceiling embedded.
- `BUILD_PROTOCOL.md` — the eight hard rules governing every future change.

Law: reason PROPOSES; ONYX DISPOSES (QL5). Own principals only (QL6). Deterministic
(QL4). Legal-by-construction (scope-guarded, dry-run-gated). False positives
impossible (ONYX Δstate); false negatives possible where intent didn't leak.

CLI:  `iolite reason --dir ./captures [--scope host,host] [--dossier out.md]`
