# WALL-17 — the hardened-target simulation lab

> Before a real engagement, we need to know the tool *works* behind the hardest defences — not in
> theory, but by running the real engine and watching it build intent, hit walls, confirm bugs, and
> emit a report. `iolite/intent/simlab.py` is that proving ground: a fully synthetic, deterministic
> dry-run against models of Google / Microsoft / Cloudflare / Akamai-class stacks. No real traffic;
> every response is fabricated. It drives the unmodified engine, so what it shows is real behaviour.

## Why a simulation (and why it is safe)
Real hardened targets can't be used to *develop* confidence — you get one reputation and a scope.
So we model the defences and the authorization logic, seed a few genuine flaws, and let the actual
code meet them. Everything is offline and fabricated: `simlab` is a validation harness for the
operator's own authorised-testing tool, never an exploit and never pointed at a real system.

## What it drives (the real code, not a mock)
- **Intent:** `LiveSession.ingest_raw` → `observation.observe` → `policy_learn.PolicyLearner`.
- **Confirmation:** `confirm.confirm_leads` → `executor.run_tasks` + `pacer.AdaptivePacer` + the
  value-presence oracle.
- **Execution stress:** `executor.run_tasks` with `refresh_auth`.
- **Report:** `dossier.render` over `LiveSession.snapshot()`.

## The target models (`HardenedTarget` + `Persona`)
A single `respond()` choke point applies, in order: scope → **rate-limit** (token bucket, 429 +
Retry-After) → **edge WAF / bot wall** (vendor headers + a block page) → **JS/captcha challenge** →
**auth expiry** (401 on a short-lived token) → **authorization**. A shared `VirtualClock` means a
pacer back-off actually lets the bucket refill — a real closed loop, but deterministic and instant.

Four personas, each with a different defence posture and a few **seeded** truths to find:
- `google-class` — very aggressive rate-limiting + reCAPTCHA interstitial; strict object authz.
- `microsoft-class` — Azure-AD short-lived tokens (expiry under load) + Front Door WAF + tenant isolation.
- `cloudflare-fronted` — Cloudflare WAF (`cf-ray`) + JS challenge; origin enforces object authz.
- `akamai-ecommerce` — Akamai bot-manager 429 bursts; seeded cross-tenant + ghost-endpoint BOLA.

Seeded reality (so there are true positives): one object type with a real **BOLA** (non-owner reads
it), a **cross-tenant** object delivered across the namespace, a **ghost/archived** endpoint with
rotted authz, and a **BFLA** admin endpoint reachable by a non-admin. Everything else is correctly
enforced (non-owners get a clean `403`).

## Identity is real
Principals carry real **JWTs** (`header.payload.sig`); the engine decodes only the payload claims
(`sub`/`role`/`tenant`) exactly as the live hook does — the token is never stored. The target
identifies the caller by the token's `sub`, and `refresh_auth` re-mints it on expiry.

## What the run proves
With seed 7, across all four profiles:
- **Operational: 4/4.** No breakage. Rate-limits trigger AIMD back-off and honour `Retry-After`; a
  WAF is a request-specific wall (soft-penalty + fast park, not a global stall); token expiry is
  transparently refreshed (`microsoft-class`: tokens expired under load and the run continued).
- **Intent built by contrast.** `order`/`profile`/`shipment` are learned as *enforced* owner/tenant
  boundaries (owner allowed, non-owner cleanly denied); the BOLA type shows violations, not a boundary.
- **Seeded bugs surfaced 4/4** — BOLA and cross-tenant both caught live *and* re-confirmed by
  defense-aware replay (value-presence on a clean 2xx).
- **Precision held:** **zero** false boundaries from a WAF/429, and **every** finding came from a
  clean 2xx — never a status code. The enforced `order` endpoint stayed a true-negative.

## Honest operational findings (surfaced by the lab itself)
- A WAF/challenge can **park a real-bug probe**; it is reported as *blocked*, never as *no bug*.
  Re-visiting the object surfaces it (the lab models the re-visit). Recommendation: re-queue a parked
  high-EV lead once the pace recovers.
- **Vendor-fingerprint gap:** the Azure/Front-Door block was correctly classified as a *defence* by
  its body phrase, but no vendor was attributed. Functionally safe; recommendation: add Azure markers
  to `defense._WAF` for cleaner attribution.

## Reproduce
`iolite sim --out readiness.md` or `python -m iolite.intent.simlab`. Deterministic (seeded RNG +
virtual clock). Covered by `tests/test_simlab.py`.
