# WALL-10 — defense-aware execution (learn the target's defences, ride the ceiling)

> The self-critique of Wall-9: it was blind to defences. On a strong program it would hammer
> into a 429/WAF block, and — worse — mistake a WAF/bot 403 for an authorization boundary,
> poisoning the intent model. Wall-10 senses the defences, learns them, and goes exactly as fast
> as the target tolerates.

## Tell a real denial from a defensive block (`defense.py`)

Every response is classified:

| signal | trigger | effect |
|---|---|---|
| `RATE_LIMITED` | 429 / Retry-After | pacer backs off globally |
| `WAF_BLOCK` | vendor fingerprint (cf-ray, x-iinfo, AkamaiGHost, awswaf, …) or an HTML block page | park that request; light pacer touch |
| `CHALLENGE` | captcha / JS interstitial markers | park (never solved) |
| `AUTH_EXPIRED` | token/session-expiry markers on a 401 | refresh auth + retry |
| `FORBIDDEN_AUTHZ` | a **clean** 401/403 (no fingerprint) | a real authz boundary — teaches the model |

The precision rule: a block phrase only counts from a **text/HTML** body, never from a structured
JSON error — so `{"error":"forbidden"}` is a real authz denial, while an HTML "Attention Required"
behind `cf-ray` is a WAF block. This is what stops a WAF 403 from corrupting the learned policy.

A per-host `DefenseProfile` is learned online: vendor, latency baseline, block counts, and a
**safe rate** (just under the first rate at which a block appeared). It is the memory of how this
target defends itself.

## Ride the ceiling (`pacer.py`)

A TCP-style AIMD controller:
- **additive-increase** the request rate on every clean success,
- **multiplicative-decrease** (halve) + shrink concurrency on a pace block (429/5xx), honoring
  Retry-After,
- a **light touch** for a request-specific WAF/challenge wall (it is not evidence the global pace
  is wrong, so throughput for everything else is preserved).

It converges just below the target's tolerance — the fastest speed that does not trip defences.

## Execute fast and safely (`executor.py`)

Runs the gated live probes **highest-EV-first** under the pacer + a hard request budget:
- backs off and bounded-retries on blocks; **parks** a WAF-walled path after one retry instead of
  hammering it;
- **refreshes auth** on token expiry and resumes;
- enforces scope per request; own accounts only;
- returns responses + the learned defence profile. It never decides a finding — the metamorphic
  oracle still owns the verdict.

Measured on a simulated hardened target (5 req/s ceiling + Cloudflare WAF path + token expiry):
start 12 req/s → settle ~3.3 req/s, every legitimate task completed, WAF path parked, token
refreshed and recovered, vendor + safe rate learned — in roughly half the wall-clock of a naive
fixed-rate run, with no sustained blocking.

## Live integration
As you browse (`iolite watch`), defence responses surface as `defense` events and build the
profile, so the gated step starts already knowing the target's vendor and safe rate. The in-page
hook forwards the edge headers needed to fingerprint the WAF.

## Safety / legality (unchanged, load-bearing)
The pacer makes the tool both faster AND gentler — it honors Retry-After and backs off, which is
exactly what a responsible tester should do. Everything live is own-accounts-only, scope-guarded,
and gated behind an attested engagement. IOLITE never solves captchas, never forges "humanity",
and never tries to defeat a bot wall — it recognises one and stops.

## Honest floor
The pacer finds a *sustainable* rate, not a bypass. A full JS/captcha wall is parked, not beaten.
Defence learning improves with observations. A force-multiplier for an authorized hunter on a
hardened target — not an autonomous scanner, and not an anti-WAF weapon.
