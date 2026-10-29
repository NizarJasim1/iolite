# IOLITE — The Legal Ceiling (Rules of Engagement)

IOLITE is built to reach the **maximum depth that is legal**, and to stop exactly
there — by construction, not by good intentions. This file states where the line
is; `scope_guard.py` and `roe.py` enforce it.

## The one principle: switch the carrier

The tool never blasts a giant target. **You** (an authorised human, inside a
program's written scope) browse legally with **your own accounts**; IOLITE feasts
on what you legally captured, offline. Requests that do go out are your authorised
sessions, at human pace, in-scope only.

## ✅ Inside the ceiling (IOLITE will do)

- **Zero-touch OSINT**: Certificate Transparency, Wayback/CommonCrawl/OTX, public
  GitHub, `robots.txt` / `sitemap.xml` / `security.txt`, Google dorks. No packet
  reaches the target.
- **Your authenticated browsing**: HAR captured from *your own accounts* through
  the app's normal flow.
- **Your own installed mobile app**: endpoints extracted from an APK/IPA on *your*
  device.
- **Exposed contracts**: `/openapi.json`, `/api-docs`, GraphQL introspection — if
  the target itself exposes them.
- **Frontend source**: JS bundles and `.js.map` sourcemaps the target serves publicly.
- **Cross-principal probes planned only between accounts you own** — the Δstate
  proof reads *your* object back as *your* other account. No real victim is touched.
- Requests only to **in-scope hosts**, at **human-like volume**, with **dry-run on**
  by default (no mutations until you explicitly opt in and the program allows it).

## ❌ Above the ceiling (Scope-Guard HALTS — IOLITE refuses)

- Any request to a host not in the declared allow-list.
- Accessing a **real other user's** data to "prove" an IDOR (use your own second
  account instead — that is the only legal proof path).
- High-volume automated attack / brute force / DoS-shaped traffic.
- Bypassing authentication, CAPTCHA, MFA, or bot-detection.
- Testing when the program's rules forbid automation (`automation_permitted=false`).
- Destructive mutations unless `allow_destructive=true` *and* the program permits it.
- Social engineering, or any exfiltration beyond a minimal proof-of-concept.

## The operator's responsibility (IOLITE cannot check these for you)

- You have a **written authorisation** (a public bug-bounty/VDP scope, or explicit
  permission) for every host in the allow-list.
- The accounts you use are **yours**, created within the target's Terms of Service.
- You honour each program's specific rules (rate, scope, disclosure).

`roe.py` records these as an explicit, signed-off engagement declaration that rides
with every run and is embedded in the emitted ONYX spec, so a reviewer can see the
authorisation basis of the whole corpus.
