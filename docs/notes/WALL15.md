# WALL-15 — the same dashboard, now tactile

> The dashboard is the v1.22 file, **unchanged** in palette, header, cards, layout and contents.
> The only difference is that every existing element now has interactive and physical detail layered
> on top of it — nothing was replaced, moved or restructured. One self-contained file, same colours.

## The rule this wall follows
Start from the v1.22 `iolite_dashboard.html` verbatim. Keep lines 1–77 (the `<style>` tokens and
the entire `<body>`) exactly as they were. Only two things are allowed: (1) *append* CSS rules that
use the existing `--bg/--panel/--v1/--v2/--v3/--ok/--warn/--crit` tokens, and (2) replace the
`<script>` with one whose render logic is the same v1.22 code, with interactivity and a silent demo
stream added. This is why v1.24's force-graph (which changed the Principals card) was reverted: it
replaced an element, and the brief is to add *to* each element, not swap any out.

## What each element gained (identity untouched)
- **Header pills** — `countUp()` animates exchanges / confirmed / blocks with tabular numerals; the
  `confirmed` pill `bump()`s when a confirmation arrives.
- **Cards** — staggered `cardin` spring-in on load; `cardTilt()` adds a ≤3° pointer-parallax tilt +
  lift on hover (disabled under reduced motion, and suppressed while a chip is being dragged).
- **Live feed** — rows get `.spawn` (spring in from the top); a `corroborated` row also gets
  `.pulse` (a red shock ring); hover nudges the row; click toggles `.open` to expand the detail.
- **Policy table** — row hover highlight; each `allow/deny/viol` cell renders a `.ratio` bar whose
  three segments (green allow / indigo deny / red violations) animate their widths.
- **Principals & ownership** — the `.p` chips are unchanged markup, but `wireDrag()` makes them
  grabbable; on release `flingHome()` integrates a little spring (`v += -x*k; v *= damp`) so the chip
  flings with the pointer's velocity and overshoots back home. This is the "physics" applied to the
  element that already existed, not a new widget.
- **Leads / confirmed exposures** — `.spawn` entrance, hover slide, and a `copy-probe` affordance on
  each lead (guarded `navigator.clipboard`).
- **Global** — `ripple()` draws a pointer-origin ripple on pills and leads; a slow `sheen` animates
  the `◈ IOLITE LIVE` gradient. All of it respects `prefers-reduced-motion` (snaps to final state).

## Alive on open (the v1.22 empty-state bug, fixed without touching the look)
`SIM` is an in-page simulator that emits the **same JSON shapes** the collector serves. On load the
page probes `/status`; if nothing answers it sets `DEMO=true` and `j(u)` is served by `SIM.route(u)`
instead of `fetch`. Owners create objects, non-owners are denied (→ boundaries), a few reads
reproduce an owner's private value (→ confirmations), interleaved with WAF / rate-limit / enumeration
events, and EV-ranked leads are recomputed. Because the shapes are identical, the *same* render code
fills the *same* elements — the page is simply never empty on open. Under `iolite watch` the probe
succeeds, `DEMO` stays false, and the real `LiveSession` data drives everything; the `host` pill
reads the real host rather than the demo host, which is the only visible tell of which mode is live.

## Re-render discipline
Feed rows are appended incrementally by `evseq` (as in v1.22). Policy / principals / confirmations /
leads are re-rendered only when their serialized payload changes, and the principals list is never
rebuilt mid-drag — so a chip you are holding is never yanked out from under the pointer.

## Verification
`node --check` is clean; the full load path and ~1.6 s of live loops (count-up frames, the demo
interval, tick/snap re-renders) run under a DOM stub with no error or unhandled rejection; the
collector serves the page; `test_dashboard.py` asserts both the restored identity and the added
interactivity. The page stays loopback-only and shows only the operator's own session.
