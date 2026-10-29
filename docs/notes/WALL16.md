# WALL-16 — the console dashboard, now tactile

> The mission-control dashboard from **v1.11.0** (`dashboard/index.html`) — the full grid console
> with the pleochroic gem identity, faceted panels and the radial SURVEY map — kept **exactly** as
> it was, with interactivity and physics layered onto every existing element. The `<body>` markup is
> byte-identical to v1.11.0 and the whole original CSS block is preserved verbatim; everything new is
> appended CSS and added JS.

## Why this wall
Earlier dashboard work (v1.22→v1.25) enhanced the *other*, simpler collector dashboard
(`iolite/assets/iolite_dashboard.html`). The dashboard the operator actually wanted is the v1.11.0
console at `dashboard/index.html`. This wall takes that file verbatim as the base and only adds to it.

## Identity — frozen
- `:root` palette unchanged (`--bg #06060f`, `--v #a855f7`, `--i #6366f1`, `--c #22d3ee`, …).
- The entire v1.11.0 `<style>` block is a verbatim substring of the new file; the `<body>` is
  byte-for-byte identical. The gem logo, IOLITE/ONYX tabs, telemetry, SURVEY button, left rail
  (VIEW / THROUGHPUT / EFFECT SPECTRUM / PRINCIPAL LOAD), the radial map stage, right rail
  (TRIAGE / ACQUISITION LOG / RESEARCH) and the PIPELINE track are all exactly where they were.

## What every element gained
- **Wordmark** — a slow pleochroic sheen across the existing IOLITE gradient (`ioSheen`).
- **Gem logo** — hover glow; click spins it (`gemSpin`) and fires the existing screen flash.
- **Every control** (SURVEY, icon buttons, IOLITE/ONYX tabs, VIEW modes, severity chips) — a
  pointer-origin ripple (`ioRip`) and a physical press (translate + scale). SURVEY also pulses with a
  "charge" glow while a survey runs (`ioCharge`).
- **Tab / mode / severity groups** — a sliding physical indicator (`slide-ind`, positioned by
  `linkSlide`) glides behind the active item.
- **Telemetry** — ENDPOINTS and PROBES count up with tabular figures (`ioCount`).
- **The radial SURVEY map** (the signature viz) — now a tactile instrument:
  - **drag to rotate** the whole field, with **fling inertia** that eases to rest (`mapRot`/`mapVel`);
  - **hover a marker** for a tooltip (endpoint · effect · risk), via per-frame hit-recording
    (`markerHits` + `#mapTip`);
  - **click a marker** to select it (it grows and gets a ring), **cross-linked** to the triage
    ledger — and clicking a triage row selects and highlights its marker on the map (`selectOn`).
- **Left instruments** — the throughput sparkline draws a glowing dot on the latest sample; EFFECT /
  PRINCIPAL bars lift and brighten on hover.
- **PIPELINE** — each stage sends a completion **ping** as it lights (`ioPing`); ticks show their
  stage name on hover; the playhead keeps its glow.
- **Depth** — the vignette and faceted overlay drift with a subtle pointer **parallax**.

## Fixes / production-ready
- Opens alive with no server (unchanged `DEMO_SPEC` fallback; `/api/*` failures are caught).
- The theme button (`◐`) now works: a tasteful **light theme** (`data-theme="light"`); dark stays
  the default identity.
- Full `prefers-reduced-motion` support — the *added* motion (sheen, ripple, parallax, map inertia,
  charge) is disabled and the UI snaps to final states.
- `node --check` clean; the whole script ran ~1.6 s under a DOM/canvas stub (the map rAF loop with
  inertia, the timed render pipeline, and all wiring) with no error or unhandled rejection.

## Verification
`tests/test_console_dashboard.py` asserts the preserved identity tokens/structures **and** every
pinned modification marker. The modification list itself is pinned in `docs/DASHBOARD_MODS.md`.
