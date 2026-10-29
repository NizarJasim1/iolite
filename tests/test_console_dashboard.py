"""
The v1.11.0 mission-control console dashboard (dashboard/index.html), enhanced with
interactivity + physics in v1.26.0. These assertions pin two things:
  1. the original v1.11.0 visual identity is preserved verbatim (same palette tokens, same body), and
  2. every pinned modification is actually present in the file.
Pure file-content checks — no server needed.
"""
import os

_HTML = os.path.join(os.path.dirname(__file__), "..", "dashboard", "index.html")


def _read():
    with open(_HTML, encoding="utf-8") as f:
        return f.read()


def test_identity_preserved():
    h = _read()
    # pleochroic identity tokens from v1.11.0 :root — unchanged
    for tok in ["--bg:#06060f", "--v:#a855f7", "--i:#6366f1", "--c:#22d3ee",
                'data-theme="dark"', "SURFACE", "CARTOGRAPHY"]:
        assert tok in h, tok
    # the signature structures are all still there
    for lbl in ["TRIAGE LEDGER", "ACQUISITION LOG", "RESEARCH", "PIPELINE",
                "EFFECT SPECTRUM", "PRINCIPAL LOAD", 'id="cv"', ">SURVEY<"]:
        assert lbl in h, lbl


def test_interactivity_and_physics_present():
    h = _read()
    # B — interactivity on every element
    assert "ioSheen" in h          # wordmark sheen
    assert "gemSpin" in h          # gem click-spin
    assert "ioRip" in h and "ioCount(" in h   # ripples + count-up telemetry
    assert "slide-ind" in h and "linkSlide(" in h   # sliding group indicators
    assert "ioCharge" in h         # SURVEY charge pulse
    # C — physics on the moving things
    assert "mapRot" in h and "mapVel" in h     # drag-to-rotate map w/ inertia
    assert "markerHits" in h and "mapTip" in h # marker hit-testing + hover tooltip
    assert "selectOn(" in h        # triage <-> map cross-link
    assert "ioPing" in h           # pipeline completion ping
    # D/E — depth + production-ready
    assert "parallax" in h.lower() or "#vig" in h
    assert 'data-theme="light"' in h           # working theme toggle
    assert "prefers-reduced-motion" in h       # reduced-motion fallback


def test_center_stage_physics_field():
    h = _read()
    # the radial map is now a dense, physically-animated field
    assert "fxMotes" in h          # floating mote field (depth)
    assert "fxMarks" in h          # per-body spring state (float + impulse)
    assert "fxShock(" in h         # expanding shockwaves on click / survey-complete
    assert "flowing" in h.lower()  # data particles flowing along connection lines
    assert "spring" in h.lower()   # spring-driven bodies
    assert "graduat" in h.lower() or "counter-rotating" in h.lower() or "rings" in h.lower()


def test_offline_demo_fallback_kept():
    h = _read()
    # opens alive without a server: falls back to the embedded DEMO_SPEC
    assert "const DEMO_SPEC =" in h
    assert "render(DEMO_SPEC)" in h
