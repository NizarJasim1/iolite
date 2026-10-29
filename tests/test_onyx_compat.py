"""
ONYX compatibility — the load-bearing integration contract.

Skips gracefully if ONYX/AuthPath is not importable (set ONYX_PATH to the onyx repo
root, or install it, to run this). When ONYX is present, it proves that ONYX's OWN
normalisation maps IOLITE's concrete probe paths onto exactly the templated contract
keys IOLITE emits — i.e. the spec is consumed natively, no translation.
"""
import os
import sys

_FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


def _load_onyx():
    p = os.environ.get("ONYX_PATH")
    if p and p not in sys.path:
        sys.path.insert(0, p)
    try:
        import authpath  # noqa
        return True
    except Exception:
        return False


def _demo_spec():
    from iolite.pipeline import Inputs, run
    from iolite.roe import Engagement
    eng = Engagement(program="t", authorized_by="fix", operator="t",
                     in_scope_hosts=["shop.demo.test"], automation_permitted=True,
                     attestation="fix")
    inp = Inputs(
        har_files=[os.path.join(_FIX, "capture_A.har"), os.path.join(_FIX, "capture_B.har")],
        js_files=[os.path.join(_FIX, "app.current.js")],
        sourcemap_files=[os.path.join(_FIX, "app.js.map")],
        archived_js_files=[os.path.join(_FIX, "app.archived.js")],
        graphql_file=os.path.join(_FIX, "graphql_introspection.json"))
    return run(eng, inp).spec


def test_onyx_parses_iolite_spec():
    if not _load_onyx():
        print("  (skipped: ONYX not importable — set ONYX_PATH to run)")
        return
    from authpath.cli import _principals, _req
    from authpath.scope_guard import ScopeConfig

    spec = _demo_spec()
    host = spec["base_url"].split("://", 1)[-1].split("/", 1)[0]
    # principals + scope construct ONYX objects
    _principals(spec)
    ScopeConfig(**{**{"allowed_hosts": [host]}, **spec.get("scope", {})})
    # every probe path normalises (by ONYX) to a contract key IOLITE emitted
    keys = set(spec["contract"])
    for item in spec["seed"] + spec["probe"]:
        assert _req(item, host).endpoint_key() in keys
