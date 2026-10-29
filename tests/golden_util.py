"""Shared helper: produce the demo spec with volatile fields normalised."""
import os

from iolite.pipeline import Inputs, run
from iolite.roe import Engagement

_FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
GOLDEN_PATH = os.path.join(_FIX, "golden_demo_spec.json")


def demo_spec_normalized() -> dict:
    eng = Engagement(
        program="IOLITE self-demo (fixtures)",
        authorized_by="in-repo fixtures (self-authored, always authorised)",
        operator="demo", in_scope_hosts=["shop.demo.test"],
        automation_permitted=True, allow_destructive=False, dry_run=True,
        own_accounts_only=True, attestation="Fixtures are self-authored and safe to test.")
    inp = Inputs(
        har_files=[os.path.join(_FIX, "capture_A.har"), os.path.join(_FIX, "capture_B.har")],
        js_files=[os.path.join(_FIX, "app.current.js")],
        sourcemap_files=[os.path.join(_FIX, "app.js.map")],
        archived_js_files=[os.path.join(_FIX, "app.archived.js")],
        graphql_file=os.path.join(_FIX, "graphql_introspection.json"))
    spec = run(eng, inp, redact=True).spec
    # normalise the only volatile field: the tool version
    if "_iolite" in spec:
        spec["_iolite"]["version"] = "<VERSION>"
    return spec
