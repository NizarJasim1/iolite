"""Folder auto-detection — one command, no flag soup."""
import os

from iolite import detect
from iolite.pipeline import run
from iolite.roe import Engagement

_FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


def test_classifies_fixture_folder():
    inp, roe, notes = detect.detect_dir(_FIX)
    hars = {os.path.basename(p) for p in inp.har_files}
    assert {"capture_A.har", "capture_B.har"} <= hars
    assert any(p.endswith("app.js.map") for p in inp.sourcemap_files)
    assert any(p.endswith("app.archived.js") for p in inp.archived_js_files)   # archived by name
    assert any(p.endswith("app.current.js") for p in inp.js_files)
    assert inp.graphql_file and inp.graphql_file.endswith("graphql_introspection.json")


def test_archived_not_in_current():
    inp, _, _ = detect.detect_dir(_FIX)
    assert not any("archived" in p for p in inp.js_files)


def test_missing_dir_is_noted():
    inp, roe, notes = detect.detect_dir("/no/such/dir")
    assert notes and roe is None


def test_detected_inputs_build_a_spec():
    inp, _, _ = detect.detect_dir(_FIX)
    eng = Engagement(program="t", authorized_by="fix", operator="t",
                     in_scope_hosts=["shop.demo.test"], automation_permitted=True,
                     attestation="fix")
    res = run(eng, inp)
    assert res.spec["contract"]                 # a folder alone yields a working spec
    assert res.plan.probe
