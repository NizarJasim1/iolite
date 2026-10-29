"""End-to-end offline pipeline on the bundled fixtures."""
import os

from iolite.pipeline import Inputs, run
from iolite.roe import Engagement

_FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


def _eng():
    return Engagement(
        program="test", authorized_by="fixtures", operator="t",
        in_scope_hosts=["shop.demo.test"], automation_permitted=True,
        dry_run=True, allow_destructive=False, own_accounts_only=True,
        attestation="self-authored fixtures")


def _inputs():
    return Inputs(
        har_files=[os.path.join(_FIX, "capture_A.har"), os.path.join(_FIX, "capture_B.har")],
        js_files=[os.path.join(_FIX, "app.current.js")],
        sourcemap_files=[os.path.join(_FIX, "app.js.map")],
        archived_js_files=[os.path.join(_FIX, "app.archived.js")],
        graphql_file=os.path.join(_FIX, "graphql_introspection.json"))


def test_pipeline_runs_and_emits_spec():
    res = run(_eng(), _inputs())
    assert res.model.base_url == "https://shop.demo.test"
    assert len(res.model.principals) == 2
    assert len(res.spec["contract"]) > 0
    # spec has the ONYX-required top-level keys
    for k in ("base_url", "scope", "principals", "contract", "seed", "probe"):
        assert k in res.spec


def test_out_of_scope_host_dropped():
    # capture_A includes analytics.googleapis.com — must NOT appear anywhere
    res = run(_eng(), _inputs())
    blob = repr(res.spec) + res.dossier
    assert "googleapis" not in blob


def test_cross_principal_probes_are_own_principals_only():
    res = run(_eng(), _inputs())
    pids = {p.pid for p in res.model.principals}
    for pr in res.spec["probe"]:
        assert pr["principal"] in pids                 # QL6
        assert pr["method"] == "GET"                   # safety
        assert pr["_replayed_from"] in pids


def test_ghost_endpoints_detected():
    res = run(_eng(), _inputs())
    assert "GET /api/v0/orders/{id}" in res.model.ghost_keys


def test_tokens_redacted_by_default():
    res = run(_eng(), _inputs())
    for p in res.spec["principals"]:
        for v in p["auth"].values():
            assert v.startswith("$TOKEN_")


def test_deterministic_bytewise():
    a = run(_eng(), _inputs()).spec
    b = run(_eng(), _inputs()).spec
    import json
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
