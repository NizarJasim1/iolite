"""Tier-aware emission — contract is only probeable; the rest are honest leads."""
import os

from iolite.pipeline import Inputs, run
from iolite.roe import Engagement
from iolite.onyx_spec import plan_keys

_FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


def _res():
    eng = Engagement(program="t", authorized_by="fix", operator="t",
                     in_scope_hosts=["shop.demo.test"], automation_permitted=True,
                     attestation="self-authored fixtures")
    inp = Inputs(
        har_files=[os.path.join(_FIX, "capture_A.har"), os.path.join(_FIX, "capture_B.har")],
        js_files=[os.path.join(_FIX, "app.current.js")],
        sourcemap_files=[os.path.join(_FIX, "app.js.map")],
        archived_js_files=[os.path.join(_FIX, "app.archived.js")],
        graphql_file=os.path.join(_FIX, "graphql_introspection.json"))
    return run(eng, inp)


def test_every_contract_entry_is_probeable():
    res = _res()
    pk = plan_keys(res.plan)
    for key in res.spec["contract"]:
        assert key in pk, f"contract entry {key} is not exercised by the plan"


def test_contract_and_leads_are_disjoint():
    res = _res()
    contract = set(res.spec["contract"])
    leads = {ld["endpoint"] for ld in res.spec["_iolite"]["leads"]}
    assert contract.isdisjoint(leads)


def test_unprobeable_mined_endpoints_become_leads():
    res = _res()
    leads = {ld["endpoint"] for ld in res.spec["_iolite"]["leads"]}
    # admin PUT (mined, no concrete id) and a ghost must be leads, not contract
    assert "PUT /api/v1/admin/users/{id}/role" in leads
    assert "GET /api/v0/orders/{id}" in leads
    assert "PUT /api/v1/admin/users/{id}/role" not in res.spec["contract"]


def test_observed_contract_entries_are_high_confidence():
    res = _res()
    meta = res.spec["_iolite"]["contract_meta"]
    # the HAR-observed endpoints are T1_LIVE → high confidence
    for key in res.spec["contract"]:
        assert meta[key]["confidence"] in ("high", "medium")
    assert meta["GET /api/v1/orders/{id}"]["confidence"] == "high"


def test_coverage_number_is_honest():
    res = _res()
    # contract must be far smaller than total endpoints (no inflation)
    assert len(res.spec["contract"]) < len(res.model.endpoints)
    assert res.spec["_iolite"]["contract_probeable"] == len(res.spec["contract"])


def test_leads_carry_activation():
    res = _res()
    for ld in res.spec["_iolite"]["leads"]:
        assert ld["activation"] and ld["reason"]
