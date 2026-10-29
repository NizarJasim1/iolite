"""Adversarial robustness — hostile/huge/malformed inputs degrade, never crash/hang."""
import os
import tempfile

from iolite import js_extract
from iolite.limits import MAX_ENDPOINTS, MAX_CONCAT_PARTS
from iolite.pipeline import Inputs, run
from iolite.roe import Engagement
from iolite.har_ingest import ingest_har
from iolite.scope_guard import ScopeConfig, ScopeGuard


def _eng(hosts=("shop.demo.test",)):
    return Engagement(program="t", authorized_by="fix", operator="t",
                      in_scope_hosts=list(hosts), automation_permitted=True,
                      attestation="fix")


def test_huge_bundle_bounded_and_finds_real():
    junk = ("var x=" + "'noise'+" * 200000 + "'end';\n")     # ~1.6 MB of noise
    js = junk + 'http.get("/api/v1/orders/:id");\n'
    eps = {e.key for e in js_extract.extract_endpoints(js, "big.js")}
    assert "GET /api/v1/orders/{id}" in eps                   # real endpoint still found
    assert len(eps) <= MAX_ENDPOINTS


def test_pathological_concat_chain_capped():
    js = 'http.get("/api/x"' + '+"/y"' * 5000 + ');'
    eps = js_extract.extract_endpoints(js, "chain.js")        # must return, not hang
    assert isinstance(eps, list)
    for e in eps:
        assert e.path.count("/") <= MAX_CONCAT_PARTS + 2


def test_malformed_har_is_skipped_not_crash(tmp_path=None):
    d = tempfile.mkdtemp()
    bad = os.path.join(d, "bad.har")
    with open(bad, "w") as fh:
        fh.write("{ this is : not json ,,,")
    res = run(_eng(), Inputs(har_files=[bad]))
    assert res.spec["contract"] == {}                         # nothing, but no crash
    assert any("bad.har" in n for n in res.model.notes)       # skip recorded


def test_weird_har_shapes_no_crash():
    guard = ScopeGuard(ScopeConfig(allowed_hosts=["x.test"], automation_permitted=True))
    weird_entries = [None, {}, {"request": None}, {"request": {"url": ""}},
                     {"request": {"method": "GET"}}]
    for har in ({}, {"log": {}}, {"log": {"entries": "nope"}},
                {"log": {"entries": weird_entries}}):
        r = ingest_har(har, "A", guard, pid="A")              # must not raise
        assert isinstance(r.endpoints, list)


def test_deeply_nested_json_skipped():
    d = tempfile.mkdtemp()
    deep = os.path.join(d, "deep.json")
    with open(deep, "w") as fh:
        fh.write("[" * 5000 + "]" * 5000)                     # pathological depth
    res = run(_eng(), Inputs(graphql_file=deep))
    assert any("deep.json" in n for n in res.model.notes)     # skipped with a note


def test_missing_files_skipped():
    res = run(_eng(), Inputs(har_files=["/no/such.har"], js_files=["/no/such.js"],
                             graphql_file="/no/such.json"))
    assert res.spec["contract"] == {}
    assert len(res.model.notes) >= 2


def test_empty_inputs_produce_valid_spec():
    res = run(_eng(), Inputs())
    for k in ("base_url", "scope", "principals", "contract", "seed", "probe"):
        assert k in res.spec
