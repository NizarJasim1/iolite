"""The ONYX bridge — real, offline verification through ONYX's own loaders.
Runs the deep check only when ONYX is importable (ONYX_PATH set); otherwise asserts
graceful degradation."""
from iolite import onyx_link
from tests.golden_util import demo_spec_normalized


def test_available_is_bool():
    assert isinstance(onyx_link.available(), bool)


def test_wait_until_up_false_on_dead_port():
    assert onyx_link.wait_until_up("http://127.0.0.1:1/", timeout=0.5) is False


def test_verify_spec_degrades_without_onyx_or_agrees_with_it():
    spec = demo_spec_normalized()
    v = onyx_link.verify_spec(spec)
    assert "available" in v
    if v["available"]:
        # ONYX present → it must parse the IOLITE spec and fully agree on endpoint keys
        assert v["parses"] is True, v
        assert v["agree"] is True, v
        assert v["recognised"] == v["requests"]
        assert set(v["principals"]) == {"A", "B"}
    else:
        assert v.get("hint") or v.get("error")   # explained, not a crash


def test_scan_requires_unredacted_tokens():
    # a redacted demo spec must be refused for a live scan (safety)
    import json, os, tempfile
    spec = demo_spec_normalized()
    d = tempfile.mkdtemp()
    p = os.path.join(d, "spec.json")
    with open(p, "w") as fh:
        json.dump(spec, fh)
    res = onyx_link.scan(p)
    if onyx_link.available():
        assert res["ok"] is False and "redacted" in res["error"]
    else:
        assert res["ok"] is False
