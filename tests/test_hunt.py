"""
hunt — the field driver: real captures -> offline-proven bugs + leads + dossier, with the
live path fail-closed behind an attested engagement. Self-contained temp HARs.
"""
import json
import os
import tempfile

from iolite.intent.hunt import hunt, model_from_exchanges
from iolite.intent.har_capture import exchanges_from_dir
from iolite.intent import dossier
from iolite.roe import Engagement

_A = {"log": {"entries": [
    {"request": {"method": "POST", "url": "https://api.t.com/api/doc"},
     "response": {"status": 201, "content": {"text": "{\"id\":\"11\",\"secret\":\"tok_alpha12345\"}"}}},
    {"request": {"method": "GET", "url": "https://api.t.com/api/doc/11"},
     "response": {"status": 200, "content": {"text": "{\"id\":\"11\",\"secret\":\"tok_alpha12345\"}"}}},
]}}
_B = {"log": {"entries": [
    {"request": {"method": "GET", "url": "https://api.t.com/api/doc/11"},
     "response": {"status": 200, "content": {"text": "{\"id\":\"11\",\"secret\":\"tok_alpha12345\"}"}}},
]}}


def _caps():
    d = tempfile.mkdtemp(prefix="iolite_hunt_")
    with open(os.path.join(d, "a_alice.har"), "w") as fh:
        json.dump(_A, fh)
    with open(os.path.join(d, "b_bob.har"), "w") as fh:
        json.dump(_B, fh)
    return d


def _eng(attested=True):
    e = Engagement(program="T", in_scope_hosts=["api.t.com"])
    if attested:
        e.authorized_by = "https://hackerone.com/t"
        e.attestation = "authorized; own accounts"
    return e


def test_hunt_corroborates_offline_and_builds_dossier():
    rep = hunt(_caps(), engagement=_eng())
    assert rep.exchanges >= 3
    assert any(f.family == "read_bola" for f in rep.corroborated)
    md = dossier.render(rep, program="T")
    assert "Confirmed offline" in md and "BOLA" in md


def test_model_from_exchanges_builds_real_model():
    ex = exchanges_from_dir(_caps(), scope_hosts={"api.t.com"})
    m = model_from_exchanges(ex, host="api.t.com")
    assert len(m.principals) == 2
    assert m.endpoints and m.accesses


def test_live_refused_without_attestation():
    rep = hunt(_caps(), engagement=_eng(attested=False), live=True)
    assert rep.live_status.startswith("REFUSED")
    assert rep.live_findings == []


def test_live_skipped_without_target_cfg():
    e = _eng()
    e.automation_permitted = True
    rep = hunt(_caps(), engagement=e, live=True, target_cfg=None)
    assert rep.live_status.startswith("SKIPPED") or rep.live_status.startswith("REFUSED")
    assert rep.live_findings == []


def test_offline_path_sends_nothing_and_still_finds():
    # no engagement at all -> still offline-safe, still corroborates
    rep = hunt(_caps())
    assert any(f.family == "read_bola" for f in rep.corroborated)
