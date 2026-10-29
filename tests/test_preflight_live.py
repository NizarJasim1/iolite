"""
Tests for Point 5 — preflight (fail-closed live-safety gate) + live_calibrate
(non-determinism baseline that protects ONYX's zero-false-positive on a live target).
Proves: every mandatory gate can veto GO; a noise-only change is NOT a sound Δstate;
a real security change IS; determinism.
"""

from iolite.models import Principal, SurfaceModel
from iolite.roe import Engagement
from iolite.preflight import preflight
from iolite.live_calibrate import calibrate_from_samples, is_sound_delta


def _eng(**over):
    e = Engagement(
        program="Acme (HackerOne)", authorized_by="https://hackerone.com/acme/scope",
        operator="me", in_scope_hosts=["api.acme.com"], out_of_scope_hosts=["internal.acme.com"],
        automation_permitted=True, allow_destructive=False, dry_run=True,
        own_accounts_only=True, max_requests_per_min=30,
        attestation="I confirm I am authorised and all accounts are mine.")
    for k, v in over.items():
        setattr(e, k, v)
    return e


def _model(hosts=("api.acme.com",), n=2):
    m = SurfaceModel(host=hosts[0] if hosts else "")
    m.hosts_seen = set(hosts)
    m.principals = [Principal(pid=chr(65 + i), label=f"acct{i}", auth={"Authorization": "x"})
                    for i in range(n)]
    return m


def test_preflight_all_green_is_go():
    r = preflight(_eng(), _model(), spec=None, onyx_check=False)
    assert r.go is True
    assert r.mandatory_ok is True


def test_missing_attestation_vetoes():
    r = preflight(_eng(attestation="<write me>"), _model(), onyx_check=False)
    assert r.go is False
    assert any(g.name == "attestation" and not g.ok for g in r.gates)


def test_out_of_scope_host_vetoes():
    r = preflight(_eng(), _model(hosts=("evil.example.net",)), onyx_check=False)
    assert r.go is False
    assert any(g.name == "scope" and not g.ok for g in r.gates)


def test_single_principal_vetoes():
    r = preflight(_eng(), _model(n=1), onyx_check=False)
    assert r.go is False
    assert any(g.name == "principals" and not g.ok for g in r.gates)


def test_destructive_default_vetoes():
    r = preflight(_eng(dry_run=False), _model(), onyx_check=False, allow_write=False)
    assert r.go is False
    assert any(g.name == "non-destructive" and not g.ok for g in r.gates)


def test_bounded_write_opt_in_allowed():
    r = preflight(_eng(dry_run=False, allow_destructive=True), _model(),
                  onyx_check=False, allow_write=True)
    assert all(g.ok for g in r.gates if g.mandatory)


# ---- non-determinism calibration ---------------------------------------- #

def _samples():
    return [{"owner_id": 1, "balance": 50, "timestamp": 100, "views": 3},
            {"owner_id": 1, "balance": 50, "timestamp": 200, "views": 7}]


def test_calibrate_detects_volatile_and_stable():
    p = calibrate_from_samples(_samples())
    assert "timestamp" in p.volatile_fields          # differs across reads + known-volatile
    assert "views" in p.volatile_fields              # differs across reads
    assert "owner_id" in p.security_fields           # stable, security-bearing
    assert p.stability_k >= 3                         # non-determinism ⇒ vote, don't trust one read


def test_noise_only_change_is_not_sound():
    p = calibrate_from_samples(_samples())
    sound, changed = is_sound_delta(
        {"owner_id": 1, "balance": 50, "timestamp": 100},
        {"owner_id": 1, "balance": 50, "timestamp": 999}, p)
    assert sound is False and changed == []           # only a volatile field moved ⇒ NOT a breach


def test_real_security_change_is_sound():
    p = calibrate_from_samples(_samples())
    sound, changed = is_sound_delta(
        {"owner_id": 1, "balance": 50}, {"owner_id": 2, "balance": 50}, p)
    assert sound is True and "owner_id" in changed    # a security field actually changed


def test_determinism():
    p1 = calibrate_from_samples(_samples())
    p2 = calibrate_from_samples(_samples())
    assert p1.volatile_fields == p2.volatile_fields and p1.stability_k == p2.stability_k
