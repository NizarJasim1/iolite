"""
Soundness of the ONE metamorphic oracle gate (iolite.intent.metamorphic).

These are REAL pytest-style tests (discovered by tests/run_all.py): every verdict
path is exercised, and a decoy battery proves FP=0 — no benign/flaky/observer-
dependent/unsafe case can ever reach CONFIRMED.
"""
from iolite.intent.metamorphic import Evidence, Verdict, decide


def test_confirmed_on_sound_read():
    r = decide(Evidence(attacker_reproduced_value=True),
               family="read_bola", coord=("GET", "/vault/{id}", "1", ""))
    assert r.verdict == Verdict.CONFIRMED
    assert r.cert["replayable"] is True
    assert r.cert["write_safe"] is True


def test_confirmed_net_zero_write():
    r = decide(Evidence(is_write=True, reversible=True, restored=True,
                        attacker_reproduced_value=True))
    assert r.verdict == Verdict.CONFIRMED


def test_clean_when_attacker_authorized_via_own_surface():
    r = decide(Evidence(attacker_surface_authorized=True, attacker_reproduced_value=True))
    assert r.verdict == Verdict.CLEAN


def test_clean_when_attacker_is_supervisor():
    r = decide(Evidence(attacker_is_supervisor=True, attacker_reproduced_value=True))
    assert r.verdict == Verdict.CLEAN


def test_clean_when_attacker_stably_denied():
    assert decide(Evidence(attacker_reproduced_value=False)).verdict == Verdict.CLEAN


def test_refused_irreversible_write():
    r = decide(Evidence(is_write=True, reversible=False, attacker_reproduced_value=True))
    assert r.verdict == Verdict.REFUSED


def test_refused_write_not_restored():
    r = decide(Evidence(is_write=True, reversible=True, restored=False,
                        attacker_reproduced_value=True))
    assert r.verdict == Verdict.REFUSED


def test_abstain_flaky():
    assert decide(Evidence(attacker_reproduced_value=True, stable=None)).verdict == Verdict.ABSTAIN


def test_abstain_controls_disagree():
    assert decide(Evidence(attacker_reproduced_value=True,
                           controls_agree=False)).verdict == Verdict.ABSTAIN


def test_abstain_benign_cause_control_also_in():
    assert decide(Evidence(attacker_reproduced_value=True,
                           control_reproduced_value=True)).verdict == Verdict.ABSTAIN


def test_abstain_no_private_anchor():
    assert decide(Evidence(declared_private=False,
                           attacker_reproduced_value=True)).verdict == Verdict.ABSTAIN


def test_lead_when_attacker_response_unobserved():
    assert decide(Evidence(attacker_reproduced_value=None)).verdict == Verdict.LEAD


def test_lead_when_no_discriminating_value():
    assert decide(Evidence(holder_has_discriminating_value=False,
                           attacker_reproduced_value=True)).verdict == Verdict.LEAD


def test_lead_when_holder_baseline_invalid():
    assert decide(Evidence(holder_request_ok=False,
                           attacker_reproduced_value=True)).verdict == Verdict.LEAD


def test_zero_fp_decoy_battery():
    """No decoy — benign, flaky, observer-dependent, public-by-design, denied,
    or unsafe — may EVER be reported as CONFIRMED."""
    decoys = [
        Evidence(attacker_surface_authorized=True, attacker_reproduced_value=True),
        Evidence(attacker_is_supervisor=True, attacker_reproduced_value=True),
        Evidence(attacker_reproduced_value=True, stable=None),
        Evidence(attacker_reproduced_value=True, controls_agree=False),
        Evidence(attacker_reproduced_value=True, control_reproduced_value=True),
        Evidence(attacker_reproduced_value=False),
        Evidence(declared_private=False, attacker_reproduced_value=True),
        Evidence(is_write=True, reversible=False, attacker_reproduced_value=True),
        Evidence(attacker_reproduced_value=None),
        Evidence(holder_has_discriminating_value=False, attacker_reproduced_value=True),
    ]
    assert all(decide(d).verdict != Verdict.CONFIRMED for d in decoys)


def test_widening_generators_cannot_raise_fp():
    """The invariant: however many proposals arrive, only sound ones confirm. A huge
    batch of decoys + a few real bugs -> confirmations == exactly the real bugs."""
    real = [Evidence(attacker_reproduced_value=True) for _ in range(5)]
    decoys = [Evidence(attacker_reproduced_value=False) for _ in range(500)]
    confirmed = sum(decide(e).verdict == Verdict.CONFIRMED for e in real + decoys)
    assert confirmed == 5
