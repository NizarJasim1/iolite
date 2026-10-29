"""
The WIRED unified kill-chain (iolite.intent.kill_chain) over a REAL SurfaceModel.

Proves the whole-tool composition end-to-end: GENERATE (wide, from the model) ->
REDUCE (quotient) -> SCHEDULE (EV budget) -> CONFIRM (the one metamorphic gate) ->
CERTIFY -> REPORT. Separation of powers: GENERATE is wired and offline; CONFIRM is a
pluggable provider standing in for ONYX's live Δstate. Widening GENERATE can never
raise FP because only the single gate disposes.
"""
from iolite.intent.kill_chain import build_demo_model, build_demo_exchanges, run
from iolite.intent.metamorphic import Evidence


def _sound_live_provider(c):
    """Stands in for ONYX: the denied principal reproduced the private value, target
    is stable, controls agree and were denied, writes are net-zero. (A real bug.)"""
    is_write = c.action in ("write", "create", "delete")
    return Evidence(attacker_reproduced_value=True, is_write=is_write,
                    reversible=(c.action != "delete"), restored=True)


def _benign_live_provider(c):
    """Every probe turns out legitimately authorized via the attacker's own surface."""
    return Evidence(attacker_surface_authorized=True, attacker_reproduced_value=True)


def test_offline_run_generates_all_families_and_is_safe():
    rep = run(build_demo_model())
    assert len(rep.by_family) >= 7
    assert rep.quotient <= rep.raw
    # offline the gate must REFUSE the irreversible write, never confirm it
    assert len(rep.refused) >= 1
    assert all(c.action != "delete" for c, _ in rep.findings)
    assert rep.false_positives == 0


def test_offline_leads_carry_exact_probe_and_derivation():
    rep = run(build_demo_model())
    assert rep.leads, "expected live-leads offline"
    for c in rep.leads:
        assert c.method and c.path and c.derivation


def test_lattice_summary_exposed_in_report():
    rep = run(build_demo_model())
    assert rep.lattice["server_authoritative_fields"]
    assert rep.lattice["ownership_fields"]
    assert rep.lattice["excluded_state_objects"]


def test_live_confirmation_catches_many_families_fp_zero():
    rep = run(build_demo_model(), evidence_provider=_sound_live_provider)
    confirmed_families = {c.family for c, _ in rep.findings}
    # the scanner-blind families confirm when the live signal is present
    assert len(confirmed_families) >= 4
    assert "action_bola" in confirmed_families or "bopla_field" in confirmed_families
    # deletes are still refused (never performed), not confirmed
    assert all(c.action != "delete" for c, _ in rep.findings)
    # every finding carries a replayable certificate
    for _c, cert in rep.findings:
        assert cert.get("replayable") is True
        assert cert.get("write_safe") is True
    assert rep.false_positives == 0


def test_benign_provider_yields_zero_findings():
    rep = run(build_demo_model(), evidence_provider=_benign_live_provider)
    assert len(rep.findings) == 0           # FP floor: nothing confirms when all authorized


def test_widening_does_not_raise_fp_vs_benign():
    """Same wide generation; a benign world confirms nothing, a real-bug world confirms
    only real bugs. Widening raised recall, never the FP rate."""
    bugs = run(build_demo_model(), evidence_provider=_sound_live_provider)
    benign = run(build_demo_model(), evidence_provider=_benign_live_provider)
    assert bugs.raw == benign.raw                # identical, wide generation
    assert len(benign.findings) == 0
    assert len(bugs.findings) > 0


def test_deterministic_report():
    r1 = run(build_demo_model())
    r2 = run(build_demo_model())
    assert r1.raw == r2.raw and r1.quotient == r2.quotient
    assert r1.by_family == r2.by_family


# --- v1.16: learned schema + offline corroboration wired into the chain ---------

def test_schema_is_learned_from_evidence_not_wordlist():
    rep = run(build_demo_model(), exchanges=build_demo_exchanges())
    # non-English fields understood purely from behaviour
    assert "secreto" in rep.schema["server_auth_fields"]
    assert "estado" in rep.schema["state_fields"]
    assert "archivado" in rep.schema["terminal_states"]


def test_offline_corroboration_confirms_a_real_bola_zero_requests():
    rep = run(build_demo_model(), exchanges=build_demo_exchanges())
    assert any(f.family == "read_bola" for f in rep.corroborated)
    assert rep.confirmed_total >= 1          # proven offline, before any live step
    for f in rep.corroborated:
        assert f.cert.get("replayable") is True


def test_learned_terminal_state_drives_workflow_family():
    """A non-English terminal state ('archivado') must still produce workflow_state."""
    rep = run(build_demo_model(), exchanges=build_demo_exchanges())
    assert "workflow_state" in rep.by_family


def test_thin_model_without_responses_corroborates_nothing():
    rep = run(build_demo_model())   # exchanges_from_model -> no responses
    assert rep.corroborated == []   # honest: no fabricated offline confirmation
