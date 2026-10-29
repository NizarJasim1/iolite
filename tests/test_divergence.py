"""
The wide divergence enumerator (iolite.intent.divergence) — generators that PROPOSE.

Built from a REAL SurfaceModel. Asserts every bug-bounty BOLA family is produced
(including the five documented automated-scanner blind spots), that generation is
sound-by-construction (every proposal is an intent-DENY carrying its derivation), and
that it is deterministic.
"""
from iolite.intent.kill_chain import build_demo_model
from iolite.intent.divergence import enumerate_divergences, family_counts
from iolite.intent.relation_model import build_lattice, Decision, Action


_EXPECTED = {"read_bola", "action_bola", "bopla_field", "rebinding",
             "workflow_state", "tenant", "vertical"}


def test_all_families_generated_from_real_model():
    cands = enumerate_divergences(build_demo_model())
    fams = set(family_counts(cands))
    missing = _EXPECTED - fams
    assert not missing, f"families not generated: {missing}"


def test_scanner_blind_spots_present():
    """The five families stateless pattern-scanners miss on mature targets."""
    fams = set(family_counts(enumerate_divergences(build_demo_model())))
    for blind in ("action_bola", "bopla_field", "rebinding", "workflow_state", "tenant"):
        assert blind in fams, f"blind-spot family missing: {blind}"


def test_every_candidate_carries_a_proof_obligation():
    for c in enumerate_divergences(build_demo_model()):
        assert c.derivation, f"candidate without a derivation: {c.key}"
        assert c.payout > 0
        assert c.severity in ("medium", "high", "critical")


def test_generation_is_sound_only_proposes_denied_tuples():
    """PROPOSE-only soundness: re-deriving each proposal's intent must NOT return ALLOW
    (the generator never wastes a probe on something intent permits)."""
    m = build_demo_model()
    lat = build_lattice(m)
    for c in enumerate_divergences(m, lat):
        dec, _ = lat.intended_decision(
            c.attacker, Action(c.action), endpoint_key=c.endpoint_key,
            oid=c.object_id, field_name=c.field_name, field_value=c.field_value,
            state=c.state)
        assert dec != Decision.ALLOW, f"proposed an ALLOWed tuple: {c.key} -> {dec}"


def test_deterministic():
    a = [c.key for c in enumerate_divergences(build_demo_model())]
    b = [c.key for c in enumerate_divergences(build_demo_model())]
    assert a == b


def test_equivalence_class_quotient_reduces():
    cands = enumerate_divergences(build_demo_model())
    classes = {c.equiv_class for c in cands}
    assert len(classes) < len(cands), "quotient did not reduce the raw space"
