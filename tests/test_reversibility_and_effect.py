"""
Reversibility safety tag (Leap-1 completion) + dataflow-effect corroboration (Leap-2 deep).

Two sides of one seam — the true nature of a MUTATING candidate:
  • can it be confirmed without harm?  -> a verb-aware reversibility class on the candidate,
    wired into the sound oracle so an irreversible trigger (POST /wallet/{id}/transfer) is
    REFUSED before any packet — closing the hole the POST-action work would otherwise open
    (the old oracle treated only literal "delete" as irreversible).
  • what does it actually do, and to whom? -> the action's effect read from OBSERVED
    cross-principal dataflow (a non-owner's mutation accepted & echoed on a holder's object),
    not from the verb's name.

Oracle note (AMP): the "refused / corroborated" verdicts below are produced by the SHIPPED
`metamorphic.decide` and `corroborate` — the model does not assert the outcome itself, the
tool's own sound gate does. Self-authored inputs keep the capability claim at E2; the green
gate over the shipped golden fixtures is the external ('given') no-regression half. A live
E3 belongs to VAmPI / ONYX Δstate.
"""
from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.intent.divergence import enumerate_divergences
from iolite.intent.relation_model import action_safety
from iolite.intent.metamorphic import evidence_from_model, decide, Verdict
from iolite.intent.corroborate import corroborate
from iolite.intent.capture import CapturedExchange as CE
from iolite.intent.kill_chain import build_demo_model, build_demo_exchanges


def _prov(loc=""):
    return Provenance.of(SourceKind.HAR, loc or "test.har")


def _model() -> SurfaceModel:
    """A owns wallet w1 (and legitimately triggers transfer + share on it); B owns w2.
    Intent denies B both triggers on w1 — one irreversible (money), one compensating."""
    m = SurfaceModel(base_url="https://demo.example", host="demo.example")
    A, B = Principal("A", "alice"), Principal("B", "bob")
    m.principals = [A, B]

    def acc(pid, method, path, oid, *, body=None, safe_read=True):
        tmpl = path.replace(oid, "{id}") if oid else path
        m.add_endpoint(Endpoint(method=method, path=tmpl, effect=Effect.OBJECT_ACCESS,
                                provenance=[_prov()], observed_ids=[oid] if oid else []))
        m.add_access(ObservedAccess(
            principal_id=pid, endpoint_key=f"{method} {tmpl}", object_id=oid, path=path,
            method=method, provenance=_prov(), body=body, carrier="path",
            all_ids=[oid] if oid else [], safe_read=safe_read))

    acc("A", "GET",  "/api/wallet/w1", "w1")
    acc("A", "POST", "/api/wallet/w1/transfer", "w1", body={"amount": 5}, safe_read=False)
    acc("A", "POST", "/api/wallet/w1/share", "w1", body={"to": "C"}, safe_read=False)
    acc("B", "GET",  "/api/wallet/w2", "w2")
    return m


def _pick(cands, path_sub):
    hits = [c for c in cands if c.family == "action_bola" and c.method == "POST"
            and c.attacker == "B" and path_sub in c.path]
    assert hits, f"no POST action_bola candidate for {path_sub!r}"
    return hits[0]


# ---- Leap-1: reversibility classifier + oracle wiring ---------------------------

def test_action_safety_classifier():
    assert action_safety("POST", "/api/wallet/{id}/transfer") == "irreversible"
    assert action_safety("POST", "/api/invoices/{id}/refund") == "irreversible"
    assert action_safety("POST", "/api/users/{id}/ban") == "irreversible"
    assert action_safety("DELETE", "/api/doc/{id}") == "irreversible"
    assert action_safety("POST", "/api/users/{id}/follow") == "compensating"
    assert action_safety("POST", "/api/features/{id}/enable") == "compensating"
    assert action_safety("PATCH", "/api/profile/{id}") == "reversible"
    assert action_safety("GET", "/api/x/{id}") == "reversible"
    assert action_safety("POST", "/api/things/{id}/frobnicate") == "unknown"  # fail-closed


def test_candidate_carries_reversibility_tag():
    cands = enumerate_divergences(_model())
    assert _pick(cands, "/transfer").safety == "irreversible"
    assert _pick(cands, "/share").safety == "compensating"


def test_oracle_refuses_irreversible_trigger():
    """THE safety property, via the shipped sound oracle: an irreversible cross-user write
    is REFUSED before execution; a reversible one is not refused on that ground."""
    m = _model()
    cands = enumerate_divergences(m)
    bad = _pick(cands, "/transfer")
    res = decide(evidence_from_model(m, bad), family=bad.family, derivation=bad.derivation)
    assert res.verdict == Verdict.REFUSED, f"irreversible write not refused: {res.verdict}"

    ok = _pick(cands, "/share")
    res2 = decide(evidence_from_model(m, ok), family=ok.family, derivation=ok.derivation)
    assert res2.verdict != Verdict.REFUSED, "a compensating action was wrongly refused"


# ---- Leap-2: dataflow-effect corroboration of the ACTION family -----------------

def _ex_nonowner_write(echo: bool, path="/api/invoice/{id}", method="PATCH",
                       fields=None):
    fields = fields or {"status": "paid"}
    return [
        CE("A", f"{method} {path}", method, "inv1", owned=True,
           request_fields=fields, response_fields=fields, seq=0),
        CE("B", f"{method} {path}", method, "inv1", owned=False,
           request_fields=fields,
           response_fields=(fields if echo else {}), seq=1),
    ]


def test_action_bola_corroborated_from_dataflow():
    found = corroborate(_ex_nonowner_write(echo=True))
    acts = [f for f in found if f.family == "action_bola"]
    assert acts, "a non-owner mutation accepted & echoed was not corroborated"
    f = acts[0]
    assert f.owner == "A" and f.attacker == "B" and f.object_id == "inv1"
    assert f.cert["write_safe"] is True            # PATCH of a plain field is reversible


def test_action_corroboration_honest_floor_without_echo():
    """No echoed change => cannot prove the write landed => NOT corroborated (live lead)."""
    found = corroborate(_ex_nonowner_write(echo=False))
    assert not [f for f in found if f.family == "action_bola"]


def test_irreversible_action_corroboration_is_critical_and_unsafe():
    ex = _ex_nonowner_write(echo=True, path="/api/wallet/{id}/transfer",
                            method="POST", fields={"amount": "999"})
    acts = [f for f in corroborate(ex) if f.family == "action_bola"]
    assert acts and acts[0].severity == "critical"
    assert acts[0].cert["write_safe"] is False and acts[0].cert["action_safety"] == "irreversible"


# ---- regression locks -----------------------------------------------------------

def test_demo_surface_unchanged():
    """The pre-existing demo capture has no non-owner mutating+echo, so no action_bola is
    corroborated there — and the stock divergence demo keeps every original family."""
    assert not [f for f in corroborate(build_demo_exchanges()) if f.family == "action_bola"]
    fams = {c.family for c in enumerate_divergences(build_demo_model())}
    for f in ("read_bola", "action_bola", "bopla_field", "rebinding",
              "workflow_state", "tenant", "vertical"):
        assert f in fams
