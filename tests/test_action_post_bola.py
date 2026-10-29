"""
ACTION-BOLA via POST — the trigger half of the 41.7% action-BOLA family.

The wide enumerator walked PATCH/PUT/DELETE for cross-user mutation but never POST, so
RPC action/trigger endpoints on an EXISTING object (…/{id}/refund, …/{id}/promote,
…/{id}/share) — the dominant action shape on mature REST-RPC APIs — produced no
candidate at all. These tests pin the closed gap AND its zero-false-positive floor:
a create-collection POST (/api/note, no object addressed) must NOT become action-BOLA,
and the pre-existing demo surface must gain no POST action-BOLA (no regression).

Oracle note (AMP): the model below is author-written, so the "it fires" claim is a
self-check (E2). The green gate over the shipped golden fixtures is the external
('given') half: it proves the default contract stays byte-identical. A live E3
confirmation belongs to VAmPI / ONYX Δstate, not to this unit.
"""
from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.intent.divergence import enumerate_divergences, family_counts
from iolite.intent.kill_chain import build_demo_model
from iolite.intent.relation_model import (build_lattice, Decision, Action,
                                          post_is_action, resource_type_of)


def _prov(loc=""):
    return Provenance.of(SourceKind.HAR, loc or "test.har")


def _model_with_post_action() -> SurfaceModel:
    """A minimal real surface: A owns vault 1001 and legitimately triggers the action
    POST /api/vault/{id}/share on her own object; B owns 2002. Intent therefore DENIES B
    the share-action on 1001. Also a create-collection POST /api/note (addresses no
    existing object) — the negative control."""
    m = SurfaceModel(base_url="https://demo.example", host="demo.example")
    A, B = Principal("A", "alice"), Principal("B", "bob")
    m.principals = [A, B]

    def acc(pid, method, path, oid, *, body=None, safe_read=True, params=None):
        tmpl = path.replace(oid, "{id}") if oid else path
        m.add_endpoint(Endpoint(method=method, path=tmpl, effect=Effect.OBJECT_ACCESS,
                                params=params or [], provenance=[_prov()],
                                observed_ids=[oid] if oid else []))
        m.add_access(ObservedAccess(
            principal_id=pid, endpoint_key=f"{method} {tmpl}", object_id=oid,
            path=path, method=method, provenance=_prov(), body=body, carrier="path",
            all_ids=[oid] if oid else [], safe_read=safe_read))

    acc("A", "GET",  "/api/vault/1001", "1001")
    acc("A", "POST", "/api/vault/1001/share", "1001", body={"to": "C"}, safe_read=False)
    acc("B", "GET",  "/api/vault/2002", "2002")
    # negative control: a real create, no existing object addressed
    acc("A", "POST", "/api/note", "", body={"text": "hi"}, safe_read=False)
    return m


def _post_action_bolas(cands):
    return [c for c in cands
            if c.family == "action_bola" and c.method == "POST"]


def test_post_trigger_on_foreign_object_is_generated():
    """The core gap: a POST action on another principal's object yields action-BOLA."""
    cands = enumerate_divergences(_model_with_post_action())
    hits = [c for c in _post_action_bolas(cands)
            if c.attacker == "B" and c.object_id == "1001"
            and c.path == "/api/vault/1001/share"]
    assert hits, "POST action-BOLA for the denied peer was not generated"
    c = hits[0]
    assert c.action == "write", f"a trigger must classify as write, got {c.action!r}"
    assert c.derivation and "trigger" in c.derivation.lower()
    assert c.payout > 0 and c.severity in ("high", "critical")


def test_create_collection_post_is_not_action_bola():
    """Zero-FP floor: a create (/api/note, no object) must never become action-BOLA."""
    cands = enumerate_divergences(_model_with_post_action())
    assert not any(c.family == "action_bola" and "note" in c.path for c in cands), \
        "a create-collection POST was wrongly treated as an action on a foreign object"


def test_post_action_candidates_are_sound():
    """PROPOSE-only soundness: re-deriving intent for each POST action-BOLA is not ALLOW."""
    m = _model_with_post_action()
    lat = build_lattice(m)
    for c in _post_action_bolas(enumerate_divergences(m, lat)):
        dec, _ = lat.intended_decision(
            c.attacker, Action(c.action), endpoint_key=c.endpoint_key,
            oid=c.object_id, state=c.state)
        assert dec != Decision.ALLOW, f"proposed an ALLOWed tuple: {c.key} -> {dec}"


def test_deterministic():
    a = [c.key for c in enumerate_divergences(_model_with_post_action())]
    b = [c.key for c in enumerate_divergences(_model_with_post_action())]
    assert a == b


def test_demo_surface_gains_no_post_action_bola():
    """Regression lock: the pre-existing demo model has no id-bearing POST, so the new
    path must add NOTHING to it — every original family still present, no POST added."""
    cands = enumerate_divergences(build_demo_model())
    assert not _post_action_bolas(cands), \
        "the POST path changed the pre-existing surface (regression / new FP)"
    fams = set(family_counts(cands))
    for f in ("read_bola", "action_bola", "bopla_field", "rebinding",
              "workflow_state", "tenant", "vertical"):
        assert f in fams, f"family regressed: {f}"


def test_classifier_primitives():
    """The behavioural create-vs-action distinction, verb/id-aware and language-pragmatic."""
    assert post_is_action("/api/vault/{id}/share") is True        # existing object
    assert post_is_action("/api/orders/{id}/cancel") is True
    assert post_is_action("/api/orders/bulk/cancel") is True      # id-less sub-action
    assert post_is_action("/api/note") is False                   # bare create
    assert post_is_action("/api/transfer") is False               # verb, but no resource before
    assert resource_type_of("/api/vault/{id}/share") == "vault"   # acts on vault, not 'share'
    assert resource_type_of("/api/orders/{id}/cancel") == "order"
    assert resource_type_of("/api/note") == "note"
