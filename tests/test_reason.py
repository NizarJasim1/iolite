"""
Tests for the reason engine (grey-box authorization reasoning).

Covers: intent reconstruction, I△E candidates (observed + shadow-admin), the
cross-surface invariant, the unguessable-ids assumption, determinism, the one-way
(no-verdict) rule, and — critically — that reason NEVER weakens the existing
pipeline (an empty surface yields no candidates and no crash).
"""

from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.reason import (reason, infer_intent, AccessClass, build_reason_spec,
                           candidates_to_plan)
from iolite.reason.intent import RANK
from iolite.roe import Engagement


def _prov(src=SourceKind.HAR, loc="cap"):
    return Provenance.of(src, loc)


def _model_two_accounts():
    """A minimal surface: two of YOUR principals, an owner-scoped object endpoint,
    a mined admin endpoint nobody reached, and a numeric id."""
    m = SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")
    m.principals = [Principal(pid="A", label="acct-A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="acct-B", auth={"Authorization": "b"})]
    m.hosts_seen = {"api.demo.test"}

    # owner-scoped object endpoint, principal A holds object 1001 (sequential id)
    ep = Endpoint(method="GET", path="/api/orders/{id}", effect=Effect.OBJECT_ACCESS,
                  provenance=[_prov(SourceKind.HAR)], observed_ids=["1001"])
    m.add_endpoint(ep)
    m.add_access(ObservedAccess(
        principal_id="A", endpoint_key="GET /api/orders/{id}", object_id="1001",
        path="/api/orders/1001", method="GET", provenance=_prov(),
        carrier="path", all_ids=["1001"], safe_read=True))

    # a mined ADMIN endpoint (from JS) that NEITHER principal ever reached
    adm = Endpoint(method="POST", path="/api/admin/users", effect=Effect.AUTHORITY,
                   provenance=[_prov(SourceKind.JS, "app.js")],
                   role_hints=["admin"])
    m.add_endpoint(adm)
    return m


def test_intent_infers_owner_and_admin():
    m = _model_two_accounts()
    intent = infer_intent(m)
    assert intent["GET /api/orders/{id}"].access_class == AccessClass.OWNER_ONLY
    assert intent["POST /api/admin/users"].access_class == AccessClass.ADMIN_ONLY
    # every rule carries at least one human-checkable signal (QL3)
    assert all(r.signals for r in intent.values())


def test_reason_produces_candidates_and_no_verdict():
    m = _model_two_accounts()
    rep = reason(m)
    assert rep.counts["candidates"] >= 1
    # one-way rule (QL5): a candidate carries an ONYX effect, never a verdict field
    for c in rep.candidates:
        assert c.onyx_effect  # names the EffectClass ONYX will confirm under
        assert not hasattr(c, "verdict")
        assert c.probe_pids  # asks one of YOUR principals


def test_shadow_admin_surface_candidate_exists():
    """The declared-but-unreached admin endpoint must yield a candidate — this is the
    capability no observed-access generator has (there is no access to replay)."""
    m = _model_two_accounts()
    rep = reason(m)
    shadow = [c for c in rep.candidates
              if c.gap_kind == "declared_unreached_gap"
              and c.endpoint_key == "POST /api/admin/users"]
    assert shadow, "expected a shadow-admin (declared-unreached) candidate"
    assert shadow[0].intent_class == "ADMIN_ONLY"


def test_unguessable_ids_assumption_fires_on_sequential():
    m = _model_two_accounts()
    rep = reason(m)
    enum = [c for c in rep.candidates if c.family == "assumption_enum"]
    assert enum, "sequential id 1001 should trigger the unguessable-ids assumption"
    # neighbour probe targets an adjacent id the principal does not own
    assert any(c.object_id == "1002" for c in enum)


def test_cross_surface_invariant_fires():
    """Same object addressable on a strict and a loose surface → cross-surface cand."""
    m = _model_two_accounts()
    # add a looser surface that also exposes object 1001 (public-ish search echo)
    loose = Endpoint(method="GET", path="/api/search", effect=Effect.FIELD_PROJECTION,
                     provenance=[_prov(SourceKind.HAR)])
    m.add_endpoint(loose)
    m.add_access(ObservedAccess(
        principal_id="A", endpoint_key="GET /api/search", object_id="1001",
        path="/api/search", method="GET", provenance=_prov(),
        query={"q": "1001"}, carrier="query", all_ids=["1001"], safe_read=True))
    rep = reason(m)
    xs = [c for c in rep.candidates if c.family == "invariant_cross_surface"]
    assert xs, "expected a cross-surface consistency candidate for object 1001"


def test_determinism():
    m1, m2 = _model_two_accounts(), _model_two_accounts()
    r1, r2 = reason(m1), reason(m2)
    sig = lambda r: [(c.family, c.endpoint_key, c.path, c.object_id, tuple(c.probe_pids))
                     for c in r.candidates]
    assert sig(r1) == sig(r2)


def test_reason_spec_is_onyx_shaped_and_carries_reason_block():
    m = _model_two_accounts()
    rep = reason(m)
    eng = Engagement(program="t", authorized_by="scope-url", operator="me",
                     in_scope_hosts=["api.demo.test"],
                     attestation="I am authorised and all accounts are mine.")
    spec = build_reason_spec(m, rep, eng)
    # ONYX-shaped keys present
    for k in ("base_url", "scope", "principals", "contract", "seed", "probe"):
        assert k in spec
    # self-describing reason block, with the honesty ceiling embedded (P7)
    assert spec["_reason"]["candidates"]
    assert spec["_reason"]["walls"]
    # probes only ever name YOUR principals (QL6)
    pids = {p["pid"] for p in spec["principals"]}
    for item in spec["probe"]:
        assert item["principal"] in pids


def test_empty_surface_is_safe():
    """Red line: reason must never crash or invent on an empty surface."""
    m = SurfaceModel(base_url="https://x.test", host="x.test")
    m.principals = [Principal(pid="A", label="a")]
    rep = reason(m)
    assert rep.counts["candidates"] == 0
    plan = candidates_to_plan(m, rep.candidates)
    assert plan.probe == []


def test_intent_rank_ordering():
    assert RANK[AccessClass.ADMIN_ONLY] > RANK[AccessClass.OWNER_ONLY]
    assert RANK[AccessClass.OWNER_ONLY] > RANK[AccessClass.AUTHENTICATED]


# --------------------------------------------------------------------------- #
# HAZOP assumption library — the five negations (each must fire on its signal)  #
# --------------------------------------------------------------------------- #

def _model_hazop():
    m = SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"api.demo.test"}

    # internal-only endpoint, never reached
    m.add_endpoint(Endpoint(method="GET", path="/api/internal/config",
                            effect=Effect.AUTHORITY, provenance=[_prov(SourceKind.JS)]))
    # client-supplied role
    m.add_endpoint(Endpoint(method="GET", path="/api/dashboard",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/dashboard",
                 object_id="", path="/api/dashboard", method="GET", provenance=_prov(),
                 query={"role": "user"}, carrier="query", safe_read=True))
    # lifecycle state param
    m.add_endpoint(Endpoint(method="GET", path="/api/tickets",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/tickets",
                 object_id="", path="/api/tickets", method="GET", provenance=_prov(),
                 query={"status": "active"}, carrier="query", safe_read=True))
    # nested child path (parent owned, child swappable)
    m.add_endpoint(Endpoint(method="GET", path="/api/users/{id}/documents/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A",
                 endpoint_key="GET /api/users/{id}/documents/{id}", object_id="900",
                 path="/api/users/501/documents/900", method="GET", provenance=_prov(),
                 carrier="path", all_ids=["501", "900"], safe_read=True))
    # export surface, object held by A → B is a non-holder
    m.add_endpoint(Endpoint(method="GET", path="/api/export/orders",
                            effect=Effect.FIELD_PROJECTION, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/export/orders",
                 object_id="A99", path="/api/export/orders", method="GET", provenance=_prov(),
                 query={"scope": "A99"}, carrier="query", all_ids=["A99"], safe_read=True))
    return m


def test_hazop_all_five_fire():
    rep = reason(_model_hazop())
    fams = rep.by_family()
    assert fams.get("assumption_internal", 0) >= 1
    assert fams.get("assumption_client_role", 0) >= 1
    assert fams.get("assumption_lifecycle", 0) >= 1
    assert fams.get("assumption_nested_child", 0) >= 1
    assert fams.get("assumption_export", 0) >= 1


def test_hazop_catalog_all_active():
    from iolite.reason.assumptions import catalog_status
    st = catalog_status()
    assert len(st) == 7
    assert all(a["status"] == "active" for a in st)


def test_hazop_client_role_elevates_and_stays_own_principal():
    rep = reason(_model_hazop())
    cr = [c for c in rep.candidates if c.family == "assumption_client_role"]
    assert cr and cr[0].query.get("role") == "admin"
    assert cr[0].probe_pids == ["A"]        # own principal only (QL6)


def test_hazop_nested_child_keeps_parent_swaps_child():
    rep = reason(_model_hazop())
    nc = [c for c in rep.candidates if c.family == "assumption_nested_child"]
    assert nc and "/api/users/501/documents/901" == nc[0].path   # parent 501 kept, child 900→901


def test_hazop_export_probed_by_peer():
    rep = reason(_model_hazop())
    ex = [c for c in rep.candidates if c.family == "assumption_export"]
    assert ex and ex[0].probe_pids == ["B"]   # a peer who does not hold A99


# --------------------------------------------------------------------------- #
# Invariant catalog — the transplanted sciences (each fires on its signal)      #
# --------------------------------------------------------------------------- #

def _model_invariants():
    m = SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"api.demo.test"}

    # non-interference: a validation/lookup endpoint
    m.add_endpoint(Endpoint(method="GET", path="/api/username/check",
                            effect=Effect.FIELD_PROJECTION, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/username/check",
                 object_id="", path="/api/username/check", method="GET", provenance=_prov(),
                 query={"name": "alice"}, carrier="query", safe_read=True))
    # conservation: a price/quote endpoint with a quantity
    m.add_endpoint(Endpoint(method="GET", path="/api/quote",
                            effect=Effect.PRICE, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/quote",
                 object_id="", path="/api/quote", method="GET", provenance=_prov(),
                 query={"quantity": "2"}, carrier="query", safe_read=True))
    # freshness: a token bound to an object id
    m.add_endpoint(Endpoint(method="GET", path="/api/invites/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/invites/{id}",
                 object_id="700", path="/api/invites/700", method="GET", provenance=_prov(),
                 query={"token": "abc123"}, carrier="query", all_ids=["700"], safe_read=True))
    # information-flow: an object endpoint that accepts include=
    m.add_endpoint(Endpoint(method="GET", path="/api/orders/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/orders/{id}",
                 object_id="5", path="/api/orders/5", method="GET", provenance=_prov(),
                 query={"include": "items"}, carrier="query", all_ids=["5"], safe_read=True))
    # cross-surface: same object 5 also on a looser search surface
    m.add_endpoint(Endpoint(method="GET", path="/api/search",
                            effect=Effect.FIELD_PROJECTION, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/search",
                 object_id="5", path="/api/search", method="GET", provenance=_prov(),
                 query={"q": "5"}, carrier="query", all_ids=["5"], safe_read=True))
    return m


def test_invariants_all_five_fire():
    rep = reason(_model_invariants())
    fams = rep.by_family()
    for fam in ("invariant_non_interference", "invariant_conservation",
                "invariant_freshness", "invariant_information_flow",
                "invariant_cross_surface"):
        assert fams.get(fam, 0) >= 1, f"{fam} did not fire"


def test_invariant_catalog_all_active():
    from iolite.reason.invariants import catalog_status
    st = catalog_status()
    assert len(st) == 5
    assert all(i["status"] == "active" for i in st)


def test_invariant_conservation_sets_negative():
    rep = reason(_model_invariants())
    cons = [c for c in rep.candidates if c.family == "invariant_conservation"]
    assert cons and cons[0].query.get("quantity") == "-1"


def test_invariant_freshness_replays_token_across_object():
    rep = reason(_model_invariants())
    fr = [c for c in rep.candidates if c.family == "invariant_freshness"]
    assert fr and fr[0].query.get("token") == "abc123"   # SAME token
    assert fr[0].path == "/api/invites/701"              # DIFFERENT object


def test_invariant_candidates_carry_onyx_effect_no_verdict():
    rep = reason(_model_invariants())
    for c in rep.candidates:
        assert c.onyx_effect
        assert not hasattr(c, "verdict")
