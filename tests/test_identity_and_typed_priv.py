"""
The two operands of the authz decision, resolved precisely (one seam = IDENTITY):

  SUBJECT (L3): privilege is typed PER resource-domain, not a flat scalar — so a
    domain-scoped BFLA (an attacker high overall but with no authority in THIS resource
    type) is surfaced instead of cleared by the global comparison.
  OBJECT (G5): the SAME object across surfaces/representations (1001 / gid://…/1001 /
    a base64 cursor) is unified into one identity — so a non-owner reproducing the owner's
    private value via a DIFFERENT door is corroborated as a cross-surface BOLA.

Oracle note (AMP): the decisive checks compare against the SHIPPED code — the global
`vertical_candidates` really misses the typed attacker (could-fail), and the shipped
`corroborate` sound gate is what confirms the cross-rep BOLA, not the test. Self-authored
inputs => E2 capability; the green gate over the golden fixtures is the external
no-regression half; live E3 stays with VAmPI / ONYX.
"""
from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.surface_model import vertical_candidates
from iolite.intent.relation_model import privilege_by_type, vertical_candidates_typed
from iolite.intent.divergence import enumerate_divergences
from iolite.intent.object_identity import resolve, unify_holdings
from iolite.intent.corroborate import corroborate
from iolite.intent.capture import CapturedExchange as CE


def _prov(loc=""):
    return Provenance.of(SourceKind.HAR, loc or "test.har")


def _typed_priv_model() -> SurfaceModel:
    """X is an admin of BILLING (globally the highest), Y is an admin of USERS only, Z is a
    nobody. The global scalar clears X for the users-admin function (X outranks Y overall);
    typed privilege denies X there — X has zero authority in the 'users' domain."""
    m = SurfaceModel(base_url="https://demo.example", host="demo.example")
    X, Y, Z = Principal("X", "x"), Principal("Y", "y"), Principal("Z", "z")
    m.principals = [X, Y, Z]

    def acc(pid, path, roles):
        m.add_endpoint(Endpoint(method="GET", path=path, effect=Effect.AUTHORITY,
                                role_hints=roles, provenance=[_prov()]))
        m.add_access(ObservedAccess(
            principal_id=pid, endpoint_key=f"GET {path}", object_id="", path=path,
            method="GET", provenance=_prov(), carrier="path", all_ids=[], safe_read=True))

    acc("X", "/api/billing/invoices", ["admin"])   # X: 2 billing-admin endpoints -> global top
    acc("X", "/api/billing/settings", ["admin"])
    acc("Y", "/api/users/admin", ["admin"])        # Y: 1 users-admin endpoint
    # Z reaches nothing privileged
    m.add_endpoint(Endpoint(method="GET", path="/api/home", effect=Effect.NONE, provenance=[_prov()]))
    m.add_access(ObservedAccess(principal_id="Z", endpoint_key="GET /api/home", object_id="",
                                path="/api/home", method="GET", provenance=_prov(),
                                carrier="path", all_ids=[], safe_read=True))
    return m


# ---- L3: typed privilege surfaces the BFLA the flat scalar hides ----------------

def test_privilege_is_typed_per_domain():
    pbt = privilege_by_type(_typed_priv_model())
    assert sum(pbt["X"].values()) == 2 and pbt["Y"].get("admin") == 1 and pbt["Z"] == {}
    assert pbt["X"].get("admin", 0) == 0          # X has NO authority in the users domain


def test_flat_score_misses_domain_scoped_bfla():
    """THE gap, shown against the shipped global generator: X (globally top) is NOT flagged
    as an attacker on the users-admin function; the typed pass flags it."""
    m = _typed_priv_model()
    global_probes = {p for c in vertical_candidates(m) if "users/admin" in c.path
                     for p in c.probe_pids}
    assert "X" not in global_probes, "flat score unexpectedly caught the domain BFLA"

    typed = {p for c in vertical_candidates_typed(m) if "users/admin" in c.path
             for p in c.probe_pids}
    assert "X" in typed, "typed privilege failed to surface the domain-scoped BFLA"


def test_divergence_vertical_includes_typed_attacker():
    cands = enumerate_divergences(_typed_priv_model())
    assert any(c.family == "vertical" and c.attacker == "X" and "users/admin" in c.path
               for c in cands), "the typed BFLA did not reach the divergence vertical family"


# ---- G5: object identity unification across representations ---------------------

def test_identity_resolves_representations():
    im = resolve(extra_ids=["1001", "gid://app/Order/1001", "MTAwMQ=="])  # b64('1001')
    assert im.canonical("gid://app/Order/1001") == im.canonical("1001")
    assert im.canonical("MTAwMQ==") == im.canonical("1001")


def test_identity_honest_floor_no_false_merge():
    im = resolve(extra_ids=["1001", "2002", "order-slug"])
    assert im.canonical("2002") != im.canonical("1001")
    # a *reference* to another object in a response must NOT merge objects
    im2 = resolve(exchanges=[CE("A", "GET /o/{id}", "GET", "1001", owned=True,
                                response_fields={"customer_id": "55"})], extra_ids=["55"])
    assert im2.canonical("55") != im2.canonical("1001")


def test_identity_codisclosure_self_id_only():
    im = resolve(exchanges=[CE("A", "GET /o/{id}", "GET", "ord_9", owned=True,
                               response_fields={"id": "1001"})], extra_ids=["1001"])
    assert im.canonical("ord_9") == im.canonical("1001")      # self-id field unifies


def test_cross_surface_bola_corroborated_only_with_identity():
    """A owns the object as REST id 1001; B reproduces A's private value via the GraphQL
    GID. Without identity the two ids never meet -> missed. With identity the shipped sound
    gate corroborates the cross-surface BOLA."""
    secret = "sk_live_7h3Qe9x"
    ex = [
        CE("A", "GET /orders/{id}", "GET", "1001", owned=True,
           response_fields={"id": "1001", "secret": secret}),
        CE("B", "GET /orders/{id}", "GET", "gid://app/Order/1001", owned=False,
           response_fields={"secret": secret}),
    ]
    assert not [f for f in corroborate(ex) if f.family == "read_bola"], \
        "cross-rep BOLA should be invisible without identity resolution"

    im = resolve(exchanges=ex)
    hits = [f for f in corroborate(ex, identity=im) if f.family == "read_bola"]
    assert hits and hits[0].owner == "A" and hits[0].attacker == "B"


def test_unify_holdings_merges_representations():
    m = SurfaceModel(base_url="https://x", host="x")
    m.holdings = {"1001": {"A"}, "gid://app/Order/1001": {"B"}}
    im = resolve(extra_ids=["1001", "gid://app/Order/1001"])
    merged = unify_holdings(m, im)
    assert len(merged) == 1 and next(iter(merged.values())) == {"A", "B"}
