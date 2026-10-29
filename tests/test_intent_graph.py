"""
Tests for Point 3 — IntentGraph (joint intent reconstruction). Proves: observed
multi-principal partition RAISES owner intent; a sibling's guard raises an under-rated
object surface (cross-surface floor, capped at OWNER); refinement is MONOTONE (never
lowers → never silences a bug); separation sets are attached; joint=False is identical.
"""

from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.reason.intent import infer_intent, AccessClass, RANK


def _prov():
    return Provenance.of(SourceKind.HAR, "cap")


def _model():
    m = SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"api.demo.test"}

    # owner-scoped item surface (base already OWNER via shape+effect)
    m.add_endpoint(Endpoint(method="GET", path="/api/orders/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()],
                            observed_ids=["1001"]))
    # a loose sibling surface for the SAME object type, base rates it weakly
    m.add_endpoint(Endpoint(method="GET", path="/api/public/orders",
                            effect=Effect.NONE, provenance=[_prov()]))
    # a feed endpoint with NO shape signal, but observed multi-principal PARTITION
    m.add_endpoint(Endpoint(method="GET", path="/api/feed",
                            effect=Effect.NONE, provenance=[_prov()]))

    # partition evidence on /api/feed: A and B hold DISJOINT objects there
    for pid, oid in (("A", "9001"), ("A", "9002"), ("B", "8001"), ("B", "8002")):
        m.add_access(ObservedAccess(
            principal_id=pid, endpoint_key="GET /api/feed", object_id=oid,
            path=f"/api/feed?after={oid}", method="GET", provenance=_prov(),
            all_ids=[oid], safe_read=True))
    return m


def test_partition_raises_owner():
    m = _model()
    base = infer_intent(m, joint=False)
    joint = infer_intent(m, joint=True)
    assert base["GET /api/feed"].rank < RANK[AccessClass.OWNER_ONLY]      # base is blind here
    assert joint["GET /api/feed"].access_class == AccessClass.OWNER_ONLY  # partition rescued it
    assert any("partition" in s for s in joint["GET /api/feed"].signals)


def test_cross_surface_owner_floor_capped():
    m = _model()
    joint = infer_intent(m, joint=True)
    r = joint["GET /api/public/orders"]
    assert r.access_class == AccessClass.OWNER_ONLY                       # raised to sibling floor
    assert r.rank <= RANK[AccessClass.OWNER_ONLY]                         # capped — never ADMIN
    assert any("cross-surface" in s for s in r.signals)


def test_monotone_never_lowers():
    m = _model()
    base = infer_intent(m, joint=False)
    joint = infer_intent(m, joint=True)
    for key in base:
        assert joint[key].rank >= base[key].rank, f"{key} was LOWERED — forbidden"


def test_separation_set_attached():
    m = _model()
    joint = infer_intent(m, joint=True)
    assert joint["GET /api/orders/{id}"].separates == ("other-users",)


def test_joint_off_is_identical():
    m = _model()
    a = infer_intent(m, joint=False)
    b = infer_intent(m, joint=False)
    assert {k: (r.access_class, r.confidence, r.signals) for k, r in a.items()} == \
           {k: (r.access_class, r.confidence, r.signals) for k, r in b.items()}
    # and joint adds signals only additively (base signals are a prefix)
    joint = infer_intent(m, joint=True)
    for key in a:
        assert a[key].signals == joint[key].signals[:len(a[key].signals)]


def test_determinism():
    m = _model()
    j1 = infer_intent(m, joint=True)
    j2 = infer_intent(m, joint=True)
    assert {k: r.access_class for k, r in j1.items()} == {k: r.access_class for k, r in j2.items()}
