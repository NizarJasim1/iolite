"""Authz-risk triage — deterministic, transparent, correctly ordered."""
from iolite.models import Effect, Endpoint, Provenance, SourceKind, SurfaceModel
from iolite import triage


def _ep(method, path, effect=Effect.NONE, ids=None, roles=None, src=SourceKind.JS):
    return Endpoint(method=method, path=path, effect=effect,
                    observed_ids=ids or [], role_hints=roles or [],
                    provenance=[Provenance.of(src, path)])


def test_object_access_scores_above_plain():
    m = SurfaceModel()
    m.add_endpoint(_ep("GET", "/api/v1/orders/{id}", Effect.OBJECT_ACCESS, ids=["1001"]))
    m.add_endpoint(_ep("GET", "/api/v1/status", Effect.NONE))
    triage.rank(m)
    obj = m.endpoints["GET /api/v1/orders/{id}"]
    plain = m.endpoints["GET /api/v1/status"]
    assert obj.risk > plain.risk
    assert any("BOLA" in r for r in obj.risk_reasons)


def test_sequential_id_beats_uuid():
    m = SurfaceModel()
    m.add_endpoint(_ep("GET", "/api/v1/a/{id}", Effect.OBJECT_ACCESS, ids=["7"]))
    m.add_endpoint(_ep("GET", "/api/v1/b/{id}", Effect.OBJECT_ACCESS,
                       ids=["550e8400-e29b-41d4-a716-446655440000"]))
    triage.rank(m)
    assert m.endpoints["GET /api/v1/a/{id}"].risk > m.endpoints["GET /api/v1/b/{id}"].risk


def test_ghost_gets_bonus():
    m = SurfaceModel()
    m.add_endpoint(_ep("GET", "/api/v0/orders/{id}", Effect.OBJECT_ACCESS, ids=["1"],
                       roles=["ghost:removed-from-current-ui"]))
    triage.rank(m)
    ep = m.endpoints["GET /api/v0/orders/{id}"]
    assert any("ghost" in r for r in ep.risk_reasons)


def test_admin_authority_scored():
    m = SurfaceModel()
    m.add_endpoint(_ep("PUT", "/api/v1/admin/users/{id}/role", Effect.AUTHORITY,
                       ids=["1"], roles=["admin-path"]))
    triage.rank(m)
    ep = m.endpoints["PUT /api/v1/admin/users/{id}/role"]
    assert any("privilege" in r or "BFLA" in r for r in ep.risk_reasons)


def test_deterministic_ranking():
    def build():
        m = SurfaceModel()
        m.add_endpoint(_ep("GET", "/api/v1/orders/{id}", Effect.OBJECT_ACCESS, ids=["1"]))
        m.add_endpoint(_ep("GET", "/api/v1/users/{id}", Effect.OBJECT_ACCESS, ids=["2"]))
        return [e.key for e in triage.rank(m)]
    assert build() == build()
