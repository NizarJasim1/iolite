"""
corroborate — CONFIRM authorization bugs OFFLINE from multi-account captures, sending
ZERO new requests. This is the practical win v1.15 lacked. Soundness: no responses ->
nothing confirmed (honest leads), not a fabricated finding.
"""
from iolite.intent.capture import CapturedExchange as CE
from iolite.intent.schema_learn import LearnedSchema
from iolite.intent.corroborate import corroborate


def test_offline_read_bola_from_shared_secret():
    ex = [
        CE("A", "GET /vault/{id}", "GET", "1001", owned=True,
           response_fields={"secret": "tok_7h3Qe9x1"}, seq=0),
        CE("B", "GET /vault/{id}", "GET", "2002", owned=True,
           response_fields={"secret": "tok_Zk1p2Lq8"}, seq=1),
        # B's own capture contains A's object 1001 WITH A's secret -> proven BOLA
        CE("B", "GET /vault/{id}", "GET", "1001", owned=False,
           response_fields={"secret": "tok_7h3Qe9x1"}, seq=2),
    ]
    found = corroborate(ex)
    assert any(f.family == "read_bola" and f.object_id == "1001" and f.attacker == "B"
               for f in found)
    f = [x for x in found if x.family == "read_bola"][0]
    assert f.cert["replayable"] is True and f.cert["write_safe"] is True


def test_offline_tenant_crossing():
    ex = [
        CE("A", "GET /report/{id}", "GET", "7", owned=True,
           response_fields={"x": "aaaaaa"}, tenant="T1", seq=0),
        # B in tenant T2 holds a capture of T1's object 7
        CE("B", "GET /report/{id}", "GET", "7", owned=False,
           response_fields={"x": "aaaaaa"}, tenant="T2", seq=1),
    ]
    found = corroborate(ex)
    assert any(f.family == "tenant" and f.severity == "critical" for f in found)


def test_offline_bopla_reflected_server_field():
    sch = LearnedSchema(server_auth_fields={"clearance"})
    ex = [
        CE("A", "PATCH /me", "PATCH", "u1", owned=True,
           request_fields={"clearance": "TOP"}, response_fields={"clearance": "TOP"}, seq=0),
    ]
    found = corroborate(ex, sch)
    assert any(f.family == "bopla_field" for f in found)


def test_no_responses_confirms_nothing():
    """Honest floor: a thin model (no response_fields) yields NO corroboration."""
    ex = [
        CE("A", "GET /vault/{id}", "GET", "1001", owned=True, seq=0),
        CE("B", "GET /vault/{id}", "GET", "1001", owned=False, seq=1),
    ]
    assert corroborate(ex) == []


def test_shared_default_value_is_not_corroborated():
    """A value common across many objects is a shared default, not a discriminator."""
    ex = [
        CE("A", "GET /item/{id}", "GET", "1", owned=True,
           response_fields={"type": "standard"}, seq=0),
        CE("A", "GET /item/{id}", "GET", "2", owned=True,
           response_fields={"type": "standard"}, seq=1),
        CE("A", "GET /item/{id}", "GET", "3", owned=True,
           response_fields={"type": "standard"}, seq=2),
        CE("B", "GET /item/{id}", "GET", "1", owned=False,
           response_fields={"type": "standard"}, seq=3),
    ]
    # 'standard' appears for many objects -> not object-specific -> no false finding
    assert all(f.family != "read_bola" for f in corroborate(ex))
