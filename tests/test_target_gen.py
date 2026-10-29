"""
target_gen — auto-derive a reviewable engine intervention target.json from captures.
"""
from iolite.intent.capture import CapturedExchange as CE
from iolite.intent.target_gen import generate_target, to_json


def _ex():
    return [
        CE("alice", "POST /api/vault", "POST", "1001", owned=True,
           request_fields={"title": "x", "secret": "s"},
           response_fields={"id": "1001", "secret": "tok_a1"}, status=201, seq=0),
        CE("alice", "GET /api/vault/{id}", "GET", "1001", owned=True,
           response_fields={"id": "1001", "secret": "tok_a1"}, status=200, seq=1),
        # a read-only type: only a GET, no create observed
        CE("alice", "GET /api/report/{id}", "GET", "7", owned=True,
           response_fields={"id": "7"}, status=200, seq=2),
    ]


def _host_patch(ex):
    for e in ex:
        e.host = "api.t.com"
    return ex


def test_derives_create_read_kind_with_placeholders():
    cfg = generate_target(_host_patch(_ex()),
                          principal_auth={"alice": {"authorization": "Bearer A"},
                                          "bob": {"authorization": "Bearer B"}})
    kinds = {k["name"]: k for k in cfg["kinds"]}
    assert "vault" in kinds
    v = kinds["vault"]
    assert v["create"]["method"] == "POST" and v["create"]["path"] == "/api/vault"
    assert v["create"]["body"]["secret"] == "{{secret}}"       # plantable private field
    assert v["read"]["path"] == "/api/vault/{{id}}"            # engine id token
    assert cfg["host"] == "api.t.com" and cfg["base_url"].endswith("api.t.com")


def test_static_auth_from_principals():
    cfg = generate_target(_host_patch(_ex()),
                          principal_auth={"alice": {"authorization": "Bearer A"},
                                          "bob": {"authorization": "Bearer B"}})
    assert cfg["auth"] == {}                                   # static-credential mode
    assert cfg["principals"]["A"]["headers"]["authorization"] == "Bearer A"
    assert cfg["principals"]["B"]["headers"]["authorization"] == "Bearer B"


def test_read_only_type_flagged_not_dropped_silently():
    cfg = generate_target(_host_patch(_ex()), principal_auth=None)
    assert any("report" in t for t in cfg["_TODO"])           # read-but-no-create is surfaced
    # no accounts provided -> flagged
    assert any("accounts" in t for t in cfg["_TODO"])


def test_output_is_valid_json():
    import json
    cfg = generate_target(_host_patch(_ex()))
    json.loads(to_json(cfg))                                   # round-trips
    assert "_safety" in cfg
