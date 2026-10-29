"""
graphql_probe — the concrete techniques that find authz bugs on big GraphQL targets:
global-id enumeration, alias-batch packing (beat rate limits), nested-object authz paths.
"""
import base64
from iolite.intent.graphql_probe import (decode_global_id, encode_global_id,
                                         neighbor_gids, alias_batch_query,
                                         nested_authz_paths)


def test_decode_base64_global_id():
    gid = base64.b64encode(b"Order:1007").decode()
    d = decode_global_id(gid)
    assert d and d.type == "Order" and d.num == 1007 and d.style == "b64colon"


def test_decode_uri_global_id():
    d = decode_global_id("gid://shopify/Order/1007")
    assert d and d.type == "Order" and d.num == 1007 and d.style == "uri"


def test_non_gid_returns_none():
    assert decode_global_id("just-a-slug") is None


def test_neighbor_gids_decode_increment_reencode():
    gid = base64.b64encode(b"Order:1007").decode()
    nb = neighbor_gids(gid, span=2)
    nums = sorted(decode_global_id(g).num for g in nb)
    assert nums == [1005, 1006, 1008, 1009]           # ±span, self excluded
    # re-encoding round-trips to the same style
    assert all(decode_global_id(g).style == "b64colon" for g in nb)


def test_alias_batch_packs_many_ids_in_one_query():
    q = alias_batch_query("order", ["A", "B", "C"], "id total")
    assert q.count("order(id:") == 3                   # 3 objects, ONE request
    assert "a0:" in q and "a2:" in q


def test_nested_authz_finds_payment_path():
    schema = {
        "Query": {"order": "Order"},
        "Order": {"id": "ID", "customer": "Customer"},
        "Customer": {"id": "ID", "paymentMethods": "PaymentMethod"},
        "PaymentMethod": {"id": "ID", "cardNumber": "String"},
    }
    paths = nested_authz_paths(schema)
    assert any(p.path[-1] == "paymentMethods" for p in paths)
    p = [x for x in paths if x.path[-1] == "paymentMethods"][0]
    assert p.path[0] == "order"                        # reachable from the root field
    assert "nested-object authz" in p.why


def test_encode_roundtrip_uri():
    d = decode_global_id("gid://shopify/Product/5")
    assert encode_global_id(d, 9) == "gid://shopify/Product/9"
