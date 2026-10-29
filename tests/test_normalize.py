"""Path normalisation must match ONYX's endpoint_key form."""
from iolite.normalize import endpoint_key, object_ids


def test_numeric_id_templated():
    assert endpoint_key("GET", "/api/v1/orders/1001") == "GET /api/v1/orders/{id}"
    assert object_ids("/api/v1/orders/1001") == ["1001"]


def test_action_segment_not_id():
    # 'location' follows an id and is an action word — not itself an id
    assert endpoint_key("GET", "/api/v1/vehicles/9/location") == "GET /api/v1/vehicles/{id}/location"
    assert object_ids("/api/v1/vehicles/9/location") == ["9"]


def test_self_alias_not_id():
    assert endpoint_key("GET", "/api/v1/users/me") == "GET /api/v1/users/me"
    assert object_ids("/api/v1/users/me") == []


def test_uuid_and_template_markers():
    u = "550e8400-e29b-41d4-a716-446655440000"
    assert endpoint_key("GET", f"/api/v1/users/{u}") == "GET /api/v1/users/{id}"
    assert endpoint_key("GET", "/api/v1/orders/:orderId") == "GET /api/v1/orders/{id}"


def test_subresource_word_not_id():
    # a bare alpha sub-resource after a collection noun stays literal
    assert endpoint_key("GET", "/api/v1/users/settings") == "GET /api/v1/users/settings"
