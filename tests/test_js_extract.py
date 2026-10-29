"""JS miner — endpoints, method inference, role hints."""
from iolite.js_extract import extract_endpoints, extract_flags
from iolite.models import Effect


JS = """
var api = {
  getOrder: function(id){ return http.get('/api/v1/orders/:orderId'); },
  updateRole: function(u){ if(user.isAdmin){ http.put('/api/v1/admin/users/:userId/role',{role:u}); } },
  refund: function(id){ return http.post('/api/v1/orders/:orderId/refund'); },
  asset: function(){ return fetch('/static/app.css'); }
};
export const featureNewCheckout = true;
"""


def _by_key(eps):
    return {e.key: e for e in eps}


def test_mines_object_access_get():
    eps = _by_key(extract_endpoints(JS, "app.js"))
    assert "GET /api/v1/orders/{id}" in eps
    assert eps["GET /api/v1/orders/{id}"].effect == Effect.OBJECT_ACCESS


def test_infers_method_and_admin_role():
    eps = _by_key(extract_endpoints(JS, "app.js"))
    admin = eps.get("PUT /api/v1/admin/users/{id}/role")
    assert admin is not None
    assert admin.effect == Effect.AUTHORITY          # admin path + mutating verb
    assert any("admin" in r for r in admin.role_hints)


def test_ignores_static_assets():
    eps = _by_key(extract_endpoints(JS, "app.js"))
    assert not any("static" in k for k in eps)


def test_post_is_state_gate():
    eps = _by_key(extract_endpoints(JS, "app.js"))
    assert eps["POST /api/v1/orders/{id}/refund"].effect == Effect.STATE_GATE


def test_feature_flags():
    assert "featureNewCheckout" in extract_flags(JS)


def test_deterministic():
    a = [e.key for e in extract_endpoints(JS, "app.js")]
    b = [e.key for e in extract_endpoints(JS, "app.js")]
    assert a == b == sorted(a)
