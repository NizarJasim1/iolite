"""GraphQL introspection → endpoints with conservative effects."""
import json, os
from iolite.graphql_schema import parse_introspection
from iolite.models import Effect

_FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


def _model():
    doc = json.load(open(os.path.join(_FIX, "graphql_introspection.json")))
    return {e.key: e for e in parse_introspection(doc)}


def test_query_with_id_is_object_access():
    eps = _model()
    assert eps["QUERY user"].effect == Effect.OBJECT_ACCESS
    assert eps["QUERY order"].effect == Effect.OBJECT_ACCESS


def test_list_query_is_field_projection():
    assert _model()["QUERY orders"].effect == Effect.FIELD_PROJECTION


def test_role_mutation_is_authority_grant():
    assert _model()["MUTATION updateUserRole"].effect == Effect.AUTHORITY_GRANT


def test_payment_mutation():
    assert _model()["MUTATION refundOrder"].effect == Effect.PAYMENT
