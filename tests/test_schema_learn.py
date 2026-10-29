"""
schema_learn — the target's authorization schema LEARNED from evidence, not matched
against an English wordlist. All fields here are deliberately non-English to prove the
semantics come from behaviour, not names.
"""
from iolite.intent.capture import CapturedExchange as CE
from iolite.intent.schema_learn import learn_schema


def _corpus():
    return [
        # 'secreto' + 'duenio' appear only in responses (server sets them)
        CE("A", "GET /v/{id}", "GET", "1", owned=True,
           response_fields={"secreto": "tok_aaaaaa", "duenio": "A", "estado": "nuevo"}, seq=0),
        CE("B", "GET /v/{id}", "GET", "2", owned=True,
           response_fields={"secreto": "tok_bbbbbb", "duenio": "B", "estado": "nuevo"}, seq=1),
        # same object changes 'estado' over its life: nuevo -> activo -> archivado
        CE("A", "PATCH /v/{id}", "PATCH", "1", owned=True,
           request_fields={"estado": "activo"}, response_fields={"estado": "activo"}, seq=2),
        CE("A", "PATCH /v/{id}", "PATCH", "1", owned=True,
           request_fields={"estado": "archivado"}, response_fields={"estado": "archivado"}, seq=3),
    ]


def test_learns_server_authoritative_fields_language_agnostic():
    s = learn_schema(_corpus())
    assert "secreto" in s.server_auth_fields     # response-only => server owns it
    assert "duenio" in s.server_auth_fields


def test_learns_state_field_by_change_over_life():
    s = learn_schema(_corpus())
    assert "estado" in s.state_fields
    # a constant secret is NOT a state field
    assert "secreto" not in s.state_fields


def test_learns_terminal_state_as_absorbing_node():
    s = learn_schema(_corpus())
    assert "archivado" in s.terminal_states      # reached via transition, no mutation after
    assert "nuevo" not in s.terminal_states      # initial value, not a transition target
    assert "activo" not in s.terminal_states     # a mutation (->archivado) happened after it


def test_no_english_knowledge_needed():
    """Pure proof: the classifier never saw the words 'secret/status/archived'."""
    s = learn_schema(_corpus())
    assert s.server_auth_fields and s.terminal_states


def test_ownership_field_detected_when_partition_clean():
    ex = [
        CE("A", "GET /p/{id}", "GET", "1", owned=True, request_fields={"propietario": "A"}, seq=0),
        CE("B", "GET /p/{id}", "GET", "2", owned=True, request_fields={"propietario": "B"}, seq=1),
    ]
    s = learn_schema(ex)
    assert "propietario" in s.ownership_fields    # per-principal, disjoint, stable => identity
