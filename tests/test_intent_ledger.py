import pytest
from src.intent_ledger import IntentLedger, IntentCollisionError

def test_collision_detected_aborts_execution(tmp_path):
    db_file = str(tmp_path / "test_intent.db")
    ledger = IntentLedger(db_file)
    id1 = ledger.declare_intent("agent_a", "shared.resource", {"op": "write"})
    assert id1 is not None

    # Foremerge pattern: second agent attempting to acquire the same resource while PENDING must abort
    with pytest.raises(IntentCollisionError) as exc_info:
        ledger.declare_intent("agent_b", "shared.resource", {"op": "write"})
    assert "Collision detected" in str(exc_info.value)

    # Resolving agent_a's intent frees the resource lock
    ledger.resolve_intent(id1, "CONFIRMED")
    id2 = ledger.declare_intent("agent_b", "shared.resource", {"op": "write"})
    assert id2 is not None
