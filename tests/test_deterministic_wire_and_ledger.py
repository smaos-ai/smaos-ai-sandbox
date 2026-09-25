import pytest
from src.transport_observer import classify_wire_event, WireDisposition
from src.nonce_ledger import ApprovalNonceLedger, ReplayAttackViolation

def test_classify_wire_event_deterministc_states():
    # Gate: Policy Blocked
    obs = classify_wire_event(
        policy_blocked=True,
        request_bytes_written=False,
        authoritative_receipt=False,
        response_status=None,
        transport_error=None
    )
    assert obs.disposition == WireDisposition.LOCALLY_BLOCKED

    # Gate: Authoritative receipt -> Remote Confirmed
    obs = classify_wire_event(
        policy_blocked=False,
        request_bytes_written=True,
        authoritative_receipt=True,
        response_status=201,
        transport_error=None
    )
    assert obs.disposition == WireDisposition.REMOTE_CONFIRMED

    # Gate: 504 Timeout -> Dispatched Unconfirmed
    obs = classify_wire_event(
        policy_blocked=False,
        request_bytes_written=True,
        authoritative_receipt=False,
        response_status=504,
        transport_error=None
    )
    assert obs.disposition == WireDisposition.DISPATCHED_UNCONFIRMED

    # Gate: Transport Reset post-write -> Dispatched Unconfirmed
    obs = classify_wire_event(
        policy_blocked=False,
        request_bytes_written=True,
        authoritative_receipt=False,
        response_status=None,
        transport_error="connection_reset_after_write"
    )
    assert obs.disposition == WireDisposition.DISPATCHED_UNCONFIRMED

def test_atomic_nonce_ledger_replay_defense(tmp_path):
    db_path = tmp_path / "ledger.db"
    ledger = ApprovalNonceLedger(str(db_path))
    
    payload = {"action": "wire_transfer", "amount": 1000}
    approval_id = "app_123"
    scope = "finance:transfer"
    
    nonce = ledger.record_approval(
        approval_id=approval_id,
        approved_payload=payload,
        principal_id="user_77",
        task_scope=scope
    )
    
    # Consume 1: Success
    res = ledger.consume_nonce(nonce, approval_id, payload, scope)
    assert res is True
    
    # Consume 2: Replay Attack (Should Fail)
    with pytest.raises(ReplayAttackViolation) as excinfo:
        ledger.consume_nonce(nonce, approval_id, payload, scope)
    
    assert "already been consumed" in str(excinfo.value)
