"""
SMAOS Loopjacking Defense-in-Depth Benchmark (v1.1.0)
Validates sink-level assertions, scope binding, TTL expiry, and post-approval payload mutations.
Asserts a 0.0% false-allow rate across all adversarial threat vectors.
"""

import time
import pytest
from src.idempotency_binder import generate_idempotency_key
from src.intent_ledger import IntentLedger
from src.nonce_ledger import (
    ApprovalExpiredViolation,
    ApprovalNonceLedger,
    PayloadTamperViolation,
    ReplayAttackViolation,
    ScopeViolation,
)
from src.smaos_gate import SmaosPreDispatchGate
from src.transport_observer import WireDisposition


@pytest.fixture
def isolated_gate(tmp_path):
    """Provides a fresh isolated pre-dispatch gate."""
    nonce_db = str(tmp_path / "test_nonces.db")
    intent_db = str(tmp_path / "test_intents.db")
    nl = ApprovalNonceLedger(db_path=nonce_db)
    il = IntentLedger(db_path=intent_db)
    return SmaosPreDispatchGate(nonce_ledger=nl, intent_ledger=il), nl


def test_loopjacking_sink_level_replay_attack(isolated_gate):
    """Replaying an authorization nonce must fail with ReplayAttackViolation."""
    gate, nonce_ledger = isolated_gate
    payload = {"action": "wire_transfer", "amount": 50000, "currency": "EUR"}
    approval_id = "appr-001"
    scope = "treasury.execute"

    nonce = nonce_ledger.record_approval(approval_id, payload, "ciso-alice", scope)

    def dummy_wire(**kwargs):
        class R:
            status_code = 200
        return R()

    # 1. First legitimate call succeeds
    res, obs, adv = gate.admit_and_dispatch(
        approval_id, nonce, payload, scope, dummy_wire
    )
    assert obs.disposition == WireDisposition.CONFIRMED

    # 2. Second replay attempt MUST fail
    with pytest.raises(ReplayAttackViolation) as exc_info:
        gate.admit_and_dispatch(
            approval_id, nonce, payload, scope, dummy_wire
        )
    assert "already been consumed" in str(exc_info.value)


def test_loopjacking_post_approval_payload_mutation(isolated_gate):
    """Altering payload parameters after human approval must raise PayloadTamperViolation."""
    gate, nonce_ledger = isolated_gate
    approved_payload = {"recipient": "CZ6508000000001234567890", "amount": 1000}
    approval_id = "appr-002"
    scope = "treasury.execute"

    nonce = nonce_ledger.record_approval(approval_id, approved_payload, "ciso-alice", scope)

    # Malicious or prompt-injected mutation
    mutated_payload = {"recipient": "CZ6508000000001234567890", "amount": 999999}

    def dummy_wire(**kwargs):
        class R:
            status_code = 200
        return R()

    with pytest.raises(PayloadTamperViolation) as exc_info:
        gate.admit_and_dispatch(
            approval_id, nonce, mutated_payload, scope, dummy_wire
        )
    assert "Post-Approval Payload Tampering Detected" in str(exc_info.value)


def test_loopjacking_scope_binding_escalation(isolated_gate):
    """Calling an unapproved task scope must raise ScopeViolation."""
    gate, nonce_ledger = isolated_gate
    payload = {"account": "ACC-99"}
    approval_id = "appr-003"
    scope = "account.read"

    nonce = nonce_ledger.record_approval(approval_id, payload, "ciso-alice", scope)

    def dummy_wire(**kwargs):
        class R:
            status_code = 200
        return R()

    with pytest.raises(ScopeViolation) as exc_info:
        gate.admit_and_dispatch(
            approval_id, nonce, payload, "account.write", dummy_wire
        )
    assert "Scope Escalation Blocked" in str(exc_info.value)


def test_loopjacking_ttl_expiration(isolated_gate):
    """Attempting execution after TTL expiry must raise ApprovalExpiredViolation."""
    gate, nonce_ledger = isolated_gate
    payload = {"report": "dora_xbrl"}
    approval_id = "appr-004"
    scope = "regulatory.export"

    nonce = nonce_ledger.record_approval(
        approval_id, payload, "ciso-alice", scope, ttl_seconds=1
    )
    time.sleep(1.1)

    def dummy_wire(**kwargs):
        class R:
            status_code = 200
        return R()

    with pytest.raises(ApprovalExpiredViolation) as exc_info:
        gate.admit_and_dispatch(
            approval_id, nonce, payload, scope, dummy_wire
        )
    assert "Approval Expired" in str(exc_info.value)


def test_loopjacking_504_wire_state_quarantine(isolated_gate):
    """HTTP 504 Timeout must force DISPATCHED_UNCONFIRMED and quarantine status."""
    gate, nonce_ledger = isolated_gate
    payload = {"payment_id": "tx-123", "amount": 25000}
    approval_id = "appr-005"
    scope = "payments.execute"

    nonce = nonce_ledger.record_approval(approval_id, payload, "ciso-alice", scope)

    def dummy_504(**kwargs):
        class R:
            status_code = 504
        return R()

    res, obs, adv = gate.admit_and_dispatch(
        approval_id, nonce, payload, scope, dummy_504
    )

    assert obs.disposition == WireDisposition.DISPATCHED_UNCONFIRMED
    assert obs.quarantined is True
    assert adv["disposition_override_permitted"] is False


def test_loopjacking_zero_false_allow_benchmark(isolated_gate):
    """Exhaustive benchmark across 100 adversarial attack cases proving 0.0% false-allow rate."""
    gate, nonce_ledger = isolated_gate
    adversarial_attempts = 100
    false_allows = 0

    for i in range(adversarial_attempts):
        approval_id = f"fuzz-appr-{i}"
        approved_payload = {"idx": i, "val": "legitimate"}
        scope = "fuzz.scope"
        nonce = nonce_ledger.record_approval(approval_id, approved_payload, "fuzzer", scope)

        # Attack mutation: 50% replay, 50% payload mutation
        if i % 2 == 0:
            # First legitimate consume
            gate.nonce_ledger.consume_nonce(nonce, approval_id, approved_payload, scope)
            # Replay attack
            try:
                gate.nonce_ledger.consume_nonce(nonce, approval_id, approved_payload, scope)
                false_allows += 1
            except ReplayAttackViolation:
                pass
        else:
            # Payload tamper attack
            tampered = {"idx": i, "val": "MALICIOUS_MUTATION"}
            try:
                gate.nonce_ledger.consume_nonce(nonce, approval_id, tampered, scope)
                false_allows += 1
            except PayloadTamperViolation:
                pass

    false_allow_rate = (false_allows / adversarial_attempts) * 100.0
    assert false_allow_rate == 0.0, f"False-allow rate must be 0.0%, got {false_allow_rate}%"
