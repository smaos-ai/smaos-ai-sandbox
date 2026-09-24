"""
Unit Tests for Jev-Style Typed Router and Copy-on-Write (COW) State Subgraph Sandbox.
Verifies:
  1. Sub-millisecond 5-typed decisions (zero token cost)
  2. AST constraint admissibility and ISO 17442 LEI verification
  3. Wire-truth completion state transitions (504/TCP RST downgrade)
  4. Memory triage 64MB heap ceiling enforcement
  5. Copy-on-Write state isolation preventing episodic memory contamination
  6. Authentic RFC 8032 Ed25519 COSE_Sign1 verification gate
"""

import time
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.jev_typed_router import JevTypedRouter, ModelTier, CompletionState, TriageDecision
from src.cow_subgraph_sandbox import (
    COWStateGraph,
    COWBranch,
    COWBranchStatus,
    create_verified_cose_receipt,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Jev-Style Typed Router Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_jev_router_decision_1_tool_selection():
    router = JevTypedRouter()
    
    # Exact match
    tools_transfer = router.select_files_and_tools("ledger.transfer")
    assert "ledger_db" in tools_transfer
    assert "ebpf_xdp" in tools_transfer
    
    # Wire settlement
    tools_settle = router.select_files_and_tools("settle.wire")
    assert "wire_observer" in tools_settle
    assert "scitt_signer" in tools_settle

    # Fallback to minimal safe observer
    tools_unknown = router.select_files_and_tools("unregistered.custom_action")
    assert tools_unknown == ["wire_observer"]


def test_jev_router_decision_2_model_tier():
    router = JevTypedRouter(ceiling_eur=50000.0)
    
    # Standard transaction under ceiling -> Local SLM 4B
    tier, reason = router.select_model_tier({"amount": 1500.0, "action": "ledger.transfer"})
    assert tier == ModelTier.LOCAL_SLM_4B

    # Complex dispute/reconciliation -> Intermediate 70B
    tier, reason = router.select_model_tier({"amount": 1500.0, "action": "dispute.chargeback"})
    assert tier == ModelTier.INTERMEDIATE_70B

    # Breach of Tier-1 financial ceiling -> Frontier 405B
    tier, reason = router.select_model_tier({"amount": 75000.0, "action": "ledger.transfer"})
    assert tier == ModelTier.FRONTIER_REASONING_405B
    assert "breaches Tier-1 autonomy ceiling" in reason

    # Unstructured ambiguity or legal interpretation -> Frontier 405B
    tier, reason = router.select_model_tier({"amount": 100.0, "requires_legal_interpretation": True})
    assert tier == ModelTier.FRONTIER_REASONING_405B


def test_jev_router_decision_3_admissibility_and_ast_gate():
    router = JevTypedRouter(ceiling_eur=50000.0)

    # Valid nominal transfer
    verdict, reason = router.evaluate_admissibility("ledger.transfer", {"amount": 2500.0})
    assert verdict == "ALLOW"

    # Prohibited action pattern
    verdict, reason = router.evaluate_admissibility("exfiltrate_keys", {"amount": 0.0})
    assert verdict == "BLOCK"
    assert "prohibited command pattern" in reason

    # Financial ceiling escalation (EU AI Act Art. 14 Human Oversight)
    verdict, reason = router.evaluate_admissibility("ledger.transfer", {"amount": 120000.0})
    assert verdict == "ESCALATE"
    assert "Art. 14 Human Oversight" in reason

    # ISO 17442 LEI validation
    # Valid LEI (Bloomberg Finance LP: 5493001KJTIIGC8Y1R12)
    verdict, _ = router.evaluate_admissibility("settle.wire", {"amount": 100.0, "lei": "5493001KJTIIGC8Y1R12"})
    assert verdict == "ALLOW"

    # Invalid LEI checksum
    verdict, reason = router.evaluate_admissibility("settle.wire", {"amount": 100.0, "lei": "5493001KJTIIGC8Y1R99"})
    assert verdict == "BLOCK"
    assert "Invalid ISO 17442 LEI" in reason


def test_jev_router_decision_4_completion_state_machine():
    router = JevTypedRouter(default_ttl_ms=2000.0)

    # Nominal 200 OK within SLA -> CONFIRMED
    state, _ = router.evaluate_completion(200, {"status": "SUCCESS"}, elapsed_ms=120.0)
    assert state == CompletionState.SATISFIED_CONFIRMED

    # Wire failure: HTTP 504 Gateway Timeout -> DOWNGRADE_UNCONFIRMED
    state, reason = router.evaluate_completion(504, None, elapsed_ms=2005.0)
    assert state == CompletionState.DOWNGRADE_UNCONFIRMED
    assert "504" in reason

    # Wire failure: TCP RST (-1) -> DOWNGRADE_UNCONFIRMED
    state, _ = router.evaluate_completion(-1, None, elapsed_ms=45.0)
    assert state == CompletionState.DOWNGRADE_UNCONFIRMED

    # Late ACK past TTL deadline -> DOWNGRADE_UNCONFIRMED
    state, reason = router.evaluate_completion(200, {"status": "SUCCESS"}, elapsed_ms=2500.0, ttl_ms=2000.0)
    assert state == CompletionState.DOWNGRADE_UNCONFIRMED
    assert "stale override prevented" in reason

    # Downstream policy refusal -> POLICY_REFUSED
    state, _ = router.evaluate_completion(403, {"error": "FORBIDDEN"}, elapsed_ms=50.0)
    assert state == CompletionState.POLICY_REFUSED

    # Malformed response -> TERMINAL_INVALID
    state, _ = router.evaluate_completion(200, None, elapsed_ms=50.0)
    assert state == CompletionState.TERMINAL_INVALID

    # Idempotency conflict -> TERMINAL_CONFLICT
    state, _ = router.evaluate_completion(200, {"status": "CONFLICT"}, elapsed_ms=50.0)
    assert state == CompletionState.TERMINAL_CONFLICT


def test_jev_router_decision_5_memory_triage_heap_ceiling():
    router = JevTypedRouter()

    # Nominal heap usage (<85% of 64MB)
    decision, _ = router.evaluate_triage({"type": "state_update"}, current_heap_mb=20.0, heap_ceiling_mb=64.0)
    assert decision == TriageDecision.RETAIN_L1_MEMORY

    # Redundant transient logging -> Pruned
    decision, _ = router.evaluate_triage({"type": "debug_log"}, current_heap_mb=20.0)
    assert decision == TriageDecision.PRUNE_REDUNDANT

    # Heap pressure exceeding 85% (>54.4 MB) -> Spill to disk
    decision, reason = router.evaluate_triage({"type": "important_event"}, current_heap_mb=56.0, heap_ceiling_mb=64.0)
    assert decision == TriageDecision.SPILL_MERKLE_DAG_LEAF
    assert "exceeds 85% of 64.0 MB ceiling" in reason


def test_jev_router_sub_millisecond_execution_budget():
    router = JevTypedRouter()
    iterations = 200
    t0 = time.perf_counter()
    for _ in range(iterations):
        router.select_files_and_tools("ledger.transfer")
        router.select_model_tier({"amount": 1000.0, "action": "ledger.transfer"})
        router.evaluate_admissibility("ledger.transfer", {"amount": 1000.0})
        router.evaluate_completion(200, {"status": "SUCCESS"}, elapsed_ms=10.0)
        router.evaluate_triage({"type": "event"}, current_heap_mb=10.0)
    t1 = time.perf_counter()
    avg_ms = ((t1 - t0) * 1000.0) / iterations
    # Must average well under 0.1 ms per loop
    assert avg_ms < 0.1, f"Expected <0.1ms average, got {avg_ms:.4f}ms"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Copy-on-Write (COW) State Subgraph Sandbox Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_cow_sandbox_isolation_and_no_leakage():
    initial_nodes = {
        "acc_treasury": {"balance": 1_000_000, "currency": "EUR"},
        "acc_vendor": {"balance": 50_000, "currency": "EUR"}
    }
    graph = COWStateGraph(initial_nodes)
    parent_merkle_before = graph.merkle_root()

    # Fork isolated branch
    branch = graph.fork(branch_id="tx-probe-001", agent_id="agent-worker-1")
    assert branch.status == COWBranchStatus.ACTIVE
    assert branch.base_snapshot_hash == parent_merkle_before

    # Read fallthrough from parent
    assert branch.get_node("acc_treasury")["balance"] == 1_000_000

    # Mutate speculative state inside COW branch
    branch.set_node("acc_treasury", {"balance": 900_000, "currency": "EUR"})
    branch.set_node("acc_vendor", {"balance": 150_000, "currency": "EUR"})

    # Branch sees mutation
    assert branch.get_node("acc_treasury")["balance"] == 900_000
    assert branch.get_node("acc_vendor")["balance"] == 150_000

    # CRITICAL INVARIANT: Parent state graph is 100% UNTOUCHED
    assert graph.get_node("acc_treasury")["balance"] == 1_000_000
    assert graph.get_node("acc_vendor")["balance"] == 50_000
    assert graph.merkle_root() == parent_merkle_before


def test_cow_sandbox_discard_on_transport_failure():
    initial_nodes = {
        "acc_escrow": {"balance": 500_000, "currency": "EUR"}
    }
    graph = COWStateGraph(initial_nodes)
    base_merkle = graph.merkle_root()

    branch = graph.fork(branch_id="tx-fail-504")

    # Speculatively deduct funds inside closure
    def risky_operation(b):
        b.set_node("acc_escrow", {"balance": 0, "currency": "EUR"})
        # Simulate transport failure (HTTP 504 / connection timeout)
        raise TimeoutError("504 Gateway Timeout on downstream settlement gateway")

    ok, res, err = graph.execute_isolated(branch, risky_operation)
    assert not ok
    assert "504 Gateway Timeout" in err

    # Explicit discard of failed branch
    graph.discard_branch(branch, reason="Transport fault HTTP 504")
    assert branch.status == COWBranchStatus.DISCARDED
    assert branch.discard_reason == "Transport fault HTTP 504"

    # Parent state is pristine: zero episodic memory contamination
    assert graph.get_node("acc_escrow")["balance"] == 500_000
    assert graph.merkle_root() == base_merkle


def test_cow_sandbox_merge_with_verified_scitt_receipt():
    initial_nodes = {
        "acc_client": {"balance": 250_000, "currency": "EUR"},
        "acc_clearing": {"balance": 10_000, "currency": "EUR"}
    }
    graph = COWStateGraph(initial_nodes)

    branch = graph.fork(branch_id="settle-001")
    branch.set_node("acc_client", {"balance": 200_000, "currency": "EUR"})
    branch.set_node("acc_clearing", {"balance": 60_000, "currency": "EUR"})
    branch.add_edge("acc_client", "acc_clearing", "WIRE_TRANSFER", {"amount": 50_000})

    delta_hash = branch.compute_delta_hash()

    # Generate authentic RFC 8032 Ed25519 signed COSE_Sign1 receipt
    notary_key = ed25519.Ed25519PrivateKey.generate()
    receipt_payload = {
        "disposition": "CONFIRMED",
        "branch_id": branch.branch_id,
        "delta_hash": delta_hash,
        "notarized_at": time.time(),
        "audit_authority": "did:smaos:eu-czechinvest-sandbox"
    }
    receipt, pub_key = create_verified_cose_receipt(receipt_payload, private_key=notary_key)

    # Merge into main graph
    merged, msg = graph.merge_if_verified(branch, receipt, notary_public_key=pub_key)
    assert merged is True
    assert "verified and merged" in msg
    assert branch.status == COWBranchStatus.MERGED

    # Parent state graph now reflects merged state
    assert graph.get_node("acc_client")["balance"] == 200_000
    assert graph.get_node("acc_clearing")["balance"] == 60_000
    assert len(graph.edges) == 1
    assert len(graph.commit_history) == 1
    assert graph.commit_history[0]["delta_hash"] == delta_hash


def test_cow_sandbox_rejects_unconfirmed_or_toxic_receipt():
    initial_nodes = {"node_a": {"v": 1}}
    graph = COWStateGraph(initial_nodes)
    base_merkle = graph.merkle_root()

    branch = graph.fork(branch_id="tx-toxic")
    branch.set_node("node_a", {"v": 999})

    delta_hash = branch.compute_delta_hash()
    notary_key = ed25519.Ed25519PrivateKey.generate()

    # Toxic receipt: disposition is DOWNGRADE_UNCONFIRMED due to late ACK/504
    receipt_payload = {
        "disposition": "DOWNGRADE_UNCONFIRMED",
        "delta_hash": delta_hash
    }
    receipt, pub_key = create_verified_cose_receipt(receipt_payload, private_key=notary_key)

    merged, msg = graph.merge_if_verified(branch, receipt, notary_public_key=pub_key)
    assert merged is False
    assert "is not CONFIRMED" in msg
    assert branch.status == COWBranchStatus.DISCARDED

    # Main graph preserved unchanged
    assert graph.get_node("node_a")["v"] == 1
    assert graph.merkle_root() == base_merkle


def test_cow_sandbox_rejects_forged_cryptographic_signature():
    initial_nodes = {"node_a": {"v": 10}}
    graph = COWStateGraph(initial_nodes)

    branch = graph.fork(branch_id="tx-forgery")
    branch.set_node("node_a", {"v": 42})

    delta_hash = branch.compute_delta_hash()
    legit_key = ed25519.Ed25519PrivateKey.generate()
    attacker_key = ed25519.Ed25519PrivateKey.generate()

    # Attacker signs with attacker_key, but verification expects legit_key
    receipt_payload = {
        "disposition": "CONFIRMED",
        "delta_hash": delta_hash
    }
    forged_receipt, _ = create_verified_cose_receipt(receipt_payload, private_key=attacker_key)

    merged, msg = graph.merge_if_verified(branch, forged_receipt, notary_public_key=legit_key.public_key())
    assert merged is False
    assert "Cryptographic verification failed" in msg
    assert branch.status == COWBranchStatus.DISCARDED
    assert graph.get_node("node_a")["v"] == 10
