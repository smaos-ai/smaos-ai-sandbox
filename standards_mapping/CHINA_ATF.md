# Agent Trust Fabric (ATF) v1.0 Mapping

Issued by CAC/NDRC/MIIT (May 2026). Our 6-disposition taxonomy directly supports ATF's 6 dimensions:
1. 身份可信 (Identity Trust) → Bound to WIMSE/SPIFFE `spiffe_id`
2. 意图对齐 (Intent Alignment) → Verified via `chat_template_digest`
3. 生成有界 (Bounded Generation) → Enforced by `POLICY_GATE_REJECT` disposition
4. 行为可控 (Controllable Behavior) → Enforced by `ProofOrStopFilter.java` circuit breaker
5. 链路可审 (Auditable Chain) → Ed25519 Merkle DAG receipts
6. 责权可溯 (Traceable Accountability) → `human_oversight` field in receipt
