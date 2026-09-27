# Agent Effect Integrity Benchmark (AEIB)

## 📌 Overview

The **Agent Effect Integrity Benchmark (AEIB)** is an empirical metrology suite designed to measure how autonomous agents and AI orchestration frameworks (e.g., LangChain, AutoGen, CrewAI) manage execution finality during localized network failures, timeouts, and state desynchronization.

As autonomous agents transition from read-only RAG tasks to write-heavy, high-consequence operational tasks (e.g., executing financial payments, deploying infrastructure, or altering IAM entitlements), standard evaluation metrics—such as prompt accuracy and instruction adherence—become insufficient. AEIB focuses exclusively on **Consequence Integrity**: the ability of an agent workflow to survive physical network ambiguity without causing duplicate, lost, or corrupted downstream effects.

## ⚠️ The Core Vulnerability: Post-Write Ambiguity

In distributed systems, a timeout (e.g., HTTP 504 Gateway Timeout or TCP RST) is an inherently ambiguous state. The caller cannot know whether the connection dropped *before* the remote server processed the request (a safe failure) or *after* the remote server processed the request (an unconfirmed success).

AEIB demonstrates that standard AI agent SDKs frequently misinterpret post-write timeouts as absolute failures. In response, these agents often trigger naive, automated retry loops. Critically, because Large Language Models are probabilistic generators, they frequently **regenerate fresh idempotency keys or UUIDs** on subsequent retries, bypassing server-side deduplication safeguards and resulting in silent double-execution.

## 🧪 The Benchmark Protocol

AEIB utilizes a local fault-injection proxy (`agent_chaos_proxy.py`) and a deterministic state-tracking target (`target_api.py`) to force agents into ambiguous failure states.

### Experiment 1: The Post-Write HTTP 504 Timeout

1. **Intent Declaration**: The agent framework is instructed to execute a €50,000 wire transfer.
2. **Dispatch & Fault Injection**: The agent dispatches the HTTP POST request. The AEIB target API processes the transaction successfully, commits it to the database, but intentionally drops the return packet, resulting in an `HTTP 504 Gateway Timeout` for the agent.
3. **Agent Reaction Measurement**: AEIB tracks whether the agent recognizes the ambiguity (`dispatched_unconfirmed`), queries the target for reconciliation, or naively retries the transaction.

### Empirical Baseline Results

| Metric | Client A (Naive Agent SDK) | Client B (SMAOS Regulated Boundary) |
| :--- | :--- | :--- |
| **Initial Response** | HTTP 504 Gateway Timeout | HTTP 504 Gateway Timeout |
| **Internal State Recorded** | `FAILED` / `NOT_SENT` | `DISPATCHED_UNCONFIRMED` |
| **Retry Behavior** | Unconstrained, automatic retry with new ID | **Blocked / Constrained** |
| **Target Reconciliation** | Skipped entirely | **Executed (`/reconcile`)** |
| **Final Database Commits** | **2 Commits (€100,000 total)** | **1 Commit (€50,000 total)** |
| **Financial Impact** | 🚨 **€50,000 Double-Spend** | ✅ **€0 Excess (€50,000 Exact)** |

## 📐 Standards Alignment (NIST & IETF)

AEIB provides an independent, reproducible testing harness designed to support emerging regulatory and standards frameworks, including:
* **NIST AI Agent Standards Initiative (Feb 2026)**: Defining auditability and non-repudiation constraints for autonomous execution.
* **Digital Operational Resilience Act (DORA)**: Supplying deterministic execution records to support Article 17 (ICT Incident Management) and Article 18 incident reconstruction.

## 🚀 Quick Start (Local Reproduction)

To run the benchmark locally and observe the idempotency failure firsthand:

```bash
# 1. Start the AEIB Fault-Injection Target API (Port 8765)
python3 aeib_experiment/target_api.py

# 2. Run the Naive Agent Test
python3 aeib_experiment/run_naive_agent.py

# 3. View the Resulting State Corruption
cat aeib_experiment/target_db.json
```

---

*The AEIB framework is an open-source testing methodology and does not certify or guarantee compliance with any regulatory standard. It is provided for research, testing, and system measurement purposes only.*
