# AEIB & SMAOS: Research Briefing
**Prepared for:** Oleg / Lviv Polytechnic National University (AI Department)
**Focus:** Execution Finality and Post-Write Ambiguity in Non-Deterministic Agentic Workflows

---

## 1. The Core Academic Thesis
Current research in Artificial Intelligence heavily indexes on model capability, prompt engineering, and probabilistic evaluation (e.g., achieving 95% accuracy on reasoning benchmarks). However, when autonomous agents are given **write-access** to high-consequence environments (payments, infrastructure, ERP), probabilistic correctness is fundamentally insufficient. 

In distributed systems, a network timeout (like an `HTTP 504 Gateway Timeout`) creates an ambiguous state (the *Two Generals' Problem*). Our research proves that because Large Language Models are non-deterministic, standard Agent SDKs fail gracefully under network partitions. Instead of reconciling state, they frequently hallucinate fresh idempotency keys and re-dispatch requests—causing catastrophic, silent double-execution.

## 2. The Agent Effect Integrity Benchmark (AEIB)
To move this problem from theoretical debate to empirical measurement, we built **AEIB**. AEIB is an open-source, reproducible fault-injection harness that tests how AI orchestration frameworks (LangChain, AutoGen, CrewAI) manage execution finality during localized network failures.

**The Local Reproduction Experiment:**
We use a local `agent_chaos_proxy.py` to inject a post-write 504 timeout. 
* **Naive SDKs**: Automatically retry, generating a new UUID -> **Double-Execution**.
* **SMAOS Boundary**: Traps the 504, records `DISPATCHED_UNCONFIRMED`, blocks autonomous retries, and forces a target reconciliation.

## 3. The SovereignNexus (SMAOS) Architecture
SMAOS acts as the deterministic "Layer 5" enforcement boundary for non-deterministic agents.
* **O(1) Cryptographic Accumulator**: Compresses the entire session's execution state into a single 256-byte Merkle-linked state root.
* **Decoupled State Vocabulary**: Replaces boolean `success/fail` with a 6-outcome taxonomy (`not_dispatched`, `dispatched_unconfirmed`, `remote_confirmed`, etc.).
* **Zero-Trust Guard**: Enforces strict execution bounds at the network socket layer, completely decoupled from the LLM's internal reasoning.

## 4. Potential Areas for Academic Collaboration
We see strong alignment between this project and Lviv Polytechnic's engineering and AI research strengths. We are opening the benchmark for academic critique and extension:

1. **Formal Verification of Agent SDKs**: Using the AEIB harness to systematically test and publish vulnerability disclosures for popular open-source agent frameworks.
2. **eBPF Network-Level Enforcement**: Moving the SMAOS isolation boundary from user-space down into the Linux kernel using XDP/TC to prevent unauthorized agent egress natively.
3. **Cryptographic State Proofs**: Expanding the $O(1)$ accumulator to support Zero-Knowledge Proofs (ZKPs) for privacy-preserving audit logs in regulated financial environments.

---
**Next Steps:** We invite your team to review the empirical data in the `AEIB_SPECIFICATION.md`, run the local fault-injection harness, and discuss potential avenues for academic publication and joint research.
