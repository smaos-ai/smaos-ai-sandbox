# SMAOS System Boundary & Succession Proofs (v0.4.0)

To guarantee execution integrity, SMAOS enforces a strict governed succession method across four whole-system boundaries. Passing an examination does not manufacture greater authority; evidence proves what it proves and stops there.

## 1. Boundary Examination Matrix

| Boundary | State Transition | Evaluation Criteria | Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **Boundary 1** | Network Transport ➔ Agent SDK | Does internal agent state match physical socket state? | Loopback socket interception (`127.0.0.1`); overrides false `CONFIRMED` claims on HTTP 504 / TCP RST. |
| **Boundary 2** | Agent A ➔ Agent B (Handoff) | Does delegation scope survive inter-agent handoff without privilege escalation? | Validates predecessor `prior_state_hash` & authority ceiling before allowing Agent B execution. |
| **Boundary 3** | Context ➔ Pipeline | Does the agent possess unexpired session mandates & active authority? | Pre-dispatch admissibility check validating mandate TTL & authority freshness. |
| **Boundary 4** | Outcome ➔ Audit Witness | Is telemetry cryptographically immutable and offline-verifiable? | Ed25519 & ML-DSA-65 signed receipts canonicalized via RFC 8785 JCS + Merkle DAG inclusion. |

## 2. Negative State Assertions (Falsifier Engine)
Every verification cycle actively asserts the following negative boolean state constraints:
- `privilege_escalation_detected`: **false** (Successor payloads inherited strictly equal or narrower scopes).
- `authority_created`: **false** (Verification did not expand baseline permissions).
- `external_execution_unauthorized`: **false** (Zero uninspected packets breached local loopback).
- `freeze_authorized`: **false** (No silent freezing of state occurred).
