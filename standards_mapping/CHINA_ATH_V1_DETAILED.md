# ATH 1.0 (Agent Trust Handshake) Clause-by-Clause Mapping

**Specification:** CAICT Agent Trust Handshake Protocol 1.0 (AtomGit/GitHub, May 2026)
**Core Principle:** 3-Party Attestation (User, Agent, Service)

## Phase 1: Identity & Intent Alignment
**ATH Requirement:** "Who is the agent? Whom does it represent?"
**SMAOS Implementation:** We bind the runtime execution to IETF WIMSE/SPIFFE identities (`spiffe_id`).
**Moat Check:** Passed. The agent cannot spoof its identity payload in the execution trace.

## Phase 2: Bounded Generation & Control
**ATH Requirement:** "What is it authorized to do?" (Generation boundaries)
**SMAOS Implementation:** The `REFUSED` (Policy Gate Reject) disposition proves the agent correctly recognized and logged an authorization failure, satisfying the ATH behavior boundary constraint.

## Phase 3: Auditable Chain & Accountability
**ATH Requirement:** "Is the process traceable?"
**SMAOS Implementation:**
Our exact error taxonomy satisfies ATH failure state reporting:
| SMAOS State | ATH 1.0 Phase Failure | Consequence |
| :--- | :--- | :--- |
| `dispatched_unconfirmed` | `service_handshake_missing` | Fails Step 6 (Service Attestation). Proof that wire dropped. |
| `CONFLICT` | `dual_handshake_hash_mismatch` | Fails Step 8 (Hash Verification). |
| `CONFIRMED` | `handshake_complete` | Valid 3-party attestation sequence. |

*This mapping serves as the institutional bridge between EU DORA (incident evidence) and Asian ATH (agent trust parameters).*
