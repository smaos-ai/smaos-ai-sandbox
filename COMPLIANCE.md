# SMAOS Regulatory Compliance Mapping

This document maps the SMAOS architecture to key European regulatory requirements.

## 1. EU AI Act (Art. 12 & 14)

### Article 12: Record-Keeping
**Requirement**: High-risk AI systems must automatically record events (logs) while operating.
**SMAOS Implementation**: 
- **Receipt Chain**: All authorization and execution events generate an immutable, IETF SCITT `COSE_Sign1` Merkle audit receipt.
- **SQLite Nonce Ledger**: Atomic ledger records cryptographic digests of human intent, task scope, and exact timestamps prior to socket dispatch.

### Article 14: Human Oversight
**Requirement**: High-risk AI systems must be designed in a way that they can be effectively overseen by natural persons.
**SMAOS Implementation**:
- **Execution Boundary**: AI agents operate in an advisory capacity up to the `smaos_gate`. Dispatch across the wire requires explicit human cryptographic authorization matching the exact canonical payload.
- **Loopjacking Defense**: `verify_approved_matches_resolved` ensures that post-approval modifications by autonomous loops fail immediately at the socket level.

## 2. Digital Operational Resilience Act (DORA)

### Article 17: Management of ICT Third-Party Risk
**Requirement**: Financial entities must ensure ICT third-party risk is managed as an integral part of ICT risk management.
**SMAOS Implementation**:
- **xBRL-CSV DORA Compiler**: SMAOS automatically tracks and compiles dependencies and sub-contractor details into the required 15-template Register of Information (ITS 2024/2956) format for regulatory submission.
- **Dependency Admission Standard**: A strict 4-stage supply chain verification pipeline evaluates all external dependencies (existence, integrity, API verification, utility) before admitting them into the Trusted Computing Base (TCB).

## 3. Strict Non-Authoritativeness of Advisory Models

In accordance with safety-critical operational standards, diagnostic and SLM models (e.g., `gliner2`) are formally restricted to the **Advisory Enrichment Plane**.
If the **Deterministic Transport Observer** records an ambiguous wire state (e.g., `HTTP 504`), the record is permanently locked as `DISPATCHED_UNCONFIRMED`. Model heuristics cannot upgrade unconfirmed states to `REMOTE_CONFIRMED`.
