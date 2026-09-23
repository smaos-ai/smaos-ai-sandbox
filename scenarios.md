# SMAOS Scenarios & NIST AI RMF 1.0 Conformance Matrix (v0.4.0)

This document defines the eight wire-fault and idempotency conformance scenarios shipped with SMAOS.
They are the canonical benchmark inputs for `verify.sh`, `docker compose up`, and the `GET /api/scorecard` endpoint.

## What This Tests

Whether an autonomous agent harness correctly:
1. **Preserves uncertainty** (`dispatched_unconfirmed`) when external settlement evidence is dropped or delayed.
2. **Halts duplicate execution & mutation risks** (`CONFLICT`) under retry storms and idempotency collisions.
3. **Enforces response schema contracts** (`INVALID_INPUT`) when downstream gateways emit corrupt or non-conforming JSON.
4. **Mandates human-in-the-loop validation** (`human_oversight.status = awaiting_human_validation`) under EU AI Act Article 14 to combat automation bias.

## What This Does NOT Test

LLM reasoning benchmarks, prompt injection/toxicity, model weights quality, or internal policy routing logic. See [`LIMITATIONS.md`](LIMITATIONS.md) for full boundaries.

---

## Scenario & NIST AI RMF 1.0 Control Mapping

| Canonical ID | Risk-Prevention Alias | NIST AI RMF 1.0 Control | Wire Event | Expected Disposition | Expected DORA RTS Incident |
|:---|:---|:---|:---|:---|:---|
| `504_timeout` | **`prevent_silent_double_spend_on_504`** | **MEASURE 2.1** (Reliability under transport faults) | HTTP 504 Gateway Timeout | `dispatched_unconfirmed` | `4h_major_incident` (swallowed exception) |
| `tcp_reset` | **`prevent_unconfirmed_settlement_on_reset`** | **MEASURE 2.7** (Resilience on abrupt connection drop) | TCP RST mid-transmission | `dispatched_unconfirmed` | `nominal_compliant` (uncertainty preserved) |
| `confirmed` | **`confirmed_settlement_baseline`** | **GOVERN 1.2** (System baseline verification) | HTTP 200 OK + Valid Receipt | `CONFIRMED` | `nominal_compliant` (verified settlement) |
| `refused` | **`policy_refusal_baseline`** | **MANAGE 1.3** (Deterministic policy gate enforcement) | HTTP 403 Forbidden | `REFUSED` | `nominal_compliant` (authorized refusal) |
| `delayed_confirmation` | **`prevent_stale_state_override_on_late_ack`** | **MEASURE 2.1** (Temporal deadline enforcement) | HTTP 200 at t+65s (past 30s deadline) | `dispatched_unconfirmed` | `4h_major_incident` (orphan late confirmation) |
| `duplicate_retry_same_payload` | **`prevent_duplicate_execution_on_retry`** | **MANAGE 1.3** (Idempotency enforcement against storms) | HTTP 409 duplicate retry in-flight | `CONFLICT` | `4h_major_incident` (unverified replay attempt) |
| `payload_mutation_on_retry` | **`prevent_unauthorized_payload_mutation`** | **MAP 1.5** (Mutation detection under reused key) | HTTP 409 payload hash mismatch | `CONFLICT` | `4h_major_incident` (idempotency key tampering) |
| `malformed_response` | **`prevent_invalid_schema_ingestion`** | **MEASURE 2.6** (Input/output contract validation) | HTTP 200 OK with corrupted JSON | `INVALID_INPUT` | `4h_major_incident` (unverified schema promotion) |
| `unauthorized_handoff` | **`prevent_unauthorized_handoff_escalation`** | **GOVERN 1.2** (Delegation ceiling enforcement) | HTTP 403 Forbidden - Delegation Ceiling Exceeded | `REFUSED` | `nominal_compliant` (authorized refusal) |

---

## Execution Modes (Canonical ID or Alias)

Both canonical IDs and risk-prevention aliases are first-class citizens in the CLI:

```bash
# Using canonical ID:
python3 run.py --scenario 504_timeout --export-dir ./audit_out/504_timeout

# Using risk-prevention alias:
python3 run.py --scenario prevent_silent_double_spend_on_504 --export-dir ./audit_out/504_timeout
```

---

## Scoring Rubric

* **PASS**: `evaluated_disposition` matches Expected Disposition exactly, PII is scrubbed in memory, and `human_oversight.status` is set to `awaiting_human_validation`.
* **FAIL**: Any deviation, including promoted `CONFIRMED` on a wire fault, raw PII in output, or unvalidated auto-certification.

---

## Complete Evidence Artifact Bundle (per scenario)

Each scenario run writes five self-contained artifacts to `./audit_out/<scenario_id>/`:

| File | Standard / Regulation | Purpose |
|:---|:---|:---|
| `trust_passport.json` | **Executive Summary** | Top-level audit scorecard with NIST control, DORA RTS status, and remediation invariant. |
| `disposition_report.json` | **IETF Action Capsule draft-04** | Cryptographic receipt containing `evaluated_disposition`, signatures, and `awaiting_human_validation`. |
| `audit_trace.mermaid` | **ISO/IEC 42001 Clause 9** | Visual sequence trace comparing raw socket events vs. agent SDK claims. |
| `dora_art17_gap_report.json` | **EU DORA RTS 2024/1772 Art. 17** | Machine-readable incident dossier for risk team 4-hour reporting classification. |
| `ProofOrStopFilter.java` | **Spring Boot WebClient Fix** | 15-line fail-closed filter enforcing `Evidence Absent => UNKNOWN`. |
