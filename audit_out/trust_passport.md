# Trust Passport (SMAOS Audit)
- **Audit ID:** urn:uuid:passport-504_timeout-2026
- **Scenario:** 504_timeout (prevent_silent_double_spend_on_504)
- **Engine Version:** v0.4.0-wire-truth

## Identity & Delegation
- **Actor:** Agent-LangChain-Treasury
- **On Behalf Of:** urn:smaos:delegator:system
- **Authority Ceiling Enforced:** True

## Authority
- **Permitted Operations:** POST /v1/settle, GET /v1/status, payments.execute
- **Rejected Paths:** 2

## Negative State Assertions
- authority_created = false
- delegation_ceiling_breached = false
- unverified_state_promoted = false

## Evidence Integrity
- **NIST AI RMF 1.0 Control:** MEASURE 2.1 (System reliability under transport fault)
- **EU AI Act Art. 14 Oversight:** awaiting_human_validation
- **DORA Classification:** 4h_major_incident

## Limitations
- Covers wire-fault effect integrity only.
- Does not measure model quality or content safety.
- Not a compliance certification.
