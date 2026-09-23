# SMAOS Compliance Deployment Checklist

This checklist aligns SMAOS deployment with **EU AI Act Article 14 (Human Oversight)** and **DORA RTS 2024/1772 (ICT Risk)** requirements, drawing from RaaSify and ARIA OMEGA patterns.

## 1. EU AI Act Article 14 (Human Oversight)

Article 14 requires that high-risk AI systems (including financial autonomous agents) are subject to effective human oversight to prevent automation bias.

- [ ] **Default State:** Ensure `human_oversight.status` defaults to `awaiting_human_validation` for all mutating transactions.
- [ ] **Audit Trail:** Maintain immutable logs of which human reviewed which Trust Passport.
- [ ] **Rejected Paths Logging:** Ensure `rejected_paths` array is populated so reviewers can see *what the agent considered but did not do*.
- [ ] **Suspension Capability:** Ensure a "Stop Button" exists that can halt agent execution immediately without corrupting ledger state.

## 2. EBA DORA RTS 2024/1772 Article 17 (ICT Incidents)

DORA requires stringent reporting for major ICT-related incidents, particularly those affecting financial ledgers.

- [ ] **Incident Detection:** Ensure `dora_rts_classification` is accurately toggled to `4h_major_incident` when a discrepancy is detected (e.g., 504 timeout swallowed).
- [ ] **Automated Reporting:** Connect `dora_art17_gap_report.json` outputs to the enterprise risk management (ERM) system.
- [ ] **Zero-Egress Sanitization:** Ensure `TraceScrubber` (PII/PCI-DSS redaction) is active so incident reports can be shared safely.

## 3. NIST AI RMF 1.0

- [ ] **GOVERN 1.2:** Whole-system boundary assertions are verified before deployment.
- [ ] **MEASURE 2.1:** Transport faults are reliably converted to `dispatched_unconfirmed`.
- [ ] **MANAGE 1.3:** Idempotency and policy gates are strictly enforced.

## 4. Multi-Agent Delegation (Ceiling Enforcement)

- [ ] **Identity:** Every agent action includes an immutable `actor` ID.
- [ ] **Delegation:** `on_behalf_of` clearly tracks the origin of the request.
- [ ] **Authority:** Actions exceeding the established `permitted` scope are rejected (`prevent_unauthorized_handoff_escalation`).
