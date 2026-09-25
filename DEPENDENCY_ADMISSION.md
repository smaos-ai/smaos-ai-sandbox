# Sovereign Four-Stage Dependency Admission Standard (v1.1.0)

This standard establishes the verification and isolation pipeline for external dependencies, third-party libraries, and foundation models integrated into the SMAOS execution membrane.

---

## 1. The Four-Stage Admission Pipeline

Every dependency must pass all four stages before integration into production execution paths:

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│                    FOUR-STAGE DEPENDENCY ADMISSION PIPELINE                       │
├──────────────┬───────────────────────────────┬────────────────────────────────────┤
│ STAGE        │ VERIFICATION CRITERIA         │ GATE ENFORCEMENT                   │
├──────────────┼───────────────────────────────┼────────────────────────────────────┤
│ Stage 1      │ Package Existence & Provenance│ Verified PyPI / Crates.io metadata │
│              │                               │ Cryptographic maintainer keys      │
├──────────────┼───────────────────────────────┼────────────────────────────────────┤
│ Stage 2      │ Supply-Chain Integrity        │ Immutable SHA-256 hash lock        │
│              │                               │ Sigstore SLSA L3 provenance attest │
├──────────────┼───────────────────────────────┼────────────────────────────────────┤
│ Stage 3      │ API Verification & Sandbox    │ Offline AST & interface inspection │
│              │ Introspection                 │ Pure sandbox runtime verification  │
├──────────────┼───────────────────────────────┼────────────────────────────────────┤
│ Stage 4      │ Utility & Security Evaluation │ Strict sandboxing (Advisory Plane) │
│              │                               │ 0-byte airgap network verification │
└──────────────┴───────────────────────────────┴────────────────────────────────────┘
```

### Stage 1: Package Existence & Provenance
- The package must possess an immutable, canonical namespace in the official upstream registry (PyPI, Crates.io).
- Releases must be verifiable against source repository tags with zero uncommitted upstream delta.

### Stage 2: Supply-Chain & Hash Integrity
- Binary packages and wheel distributions must have their SHA-256 hashes recorded in lockfiles (`checksums.sha256`, `requirements.txt` hashes, or `Cargo.lock`).
- Any checksum deviation triggers automated build halt.

### Stage 3: API Verification & Sandbox Introspection
- Documented interfaces must be verified directly against the installed package AST without reliance on third-party marketing claims.
- If an API signature or feature cannot be confirmed via offline introspection, the feature remains quarantined in an unadmitted state.

### Stage 4: Utility, Security & Airgap Evaluation
- External inference models (e.g. GLiNER2 via Fastino) are admitted strictly to the **Advisory Enrichment Plane**.
- **Architectural Invariant**: Model outputs enrich diagnostic metadata for human auditors but are cryptographically forbidden from modifying `WireDisposition` or upgrading `DISPATCHED_UNCONFIRMED` states to `CONFIRMED`.

---

## 2. Procurement Cleanliness & Unverified Vendor Scrub

To maintain institutional compliance and audit clarity:
- **No Unverified Vendor Claims**: References to speculative or unverified vendor frameworks are strictly quarantined from production specifications and commercial materials.
- **Protocol-Derived Wire Truth**: All operational claims must originate from measured socket bytes, HTTP status codes, and deterministic cryptographic signatures.
