# 🏛️ Regulatory Sandbox Cover Letter

**To:** Czech Agency for Standardisation (ČAS) / CzechInvest Fintech Sandbox Selection Committee  
**Copied For Awareness:** Czech National Bank (ČNB — Bank Supervision), ÚOOÚ (Office for Personal Data Protection)  
**Subject:** Submission of the Cryptographic Agent Supervision & Verification Framework (DORA Art. 17 & EU AI Act Art. 12/14)  
**Date:** 24 September 2026  
**Applicant:** SovereignNexus s.r.o. (Prague, Czech Republic)  
**Project:** SMAOS (Sovereign Multi-Agent Operating System) v1.1.0  

---

To the Sandbox Selection Committee and Supervisory Representatives,

We submit the **Sovereign Multi-Agent Operating System (SMAOS) Cryptographic Verification Framework**—an air-gapped, zero-egress execution membrane designed to enable the ČNB and ÚOOÚ to safely supervise autonomous AI agents operating in regulated financial workflows.

Current market implementations force supervisors and financial entities into an operational paradox: immutable logging required under DORA Article 17 and EU AI Act Article 12 forces customer PII (e.g., IBANs, transaction amounts) into immutable databases, directly violating GDPR Article 17 (Right to Erasure). Furthermore, client-side agent SDKs swallow network timeouts (`HTTP 504`), falsely logging `CONFIRMED` and causing silent ledger drift and reconciliation failure.

SMAOS resolves this regulatory deadlock through a 100% offline, zero-cloud-egress runtime:
1. **Pre-Execution Behavioral Admissibility (EU AI Act Art. 14)**: Evaluates tool calls in hardcoded C/eBPF kernel code before dispatch, enforcing deterministic ALLOW / ASK / DENY gates and human co-signatures.
2. **Wire-Truth Socket Physics (DORA Art. 17)**: Intercepts transport-level HTTP 504 timeouts and TCP RST drops at the network interface, overriding probabilistic model claims to prevent false transaction confirmations.
3. **W3C BBS+ Selective Disclosure (GDPR Art. 17 vs. AI Act Art. 12)**: Uses BLS12-381 vector signatures to cryptographically redact PII while preserving signature validity against IETF SCITT COSE_Sign1 transparency ledgers.
4. **Hardware-Attested Confidential VMs (Intel TDX & AMD SEV-SNP)**: Direct kernel ioctls binding raw 64-byte SHA-512 statement nonces into CPU hardware registers (`REPORTDATA`), generating authentic 1024-byte `TDREPORT_STRUCT` quotes.
5. **EBA DPM 4.0 / ITS 2024/2956 Register of Information**: Automated generation and ISO 17442 LEI check-digit verification of the complete 15-template package (`DORA_Register_DPM40_EBA_ITS_2024_2956.zip`).

We provide ČAS, ČNB, and ÚOOÚ supervisors with a standalone, zero-dependency WebAssembly verifier (`dist/verifier.html` wrapping `smaos_verify.wasm`) that runs inside any disconnected browser over `file://`. Supervisors can drag and drop redacted execution receipts to verify legal compliance and wire truth in milliseconds with zero bytes of data leaving the local machine.

We invite the committee to review the attached technical specifications and utilize our verification framework as the supervisory baseline for autonomous agent resilience testing.

Respectfully,

**Andrei Leukhin**  
Founder & Lead Architect, SMAOS | SovereignNexus s.r.o.  
Email: `andrejlo123@gmail.com`  
Prague, Czech Republic  
Repository: https://github.com/smaos-ai/smaos-ai-sandbox
