# 📧 Direct Outreach to ČAS "Rada pro trh a inovace"

**To:** Rada pro trh a inovace (Market and Innovation Council), Czech Agency for Standardisation (ČAS)  
**From:** Andrei Leukhin, Lead Architect, SMAOS | SovereignNexus s.r.o.  
**Subject:** Working Reference Implementation: EU AI Act Article 14 Kill-Switch & Offline Agent Audit Framework  
**Date:** 24 September 2026  

---

Vážené členky, vážení členové Rady,

Following the September 15 council formation, we are reaching out directly to present a working reference implementation for the supervisory controls required under the **EU AI Act (Articles 12 & 14)** and **DORA (Article 17)**.

While existing market proposals offer post-hoc monitoring dashboards, SMAOS provides an operational, driver-level execution membrane that enforces human oversight before actions fire on external wires:

1. **Pre-Execution Admissibility Gate**: Implements a hard control returning ALLOW, DENY, or ESCALATE (AWAITING_HUMAN), physically freezing mutating financial transactions (≥ €10,000) until a human co-signature is registered.
2. **W3C BBS+ Vector ZKP Redaction**: Solves the ÚOOÚ / GDPR Article 17 conflict by allowing banks to zero out customer PII from audit trails without breaking the cryptographic signature verified by ČNB examiners.
3. **Air-Gapped Verification Engine**: Delivered as a pure-Rust 186 KB WebAssembly module (`dist/verifier.html` / `smaos_verify.wasm`) that executes locally inside the browser with zero cloud egress.
4. **Hardware-Attested Trust**: Binds raw execution passports directly to Intel TDX / AMD SEV-SNP CPU hardware nonces via direct kernel ioctls.

We would be glad to provide ČAS council members and supervisory examiners with a 15-minute live demonstration of the offline verifier using synthetic banking traces.

S úctou,

**Andrei Leukhin**  
Lead Architect, SMAOS (Sovereign Multi-Agent OS)  
SovereignNexus s.r.o., Prague, Czech Republic  
Email: `andrejlo123@gmail.com`  
Open-Core Implementation: https://github.com/smaos-ai/smaos-ai-sandbox
