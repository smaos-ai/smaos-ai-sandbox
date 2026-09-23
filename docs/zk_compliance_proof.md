# Zero-Knowledge Compliance Proofs (ZK-SNARKs)

## 1. The Objective
To prove to a regulator (e.g., EBA, ČNB) that a specific AI risk control was enforced across a 30-day window, without submitting the raw transaction logs.
**Target Property:** *"For all execution traces where a transport fault (e.g., HTTP 504) occurred, the SMAOS engine assigned a disposition of `dispatched_unconfirmed` or `UNKNOWN`. No fault resulted in a false `CONFIRMED` state."*

## 2. Circuit Design (Halo2 / Arkworks)
We define a ZK circuit that takes the raw execution logs as **private inputs (witness)**, and outputs a single boolean compliance flag as a **public output**.

### 2.1 Private Inputs
- Array of `Trace`: `[Wire_Status_Code, Agent_Claim, SMAOS_Disposition]`

### 2.2 Circuit Logic
```rust
for trace in private_traces {
    // If wire dropped (504, 503, RST)
    if trace.Wire_Status_Code >= 500 || trace.Wire_Status_Code == 0 {
        // Enforce that SMAOS did NOT allow a CONFIRMED state
        assert(trace.SMAOS_Disposition != "CONFIRMED");
    }
}
// If all constraints hold, output True
return true;
```

## 3. The Deliverable Artifact
Instead of generating a 500 MB `dora_art17_gap_report.json` filled with sensitive IBANs and agent prompts, SMAOS generates:
1. `compliance_proof.snark` (2 KB)
2. `verification_key.vk` (1 KB)

The regulator runs the verification function offline in milliseconds. If it returns `TRUE`, they possess mathematical certainty that the overclaim rate was 0.0%, satisfying audit requirements entirely in zero-knowledge.
