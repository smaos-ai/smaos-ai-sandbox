# Hardware-Backed Attestation for SMAOS Trust Passports

## 1. Threat Model & Vulnerability in v0.4.0
Currently, the SMAOS engine (`run.py`) and the `trust_passport.json` generation occur in user-space. A compromised host OS, a hijacked Docker daemon, or an agent achieving root privilege escape could theoretically alter the in-memory execution state, spoof the wire-evidence, or extract the Ed25519 private key used to sign the Trust Passport.

## 2. The Hardware Membrane (TDX / SEV-SNP)
To eliminate host-level trust assumptions, SMAOS v0.5.0 introduces **Hardware-Backed Execution**.
The core verification engine and signing keys are isolated inside a Confidential Computing Enclave (e.g., Intel TDX or AMD SEV-SNP).

### 2.1 The Attestation Quote
When the enclave generates a `trust_passport.json`, it also requests a **Hardware Attestation Quote** from the CPU. This quote cryptographically binds:
1. The **Measurement (MRENCLAVE/MRSIGNER)**: A hash of the exact SMAOS engine bytecode loaded into the enclave.
2. The **Report Data**: The SHA-256 hash of the generated `trust_passport.json`.

## 3. Trust Passport Schema Extension (v0.5.0)
The Trust Passport will include a new `hardware_attestation` block:

```json
{
  "hardware_attestation": {
    "provider": "Intel_TDX",
    "quote_base64": "AwACAAAAAAAJAA...",
    "enclave_measurement": "sha256:4a5b6c...",
    "report_data_binding": "sha256_of_passport_payload"
  }
}
```

## 4. Verification Workflow
1. The auditor receives the Trust Passport.
2. The offline verifier checks the Ed25519 signature.
3. The offline verifier parses the `quote_base64` and verifies it against the CPU vendor's public certificate chain (e.g., Intel SGX/TDX Provisioning Certification Key).
4. The verifier confirms the `enclave_measurement` matches the known good release of the SMAOS engine.

## 5. Limitations
Hardware attestation proves the engine wasn't tampered with, but it does not protect against vulnerabilities within the SMAOS engine bytecode itself, nor does it prevent Denial of Service (shutting down the enclave).
