# Hardware-Backed Attestation for SMAOS Trust Passports

## 1. Threat Model & Vulnerability in v0.4.0
Currently, the SMAOS engine (`run.py`) and the `trust_passport.json` generation occur in user-space. A compromised host OS, a hijacked Docker daemon, or an agent achieving root privilege escape could theoretically alter the in-memory execution state, spoof the wire-evidence, or extract the Ed25519 private key used to sign the Trust Passport.

## 2. The Hardware Membrane (TDX / SEV-SNP Production Architecture)
To eliminate host-level trust assumptions, SMAOS v1.1.0 integrates **Hardware-Backed Execution** directly via:
1. `src/enclave_cvm.py`: Live kernel ioctl interface for Intel TDX (`/dev/tdx_guest`, `TDX_CMD_GET_REPORT0`) and AMD SEV-SNP (`/dev/sev-guest`, `SNP_GET_REPORT`).
2. Kata Containers 3.x Confidential VM runtime classes configured in `deploy/kata/` (`kata-qemu-tdx` and `kata-qemu-snp`).

### 2.1 The Attestation Quote & Nonce Binding
When generating `audit_out/trust_passport.json` and signing the `COSE_Sign1` envelope:
1. **Payload Binding**: The SHA-512 digest (64 bytes) of the raw COSE_Sign1 passport bytes is injected directly into the CPU's hardware `REPORTDATA` register.
2. **CPU Measurement**: Intel TDX generates a 1024-byte `TDREPORT_STRUCT` containing:
   - `REPORTTYPE`: Architecture type identifier.
   - `RESERVED`: Reserved field.
   - `REPORTDATA`: Exactly 64 bytes cryptographically binding the trust passport.
   - `TCBMAC`: CPU hardware MAC computed with the platform's root key.
   - `TEE_TCB_SVN`: Security Version Number.
   - `MRTD`: Measurement of the initial virtual machine code (Trust Domain).
   - `RTMR[0..3]`: Runtime measurement registers tracking boot and runtime execution state.

## 3. Trust Passport Schema Integration (v1.1.0)
The Trust Passport automatically attaches the hardware attestation block:

```json
{
  "hardware_attestation": {
    "provider": "Intel_TDX",
    "quote_base64": "...",
    "enclave_measurement": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "report_data_binding": "...",
    "binary_report_path": "audit_out/tdx_report.bin"
  }
}
```

## 4. Kata Containers & Kubernetes Deployment
Production Confidential Pods run with hardware isolation using the manifests in `deploy/kata/`:
- `deploy/kata/kata-qemu-tdx-runtime.yaml`: RuntimeClass `kata-qemu-tdx` targeting QEMU with TDX guest firmware.
- `deploy/kata/kata-qemu-snp-runtime.yaml`: RuntimeClass `kata-qemu-snp` targeting AMD SEV-SNP firmware.
- `deploy/kata/pod-cvm-enclave.yaml`: Zero-egress Kubernetes Pod mounting `/dev/tdx_guest` with `runtimeClassName: kata-qemu-tdx`.

## 5. Verification Workflow
1. The verifier loads `audit_out/trust_passport.json` and reads `hardware_attestation`.
2. Verifies that `report_data_binding` matches `sha512(cose_sign1_bytes)`.
3. Verifies the binary `tdx_report.bin` structurally using `verify_tdx_report()` in `src/enclave_cvm.py`.
4. Enforces that both Ed25519 software wire-truth signatures and hardware CPU quotes match without divergence.

