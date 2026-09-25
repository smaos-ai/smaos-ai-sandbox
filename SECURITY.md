# Sovereign Zero-Trust Security Specification (v1.1.0)

This document formalizes the **Bare-Metal Hardware Attestation**, **Confidential VM (CVM) Register Mapping**, and **Ring-0 Kernel Physics** security architecture for the Sovereign Multi-Agent Operating System (SMAOS).

---

## 1. Hardware Enclave Register Mapping

SMAOS eliminates host hypervisor and operating system trust assumptions by cryptographically binding every agent execution envelope directly into hardware CPU registers.

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│                       CPU HARDWARE ATTESTATION PIPELINE                           │
├───────────────────────────────┬───────────────────────────────────────────────────┤
│ EXECUTION LAYER               │ HARDWARE BOUNDARY                                 │
├───────────────────────────────┼───────────────────────────────────────────────────┤
│ Agent Intent / Receipt        │ JCS RFC 8785 Canonical Representation             │
│          ▼                    │                         ▼                         │
│ COSE_Sign1 Binary (.cose)     │ RFC 9052 Tag 18 Binary CBOR Structure             │
│          ▼                    │                         ▼                         │
│ SHA-256(COSE_Sign1_Digest)    │ Exact 64-byte User Data Input                     │
│          ▼                    │                         ▼                         │
│ CPU `ioctl` Syscall           │ TDX_CMD_GET_REPORT0 (0xC0205401) / SNP_GET_REPORT │
│          ▼                    │                         ▼                         │
│ Hardware Register             │ 64-byte REPORTDATA / user_data in Silicon Fuses  │
└───────────────────────────────┴───────────────────────────────────────────────────┘
```

### 1.1 Intel Trust Domain Extensions (TDX 1.0)
* **Device Interface**: `/dev/tdx_guest` (fallback: `/dev/tdx-guest`)
* **IOCTL Command**: `TDX_CMD_GET_REPORT0 = 0xC0205401`
* **Structure Layout**: `TDREPORT_STRUCT` (1024 bytes)
* **REPORTDATA Offset**: Byte offset 96 (length: 64 bytes)
* **Measurement Registers**:
  - `MRTD` (Measurement Root of Trust Domain): Byte offset 160 (48 bytes, SHA-384)
  - `RTMR0` (Runtime Measurement Register 0): Byte offset 288 (48 bytes, SHA-384)

The agent runtime passes the 64-byte `REPORTDATA` nonce directly into `/dev/tdx_guest`:
```c
struct tdx_report_req {
    __u8  subtype;        /* Subtype 0 = TDREPORT */
    __u64 reportdata;     /* Pointer to 64-byte SHA-256(COSE_Sign1_Digest) */
    __u64 tdreport;       /* Pointer to 1024-byte output report buffer */
    __u32 rpd_len;        /* 64 */
    __u32 tdr_len;        /* 1024 */
};
ioctl(fd, TDX_CMD_GET_REPORT0, &req);
```

### 1.2 AMD SEV-SNP (Firmware ABI 1.55)
* **Device Interface**: `/dev/sev-guest`
* **IOCTL Command**: `SNP_GET_REPORT = 0xC0205300`
* **Structure Layout**: `ATTESTATION_REPORT` (1184 bytes)
* **REPORTDATA Offset**: Byte offset 80 (length: 64 bytes)
* **Measurement Offset**: Byte offset 144 (48 bytes, SHA-384)

```c
struct snp_report_req {
    __u8  user_data[64];  /* 64-byte SHA-256(COSE_Sign1_Digest) */
    __u32 vmpl;           /* VMPL level (0 = Bare-metal agent core) */
    __u8  rsvd[28];
};
```

---

## 2. Ring-0 Kernel Physics Layer (eBPF XDP)

Lateral agent movement and unauthorized network egress are stopped directly in the network card / device driver hook before entering the user-space TCP/IP stack.

* **Kernel Bytecode**: `ebpf/smaos_egress_xdp.o` (64-bit ELF relocatable, `EM_BPF = 247`)
* **Hook Point**: `SEC("xdp_egress")`
* **Enforcement Latency**: `<500 nanoseconds` (sub-microsecond)
* **Host CPU Impact**: `0 user-space CPU cycles consumed` for dropped packets
* **Dynamic BPF Maps**:
  - `allowed_ipv4`: Hash map (`BPF_MAP_TYPE_HASH`, 1024 entries)
  - `allowed_ports`: Hash map (`BPF_MAP_TYPE_HASH`, 256 entries)
  - `egress_telemetry`: High-speed atomic array (`BPF_MAP_TYPE_ARRAY`, 16 entries)

---

## 3. Sovereign Zero-Trust Assertions

1. **AST-Level Mock Purge**:
   - Production code (`src/`, `ebpf/`, CLI runners) is scanned via AST.
   - Any reference to `unittest.mock`, `MagicMock`, `AsyncMock`, or `@patch` decorators in runtime paths halts CI and pre-commit hooks with exit code 1.
2. **Bytecode & Artifact Hash Lock**:
   - WebAssembly binaries (`smaos_verify.wasm`, `smaos_verify_bg.wasm`), eBPF kernel drivers (`smaos_egress_xdp.o`), and offline verifiers are sealed in `checksums.sha256`.
3. **Automated 0-Byte Airgap Socket Inspection**:
   - All tests execute under an active socket interceptor (`tests/conftest.py`).
   - Outbound connections to external non-loopback IP addresses raise `AirgapViolationError`.
4. **Hardware-Bound Private Keys**:
   - Signing keys (`Ed25519`, NIST FIPS 204 `ML-DSA-65`) are never read from plain `.pem` or `.json` files on disk.
   - Keys must originate exclusively from TPM 2.0 hardware registers, Secure Enclave, environment secrets, or in-memory CSPRNG ephemeral state.

---

## 4. Bare-Metal Deployment Requirements

For production Tier-1 banking and critical infrastructure deployment:

| Requirement | Specification |
|-------------|---------------|
| **Host Kernel** | Linux 6.2+ with `CONFIG_INTEL_TDX_GUEST=y` or `CONFIG_SEV_GUEST=y` |
| **Linux Capabilities** | `CAP_BPF`, `CAP_NET_ADMIN` for Ring-0 XDP driver attachment |
| **Container Runtime** | Kata Containers 3.x (`kata-qemu-tdx` / `kata-qemu-snp`) |
| **Cryptographic TPM** | Hardware TPM 2.0 with `/dev/tpmrm0` character device |
| **Toolchain** | `bpftool`, `iproute2`, `clang` / `llvm` for BPF target |
