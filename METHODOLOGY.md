# SMAOS Methodology (v0.4.0)

## What Is Tested

SMAOS tests whether an agent harness correctly classifies the outcome of a
mutating wire call when the transport layer provides no confirmation.

The test is binary: does the harness preserve uncertainty, or does it promote
an unconfirmed effect to a false success?

## How Scenarios Are Defined

Each scenario specifies:

- A **transport fault** injected by the SMAOS mock proxy (`127.0.0.1:18080`)
- The **SDK-claimed state** the agent harness would log without intervention
- The **expected disposition** the SMAOS engine must record

The eight Tier-1 wire-fault and idempotency scenarios are defined in `scenarios.md`.

## How the Engine Runs

1. A mock downstream server starts on `127.0.0.1:18081`.
2. SMAOS injects the specified transport fault via a local proxy on `127.0.0.1:18080`.
3. The agent call is routed through the proxy toward the mock server.
4. SMAOS observes the raw socket outcome and compares it to the agent's claimed state.
5. If the wire drops but the agent claims `CONFIRMED`, SMAOS records `dispatched_unconfirmed`.
6. All execution is loopback-only. No bytes leave `127.0.0.1`.

## How Dispositions Are Derived

SMAOS applies a six-level precedence cascade (highest wins):

| Priority | Disposition              | Trigger                                         |
|:---------|:-------------------------|:------------------------------------------------|
| 1        | `INVALID_INPUT`          | Malformed fixture or missing required fields    |
| 2        | `CONFLICT`               | Receipt digest mismatch                         |
| 3        | `MISSING_EVIDENCE`       | Receipt absent; outcome unknown                 |
| 4        | `dispatched_unconfirmed` | Transport fault; SDK claimed success            |
| 5        | `REFUSED`                | Policy gate rejected the call                   |
| 6        | `CONFIRMED`              | HTTP 200 with valid evidence                    |

## How Evidence Bundles Are Structured

Each run produces four artifacts in `./audit_out/<scenario_id>/`:

- **`disposition_report.json`**: Machine-readable receipt aligned to IETF Agent
  Action Capsule draft-04. Contains `evaluated_disposition`, `discrepancy_detected`,
  `transport_fault`, and `sdk_claimed_state`.
- **`audit_trace.mermaid`**: Mermaid sequence diagram mapping wire events against
  the agent's claimed state for visual inspection and ISO 42001 Clause 9 SoA sign-off.
- **`dora_art17_gap_report.json`**: Classification dossier for human risk teams
  operating under EBA DORA RTS 2024/1772 Article 17.
- **`ProofOrStopFilter.java`**: A 15-line Spring Boot WebClient filter enforcing
  `Evidence Absent => UNKNOWN` for immediate engineering remediation.

## PII Handling

All payloads are scrubbed in memory before any file write. The scrubber redacts:

- IBANs → `[REDACTED_IBAN]`
- Credit card PANs → `[REDACTED_PAN]`
- Bearer JWTs → `Bearer [REDACTED_JWT]`
- Email addresses → `[REDACTED_EMAIL]`

No raw PII is written to disk or transmitted over any network interface.

## Advanced Failure Modes (Tier-1 Scenarios)

In addition to basic gateway timeouts and TCP connection aborts, SMAOS evaluates three critical distributed systems fault modes:

### 1. Client-Side Deadline Enforcement (`delayed_confirmation`)
In high-throughput financial architectures, confirmation packets that arrive after the client-side timeout has elapsed (e.g., HTTP 200 arriving at t+65s against a 30s deadline) cannot be retroactively trusted as synchronous success. Naive harnesses promote late receipts to `CONFIRMED`, blinding upstream orchestrators to race conditions and orphan mutations. SMAOS enforces `dispatched_unconfirmed` to isolate the unconfirmed execution.

### 2. Idempotency & Mutation Guards (`duplicate_retry_same_payload` / `payload_mutation_on_retry`)
When transport drops occur, agents frequently fire automated retries. SMAOS validates wire integrity against idempotency keys:
- **Duplicate in-flight**: If an agent retries an identical mutation while the original request is unconfirmed downstream, SMAOS flags `CONFLICT` to halt duplicate clearing runs.
- **Payload mutation on retry**: If an agent alters parameters (such as amount or account) while reusing an existing `idempotency_key` or `action_id`, SMAOS flags `CONFLICT` due to payload digest divergence.

### 3. Response Contract Schema Gates (`malformed_response`)
Downstream services returning HTTP 200 OK with truncated payloads, malformed JSON, or missing cryptographic signatures must never be assumed successful. SMAOS intercepts corrupt wire payloads and enforces `INVALID_INPUT` (precedence level 1), halting ungrounded state advancement.
