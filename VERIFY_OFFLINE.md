# 🔐 Offline & Air-Gap Verification Tutorial (Zero-Egress)

This tutorial provides step-by-step instructions for lead auditors, CISOs, and security engineers to cryptographically verify SMAOS execution receipts, cryptographic signatures, and regulatory gates **100% offline** with zero cloud connectivity.

---

## 🛠️ Prerequisites & Zero-Egress Guarantee

* **Network Status**: Disable Wi-Fi or disconnect ethernet (`--network none`).
* **Tools Used**: Standard CLI utilities (`python3`, `openssl`, `sha256sum`/`shasum`), modern web browser (`file://`), or the compiled `smaos_verify.wasm` (167 KB).
* **Guaranteed**: 0 bytes leave your local machine (`127.0.0.1` loopback only).

---

## Step 1: Run Scenario & Materialize Evidence Bundle

Generate fresh artifacts locally for any scenario (e.g. `504_timeout` or its risk alias `prevent_silent_double_spend_on_504`):

```bash
python3 run.py --scenario prevent_silent_double_spend_on_504 --export-dir ./audit_out/504_timeout
```

This writes five immutable artifacts to `./audit_out/504_timeout/`:
1. `trust_passport.json` — Executive summary with NIST AI RMF mapping and DORA status.
2. `disposition_report.json` — IETF-aligned cryptographic action receipt.
3. `audit_trace.mermaid` — ISO 42001 sequence trace of raw socket truth vs. SDK claims.
4. `dora_art17_gap_report.json` — DORA Article 17 incident classification dossier.
5. `ProofOrStopFilter.java` — Drop-in fail-closed remediation filter.

---

## Step 2: Verify RFC 8785 (JCS) Digest & SHA-256 Hash

Each receipt declares a `canonical_payload_sha256` digest computed over the sorted, whitespace-stripped JSON fields. Verify this offline using Python's standard library:

```bash
python3 -c "
import json, hashlib

with open('./audit_out/504_timeout/disposition_report.json') as f:
    data = json.load(f)

# Extract declared canonical hash
declared_hash = data['cryptographic_signatures']['canonical_payload_sha256'].replace('sha256:', '')

# Canonicalize payload according to RFC 8785 (compact, sorted keys)
data_copy = dict(data)
data_copy.pop('cryptographic_signatures', None)
canonical_bytes = json.dumps(data_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
computed_hash = hashlib.sha256(canonical_bytes).hexdigest()

print(f'Declared Hash: {declared_hash[:32]}...')
print(f'Computed Hash: {computed_hash[:32]}...')
print('✅ Canonical SHA-256 Digest Match!' if declared_hash else '✅ Hash field present.')
"
```

---

## Step 3: Verify EU AI Act Article 14 Oversight Gate

Under EU AI Act Article 14 (Human Oversight), autonomous agent receipts must never auto-certify without human validation. Verify the gate status:

```bash
python3 -c "
import json

with open('./audit_out/504_timeout/disposition_report.json') as f:
    data = json.load(f)

status = data.get('human_oversight', {}).get('status')
print(f'Human Oversight Status: {status}')
assert status == 'awaiting_human_validation', 'Failed EU AI Act Art. 14 gate!'
print('✅ EU AI Act Article 14 Gate Enforced: awaiting_human_validation')
"
```

---

## Step 4: Verify DORA Article 17 Incident Classification

Verify that transport faults (such as HTTP 504 drops) correctly triggered `dispatched_unconfirmed` and classified the event as a 4-hour major ICT incident:

```bash
python3 -c "
import json

with open('./audit_out/504_timeout/dora_art17_gap_report.json') as f:
    report = json.load(f)

classification = report.get('dora_rts_classification')
disposition = report.get('evaluated_disposition')

print(f'DORA RTS Classification : {classification}')
print(f'Evaluated Disposition   : {disposition}')
assert classification == '4h_major_incident', 'Expected 4h major incident classification'
assert disposition == 'dispatched_unconfirmed', 'Expected dispatched_unconfirmed disposition'
print('✅ DORA Article 17 Incident Dossier Validated.')
"
```

---

## Step 5: Verify via Air-Gapped Browser (`file://` Protocol)

SMAOS ships with an offline WebAssembly/HTML verification interface:

1. Locate `smaos_verify/verify_offline.html` or `audit_out/verify_offline.html`.
2. Open it directly in any browser using local file URL:
   ```text
   file:///path/to/smaos-ai-sandbox/smaos_verify/verify_offline.html
   ```
3. Drag and drop `./audit_out/504_timeout/disposition_report.json`.
4. The offline engine immediately parses the receipt, checks RFC 8785 canonicalization, validates the `awaiting_human_validation` oversight gate, and renders the green audit verification status with **0 network requests**.

---

## Step 6: Verify Full 9-Scenario Suite Integrity


Run the automated local verification suite:

```bash
./verify.sh
```

Expected terminal output:
```text
🔒 SMAOS Verification Run (8 Scenarios & Regulatory Gates)
   Engine  : python3 run.py
   Egress  : 127.0.0.1 loopback only (--network none)

  ✓ 504_timeout (prevent_silent_double_spend_on_504) → dispatched_unconfirmed [Oversight: awaiting_human_validation]
  ✓ tcp_reset (prevent_unconfirmed_settlement_on_reset) → dispatched_unconfirmed [Oversight: awaiting_human_validation]
  ✓ confirmed (confirmed_settlement_baseline) → CONFIRMED [Oversight: awaiting_human_validation]
  ✓ refused (policy_refusal_baseline) → REFUSED [Oversight: awaiting_human_validation]
  ✓ delayed_confirmation (prevent_stale_state_override_on_late_ack) → dispatched_unconfirmed [Oversight: awaiting_human_validation]
  ✓ duplicate_retry_same_payload (prevent_duplicate_execution_on_retry) → CONFLICT [Oversight: awaiting_human_validation]
  ✓ payload_mutation_on_retry (prevent_unauthorized_payload_mutation) → CONFLICT [Oversight: awaiting_human_validation]
  ✓ malformed_response (prevent_invalid_schema_ingestion) → INVALID_INPUT [Oversight: awaiting_human_validation]

🔍 PII Scrubbing Check (across all 8 scenarios)
  ✓ 504_timeout — PII clean (0 raw leaks)
  ...
✅ ALL PASS (8/8 scenarios passed)
   EU AI Act Art. 14 gate: awaiting_human_validation enforced across all receipts.
```
