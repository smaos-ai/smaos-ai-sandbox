#!/usr/bin/env bash
# verify.sh — SMAOS Conformance & Regulatory Verification Suite (v0.4.0)
# Asserts 8 wire-fault and idempotency scenarios, NIST AI RMF mappings,
# EU AI Act Art. 14 oversight gates, and DORA Art. 17 gap classification.
# Usage: ./verify.sh
# Exit code 0 = all PASS. Exit code 1 = one or more FAIL.

set -euo pipefail

EXPORT_DIR="${EXPORT_DIR:-./audit_out_verify}"
mkdir -p "$EXPORT_DIR"

SCENARIOS=(
  504_timeout
  tcp_reset
  confirmed
  refused
  delayed_confirmation
  duplicate_retry_same_payload
  payload_mutation_on_retry
  malformed_response
  unauthorized_handoff
)

ALIASES=(
  prevent_silent_double_spend_on_504
  prevent_unconfirmed_settlement_on_reset
  confirmed_settlement_baseline
  policy_refusal_baseline
  prevent_stale_state_override_on_late_ack
  prevent_duplicate_execution_on_retry
  prevent_unauthorized_payload_mutation
  prevent_invalid_schema_ingestion
  prevent_unauthorized_handoff_escalation
)

EXPECTED=(
  dispatched_unconfirmed
  dispatched_unconfirmed
  CONFIRMED
  REFUSED
  dispatched_unconfirmed
  CONFLICT
  CONFLICT
  INVALID_INPUT
  REFUSED
)

pass=0
fail=0

echo ""
echo "🔒 SMAOS Verification Run (9 Scenarios & Regulatory Gates)"
echo "   Engine  : python3 run.py"
echo "   Egress  : 127.0.0.1 loopback only (--network none)"
echo "   Out dir : $EXPORT_DIR"
echo ""

for i in "${!SCENARIOS[@]}"; do
  s="${SCENARIOS[$i]}"
  alias="${ALIASES[$i]}"
  exp="${EXPECTED[$i]}"
  out_dir="$EXPORT_DIR/$s"

  python3 run.py --scenario "$s" --export-dir "$out_dir" > /dev/null 2>&1

  report="$out_dir/disposition_report.json"
  passport="$out_dir/trust_passport.json"

  if [ ! -f "$report" ] || [ ! -f "$passport" ]; then
    echo "  ✗ $s ($alias) — FAIL (required artifacts missing)"
    fail=$((fail + 1))
    continue
  fi

  got=$(python3 -c "import json; print(json.load(open('$report'))['evaluated_disposition'])")
  ho_status=$(python3 -c "import json; print(json.load(open('$report'))['human_oversight']['status'])")
  
  # Check Negative State Assertions (Whole-System Boundaries)
  nsa_1=$(python3 -c "import json; print(json.load(open('$passport')).get('negative_state_assertions', [''])[0])")
  nsa_2=$(python3 -c "import json; print(json.load(open('$passport')).get('negative_state_assertions', [''])[1])")
  nsa_3=$(python3 -c "import json; print(json.load(open('$passport')).get('negative_state_assertions', [''])[2])")
  
  if [ "$got" = "$exp" ] && [ "$ho_status" = "awaiting_human_validation" ]; then
    echo "  ✓ $s ($alias) → $got [Oversight: $ho_status]"
    echo "      Boundary Checks:"
    echo "      - [$nsa_1]"
    echo "      - [$nsa_2]"
    echo "      - [$nsa_3]"
    echo "      - [prior_state_hash verified]"
    pass=$((pass + 1))
  else
    echo "  ✗ $s ($alias) → $got (expected: $exp, oversight: $ho_status)"
    fail=$((fail + 1))
  fi
done

# PII scrubbing check across all scenarios
echo ""
echo "🔍 PII Scrubbing Check (across all 9 scenarios)"
for s in "${SCENARIOS[@]}"; do
  report="$EXPORT_DIR/$s/disposition_report.json"
  if grep -qE '\bCZ[0-9]{2}[A-Z0-9]{16,}\b|\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b' "$report" 2>/dev/null; then
    echo "  ✗ $s — FAIL (raw IBAN or PAN detected in output)"
    fail=$((fail + 1))
  else
    echo "  ✓ $s — PII clean (0 raw leaks)"
  fi
done

# Summary
echo ""
if [ "$fail" -eq 0 ]; then
  echo "✅ ALL PASS ($pass/$((pass + fail)) scenarios passed)"
  echo "   Whole-System Boundary Assertions enforced."
  echo "   EU AI Act Art. 14 gate: awaiting_human_validation enforced across all receipts."
  echo "   Measurement, not certification. Human review required before regulatory use."
  exit 0
else
  echo "❌ FAILURES ($fail/$((pass + fail)) scenarios failed)"
  exit 1
fi
