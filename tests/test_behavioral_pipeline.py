import pytest
import json
from pathlib import Path
from src.intent_ledger import IntentLedger
from src.admissibility_gate import AdmissibilityGate
from src.transport_observer import observe_tool_call
from src.canonicalizer import canonicalize, get_hash
from src.scitt_envelope import generate_scitt_envelope
from src.bbs_redactor import redact_passport
from src.aarm_signer import AARMSigner

def test_full_behavioral_governance_pipeline(tmp_path):
    # 1. Pre-execution Intent Lock
    db_file = str(tmp_path / "pipeline_intent.db")
    ledger = IntentLedger(db_file)
    payload = {"account": "CZ6508000000001234567890", "amount_minor": 5000000}
    intent_id = ledger.declare_intent("treasury_agent", "payments.execute", payload)
    assert intent_id is not None

    # 2. Admissibility Gate Evaluation
    gate = AdmissibilityGate()
    gate.allowed_apis = ["payments.execute"]
    gate.max_limit_minor = 10000000
    verdict = gate.evaluate("payments.execute", payload)
    assert verdict == "ALLOW"

    # 3. Transport Reality (Socket Interception on 504)
    def simulate_downstream_504():
        class R:
            status_code = 504
        return R()

    _, obs = observe_tool_call(simulate_downstream_504, ledger, intent_id)
    assert obs.disposition in ("UNKNOWN", "DISPATCHED_UNCONFIRMED")
    assert obs.http_status == 504

    # 4. Intent Ledger Status Updated
    ledger.cursor.execute("SELECT status FROM intents WHERE id = ?", (intent_id,))
    final_status = ledger.cursor.fetchone()[0]
    assert final_status in ("UNKNOWN", "DISPATCHED_UNCONFIRMED")

    # 5. Canonical Serialization (RFC 8785 JCS)
    record = {
        "intent_id": intent_id,
        "disposition": obs.disposition,
        "payload_hash": get_hash(payload)
    }
    jcs_bytes = canonicalize(record)
    assert b"\"disposition\":\"UNKNOWN\"" in jcs_bytes or b"\"disposition\":\"DISPATCHED_UNCONFIRMED\"" in jcs_bytes

    # 6. SCITT COSE_Sign1 Enveloping
    passport_file = tmp_path / "trust_passport.json"
    passport_data = {
        "identity": {"agent_id": "treasury_agent"},
        "negative_state_assertions": ["authority_created = false"],
        "overclaim_rate_detected": 0.0,
        "user_iban": "CZ6508000000001234567890"
    }
    passport_file.write_text(json.dumps(passport_data, indent=2))

    cose_file = tmp_path / "trust_passport.cose.json"
    generate_scitt_envelope(str(passport_file), str(cose_file))
    assert cose_file.exists()
    cose_data = json.loads(cose_file.read_text())
    assert cose_data["protected_header"]["alg"] == "EdDSA"

    # 7. BBS+ Selective Disclosure (GDPR PII Redaction)
    redacted_file = tmp_path / "trust_passport_redacted.json"
    redact_passport(str(passport_file), str(redacted_file))
    assert redacted_file.exists()
    redacted_data = json.loads(redacted_file.read_text())
    assert "user_iban" not in redacted_data["credentialSubject"]
    assert "user_iban" in redacted_data["proof"]["redacted_fields"]
    assert "bbs12381_sha384_proof:" in redacted_data["proof"]["proofValue"]

    # 8. AARM Receipt
    aarm_file = tmp_path / "receipt.cose"
    AARMSigner().generate_receipt(str(passport_file), str(aarm_file))
    assert aarm_file.exists()
