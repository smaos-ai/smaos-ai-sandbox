import base64
import json
import pytest
from src.enclave_cvm import (
    CVMHardwareEnclave,
    compute_reportdata_nonce,
    attach_hardware_attestation_to_passport,
    REPORTDATA_LEN,
    TDX_REPORT_LEN,
    TDX_REPORTDATA_OFFSET
)

def test_reportdata_nonce_length_and_determinism():
    envelope = {
        "payload_hash": "a" * 64,
        "signature_base64": "b64sig",
        "protected_header": {"alg": "EdDSA"}
    }
    nonce = compute_reportdata_nonce(envelope)
    assert len(nonce) == REPORTDATA_LEN
    assert nonce == compute_reportdata_nonce(envelope)

def test_hardware_quote_generation_and_verification():
    enclave = CVMHardwareEnclave(enclave_type="INTEL_TDX")
    envelope = {
        "payload_hash": "f" * 64,
        "signature_base64": "sig123",
        "payload": {"action": "wire_transfer", "amount": 100000}
    }

    quote_bytes, meta = enclave.get_hardware_quote(envelope)
    assert len(quote_bytes) == TDX_REPORT_LEN
    assert meta["reportdata_offset"] == TDX_REPORTDATA_OFFSET
    assert meta["status"] == "DETERMINISTIC_CVM_SPEC_VERIFIED"

    # Verify quote binding matches envelope
    is_valid = CVMHardwareEnclave.verify_quote_binding(quote_bytes, envelope)
    assert is_valid is True

    # Tampered envelope must fail verification
    tampered_env = dict(envelope)
    tampered_env["payload"] = {"action": "wire_transfer", "amount": 999999}
    assert CVMHardwareEnclave.verify_quote_binding(quote_bytes, tampered_env) is False

    # Corrupted quote bytes must fail verification
    bad_quote = bytearray(quote_bytes)
    bad_quote[TDX_REPORTDATA_OFFSET] ^= 0xFF
    assert CVMHardwareEnclave.verify_quote_binding(bytes(bad_quote), envelope) is False

def test_attach_attestation_to_passport(tmp_path):
    passport_file = tmp_path / "trust_passport.json"
    cose_file = tmp_path / "trust_passport.cose.json"

    passport_data = {"version": "1.0", "disposition": "CONFIRMED"}
    cose_data = {"payload_hash": "c" * 64, "signature_base64": "dGVzdA=="}

    passport_file.write_text(json.dumps(passport_data), encoding="utf-8")
    cose_file.write_text(json.dumps(cose_data), encoding="utf-8")

    attestation = attach_hardware_attestation_to_passport(
        str(passport_file),
        str(cose_file),
        enclave_type="INTEL_TDX"
    )

    assert "quote_base64" in attestation
    assert "reportdata_nonce" in attestation
    assert attestation["provider"] == "INTEL_TDX"

    # Verify updated passport file
    updated_passport = json.loads(passport_file.read_text(encoding="utf-8"))
    assert "hardware_attestation" in updated_passport
