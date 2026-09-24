import hashlib
import json
import pytest
from src.pqc_mldsa import (
    MLDSA65,
    HybridSigner,
    PK_BYTES,
    SK_BYTES,
    SIG_BYTES,
    SEED_BYTES,
)
from src.scitt_envelope import generate_scitt_envelope



def test_mldsa65_constants_and_parameter_bounds():
    """Validates FIPS 204 ML-DSA-65 parameter dimensions."""
    assert PK_BYTES == 1952
    assert SK_BYTES == 4032
    assert SIG_BYTES == 3309
    assert SEED_BYTES == 32


def test_mldsa65_keygen_and_determinism():
    """Validates keypair generation lengths and seed determinism."""
    seed = b"\x42" * 32
    kp1 = MLDSA65.keygen(seed)
    kp2 = MLDSA65.keygen(seed)

    assert len(kp1.public_key) == PK_BYTES
    assert len(kp1.secret_key) == SK_BYTES
    assert len(kp1.rho) == 32
    assert len(kp1.tr) == 64

    # Deterministic generation check
    assert kp1.public_key == kp2.public_key
    assert kp1.secret_key == kp2.secret_key
    assert kp1.rho == kp2.rho
    assert kp1.tr == kp2.tr


def test_mldsa65_sign_and_verify():
    """Validates signing and successful verification."""
    seed = b"\x77" * 32
    kp = MLDSA65.keygen(seed)
    message = b"FIPS-204-POST-QUANTUM-REGULATORY-LEDGER-TRANSACTION"

    sig = MLDSA65.sign(message, kp.secret_key)
    assert len(sig) == SIG_BYTES

    # Successful verification
    assert MLDSA65.verify(message, sig, kp.public_key) is True

    # Bad signature length fails
    assert MLDSA65.verify(message, sig[:-1], kp.public_key) is False

    # Bad public key length fails
    assert MLDSA65.verify(message, sig, kp.public_key[:-1]) is False


def test_mldsa65_tamper_rejection():
    """Validates that tampered signatures are rejected."""
    kp = MLDSA65.keygen()
    message = b"SOVEREIGN-SETTLEMENT-LEDGER"
    sig = MLDSA65.sign(message, kp.secret_key)

    # Empty/truncated signature
    assert MLDSA65.verify(message, b"", kp.public_key) is False

    # Corrupted signature (all zeroes)
    zero_sig = b"\x00" * SIG_BYTES
    assert MLDSA65.verify(message, zero_sig, kp.public_key) is False


def test_hybrid_signer_dual_verification():
    """Validates dual Ed25519 + ML-DSA-65 hybrid signature generation and verification."""
    seed = b"\x99" * 32
    signer = HybridSigner(seed)
    message = b"HIGH-RISK-AI-AGENT-EXECUTION-LOG-RFC8785"

    envelope = signer.sign_hybrid(message)
    assert envelope["scheme"] == "Ed25519+ML-DSA-65-Hybrid"
    assert envelope["security_level"] == "NIST Level 3 / CNSA 2.0 (192-bit quantum security)"
    assert envelope["mldsa65"]["public_key_bytes"] == PK_BYTES
    assert envelope["mldsa65"]["signature_bytes"] == SIG_BYTES

    ed_pk = signer.ed25519_pk.public_bytes_raw()
    pqc_pk = signer.pqc_keypair.public_key

    # Verification must succeed for both schemes
    ed_valid, pqc_valid = HybridSigner.verify_hybrid(message, envelope, ed_pk, pqc_pk)
    assert ed_valid is True
    assert pqc_valid is True

    # Message tampering invalidates classical signature
    bad_msg = b"TAMPERED-MESSAGE"
    ed_valid, pqc_valid = HybridSigner.verify_hybrid(bad_msg, envelope, ed_pk, pqc_pk)
    assert ed_valid is False

    # Corrupted classical signature invalidates classical verification
    corrupt_envelope = dict(envelope)
    corrupt_envelope["ed25519"] = dict(envelope["ed25519"])
    corrupt_envelope["ed25519"]["signature_hex"] = "00" * 64
    ed_valid, pqc_valid = HybridSigner.verify_hybrid(message, corrupt_envelope, ed_pk, pqc_pk)
    assert ed_valid is False
    assert pqc_valid is True


def test_scitt_envelope_pqc_integration(tmp_path):
    """Validates SCITT COSE_Sign1 generation with ML-DSA-65 PQC block."""
    passport_file = tmp_path / "trust_passport.json"
    output_cose = tmp_path / "trust_passport.cose.json"

    payload = {
        "event_id": "EVT-TEST-PQC-001",
        "action": "WIRE_DISPATCH",
        "jurisdiction": "EU",
        "compliance_target": "DORA_ART17_PQC"
    }
    passport_file.write_text(json.dumps(payload), encoding="utf-8")

    generate_scitt_envelope(str(passport_file), str(output_cose), anchor=False, enable_pqc=True)
    assert output_cose.exists()

    with open(output_cose, "r") as f:
        envelope = json.load(f)

    assert envelope["protected_header"]["crypto_suite"] == "Ed25519+ML-DSA-65-Hybrid"
    assert envelope["protected_header"]["pqc_standard"] == "NIST FIPS 204"
    assert "pqc_mldsa65" in envelope
    assert envelope["pqc_mldsa65"]["algorithm"] == "ML-DSA-65"
    assert "signature_base64" in envelope["pqc_mldsa65"]
    assert "public_key_hex" in envelope["pqc_mldsa65"]

