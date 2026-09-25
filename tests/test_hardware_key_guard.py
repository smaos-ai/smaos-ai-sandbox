"""
Unit tests for Sovereign Hardware-Bound Key Guard.
"""

import os
import pytest
from src.security.hardware_key_guard import (
    HardwareBoundKeyViolation,
    HardwareKeyProvider,
    KeySource,
)


def test_rejects_disk_file_private_key_loading():
    """Validates that loading private keys from files/disk paths is strictly prohibited."""
    with pytest.raises(HardwareBoundKeyViolation) as exc_info:
        HardwareKeyProvider.load_from_file("/etc/ssl/private/key.pem")

    assert "strictly prohibits loading raw private keys" in str(exc_info.value)


def test_ephemeral_key_generation():
    """Validates generation of in-memory ephemeral Ed25519 and ML-DSA-65 keys."""
    key = HardwareKeyProvider.get_ed25519_key(KeySource.EPHEMERAL)
    assert key is not None
    pub = key.public_key().public_bytes_raw()
    assert len(pub) == 32

    seed = HardwareKeyProvider.get_mldsa65_seed(KeySource.EPHEMERAL)
    assert len(seed) == 32


def test_environment_key_loading(monkeypatch):
    """Validates derivation of keys from environment secrets."""
    test_seed = b"\x42" * 32
    monkeypatch.setenv("SMAOS_SIGNING_KEY_HEX", test_seed.hex())
    monkeypatch.setenv("SMAOS_MLDSA_SEED_HEX", test_seed.hex())

    ed_key = HardwareKeyProvider.get_ed25519_key(KeySource.ENVIRONMENT)
    assert ed_key is not None

    mldsa_seed = HardwareKeyProvider.get_mldsa65_seed(KeySource.ENVIRONMENT)
    assert mldsa_seed == test_seed


def test_environment_key_missing_raises_violation(monkeypatch):
    """Validates violation error when required environment variable is missing."""
    monkeypatch.delenv("SMAOS_SIGNING_KEY_HEX", raising=False)
    with pytest.raises(HardwareBoundKeyViolation) as exc_info:
        HardwareKeyProvider.get_ed25519_key(KeySource.ENVIRONMENT)

    assert "empty or missing" in str(exc_info.value)


def test_tpm_and_enclave_key_source():
    """Validates hardware TPM 2.0 and Secure Enclave abstraction sources."""
    tpm_key = HardwareKeyProvider.get_ed25519_key(KeySource.TPM_2_0)
    assert tpm_key is not None

    enclave_key = HardwareKeyProvider.get_ed25519_key(KeySource.SECURE_ENCLAVE)
    assert enclave_key is not None

    tpm_seed = HardwareKeyProvider.get_mldsa65_seed(KeySource.TPM_2_0)
    assert len(tpm_seed) == 32
