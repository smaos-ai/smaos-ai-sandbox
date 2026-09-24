import base64
import json
import pytest
from src.scitt_anchor import MerkleTree, RekorAnchorService, sha256_hex

def test_merkle_tree_determinism_and_inclusion():
    tree = MerkleTree()
    leaves = [b"leaf_1", b"leaf_2", b"leaf_3", b"leaf_4", b"leaf_5"]
    indices = [tree.add_leaf(l) for l in leaves]

    root = tree.root_hex
    assert len(root) == 64

    for i, leaf in enumerate(leaves):
        proof = tree.get_inclusion_proof(i)
        is_valid = MerkleTree.verify_inclusion(
            leaf=leaf,
            index=i,
            tree_size=len(leaves),
            root_hash=root,
            proof=proof
        )
        assert is_valid is True

def test_merkle_tamper_rejection():
    tree = MerkleTree()
    leaves = [b"tx_a", b"tx_b", b"tx_c"]
    for l in leaves:
        tree.add_leaf(l)

    proof = tree.get_inclusion_proof(0)
    root = tree.root_hex

    # Tampered leaf must fail verification
    assert MerkleTree.verify_inclusion(b"tx_tampered", 0, len(leaves), root, proof) is False

    # Tampered audit path hash must fail verification
    bad_proof = list(proof)
    bad_proof[0] = {"direction": bad_proof[0]["direction"], "hash": "00" * 32}
    assert MerkleTree.verify_inclusion(b"tx_a", 0, len(leaves), root, bad_proof) is False

def test_rekor_anchor_service_full_receipt_verification(tmp_path):
    service = RekorAnchorService()
    fake_cose = {
        "payload_hash": sha256_hex(b"test_payload_data"),
        "signature_base64": base64.b64encode(b"fake_sig_bytes_64_padding_sample_12345").decode("ascii"),
        "payload": {"test": "data"}
    }

    receipt = service.anchor_cose_envelope(fake_cose, live=False)
    assert receipt["mode"] == "SOVEREIGN_AIRGAP_REKOR"
    assert receipt["verification_status"] == "CRYPTOGRAPHICALLY_VERIFIED"
    assert "inclusion_proof" in receipt
    assert "signed_tree_head" in receipt

    # Verify receipt cryptographically
    assert service.verify_receipt(receipt) is True

    # Tampering with entry must invalidate receipt
    tampered_receipt = dict(receipt)
    tampered_receipt["entry"] = dict(receipt["entry"])
    tampered_receipt["entry"]["spec"]["data"]["hash"]["value"] = "ff" * 32
    assert service.verify_receipt(tampered_receipt) is False
