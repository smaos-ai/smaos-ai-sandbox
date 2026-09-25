#!/usr/bin/env python3
"""
SMAOS SCITT COSE_Sign1 Wrapper (v1.1.0)
Implements IETF RFC 9052 / RFC 9943 / IETF SCITT Notarization Envelopes.
Serializes into both:
  1. Canonical binary CBOR structure (.cose extension, RFC 9052 Tag 18)
  2. Diagnostic JSON envelope for audit readability
"""

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

# Ensure repository root is on sys.path
_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from cryptography.hazmat.primitives.asymmetric import ed25519
from src.scitt_cose.cbor_encoder import (
    ALG_EDDSA,
    HEADER_ALG,
    HEADER_KID,
    create_cose_sign1_binary,
    create_sig_structure,
)


def generate_cose_sign1_envelope(
    passport_path: str,
    output_path: str,
    private_key: Optional[ed25519.Ed25519PrivateKey] = None
) -> str:
    """Generates an authentic RFC 9052 / RFC 9943 SCITT COSE_Sign1 binary and JSON envelope."""
    try:
        with open(passport_path, "r", encoding="utf-8") as f:
            passport = json.load(f)

        canonical_payload = json.dumps(passport, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_hash = hashlib.sha256(canonical_payload).hexdigest()

        if private_key is None:
            private_key = ed25519.Ed25519PrivateKey.generate()

        public_key_bytes = private_key.public_key().public_bytes_raw()
        kid = f"did:smaos:key-{public_key_bytes[:8].hex()}".encode("utf-8")

        # 1. RFC 9052 Protected & Unprotected Headers
        protected_headers = {
            HEADER_ALG: ALG_EDDSA, # -8 (EdDSA)
            397: "draft-ietf-scitt-architecture-04" # SCITT Profile
        }
        unprotected_headers = {
            HEADER_KID: kid,
            398: public_key_bytes.hex()
        }

        # 2. RFC 9052 Sig_structure for signature computation
        tbs_bytes = create_sig_structure("Signature1", protected_headers, b"", canonical_payload)
        signature_bytes = private_key.sign(tbs_bytes)

        # 3. Canonical Binary CBOR COSE_Sign1 Encoding (.cose)
        binary_cbor = create_cose_sign1_binary(
            protected_headers=protected_headers,
            unprotected_headers=unprotected_headers,
            payload=canonical_payload,
            signature=signature_bytes,
            tag=True
        )

        binary_output_path = output_path
        if not binary_output_path.endswith(".cose"):
            binary_output_path = str(Path(output_path).with_suffix(".cose"))

        with open(binary_output_path, "wb") as bf:
            bf.write(binary_cbor)

        # 4. Diagnostic JSON representation (.cose.json)
        json_output_path = output_path if output_path.endswith(".json") else f"{output_path}.json"
        cose_envelope = {
            "protected": base64.b64encode(json.dumps({"alg": "EdDSA", "profile": "draft-ietf-scitt-architecture-04"}).encode()).decode("utf-8"),
            "unprotected": {
                "kid": kid.decode("utf-8"),
                "public_key_hex": public_key_bytes.hex(),
                "scitt.receipts": []
            },
            "payload": base64.b64encode(canonical_payload).decode("utf-8"),
            "signature": base64.b64encode(signature_bytes).decode("utf-8"),
            "digest_sha256": payload_hash,
            "binary_cbor_path": binary_output_path,
            "cbor_byte_length": len(binary_cbor)
        }

        with open(json_output_path, "w", encoding="utf-8") as jf:
            json.dump(cose_envelope, jf, indent=2)

        print(f"[✔] SCITT Binary CBOR COSE_Sign1: {binary_output_path} ({len(binary_cbor)} bytes)")
        print(f"[✔] SCITT Diagnostic JSON Envelope: {json_output_path}")
        print(f"    Payload Digest (SHA-256): {payload_hash}")
        return binary_output_path

    except FileNotFoundError:
        print(f"[-] Error: Could not find passport at {passport_path}", file=sys.stderr)
        raise


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_in = sys.argv[1]
        target_out = sys.argv[2] if len(sys.argv) > 2 else "audit_out/trust_passport.cose"
        generate_cose_sign1_envelope(target_in, target_out)
    else:
        print("Usage: python3 cose_signer.py <path_to_trust_passport.json> [output_path]")
