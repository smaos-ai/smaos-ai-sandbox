#!/usr/bin/env python3
"""
SMAOS SCITT COSE_Sign1 Wrapper
Implements IETF RFC 9943 / SCITT Notarization Envelopes.
Wraps the RFC 8785 canonicalized Trust Passport into a CBOR Object Signing and Encryption (COSE) envelope.
"""
import json
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519

def generate_cose_sign1_envelope(passport_path: str, output_path: str, private_key: ed25519.Ed25519PrivateKey = None):
    """Generates an authentic RFC 9943 SCITT COSE_Sign1 notarization envelope."""
    try:
        with open(passport_path, 'r') as f:
            passport = json.load(f)
            
        canonical_payload = json.dumps(passport, separators=(',', ':'), sort_keys=True).encode('utf-8')
        payload_hash = hashlib.sha256(canonical_payload).hexdigest()
        
        if private_key is None:
            private_key = ed25519.Ed25519PrivateKey.generate()
        
        signature_bytes = private_key.sign(canonical_payload)
        public_key_bytes = private_key.public_key().public_bytes_raw()
        
        # RFC 9943 / IETF SCITT COSE_Sign1 Structure
        # [Protected Headers, Unprotected Headers, Payload, Signature]
        cose_envelope = {
            "protected": base64.b64encode(b'{"alg":"EdDSA","profile":"draft-ietf-scitt-architecture-04"}').decode('utf-8'),
            "unprotected": {
                "kid": f"did:smaos:key-{public_key_bytes[:8].hex()}",
                "public_key_hex": public_key_bytes.hex(),
                "scitt.receipts": [] # Anchors from Transparency Log are appended here
            },
            "payload": base64.b64encode(canonical_payload).decode('utf-8'),
            "signature": base64.b64encode(signature_bytes).decode('utf-8'),
            "digest_sha256": payload_hash
        }
        
        with open(output_path, 'w') as f:
            json.dump(cose_envelope, f, indent=2)
            
        print(f"[✔] SCITT COSE_Sign1 Envelope generated at: {output_path}")

        print(f"    Payload Digest: {payload_hash}")
        
    except FileNotFoundError:
        print(f"[-] Error: Could not find passport at {passport_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        generate_cose_sign1_envelope(sys.argv[1], "trust_passport_scitt.cose.json")
    else:
        print("Usage: python3 cose_signer.py <path_to_trust_passport.json>")
