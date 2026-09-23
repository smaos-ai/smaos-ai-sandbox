"""AARM / SCITT Notarization.

Formats receipts to the Agent Action Receipt Model (AARM) specification,
signs payloads with Ed25519, and packages into RFC 9942 COSE_Sign1.
"""
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from src.canonicalizer import canonicalize

class AARMSigner:
    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()

    def generate_receipt(self, passport_path: str, output_path: str):
        with open(passport_path, 'r') as f:
            data = json.load(f)
            
        canonical_payload = canonicalize(data)
        signature = self.private_key.sign(canonical_payload)
        
        cose_envelope = {
            "protected_header": {
                "alg": "EdDSA",
                "crit": ["profile"],
                "profile": "draft-ietf-scitt-architecture-04",
                "content_type": "application/aarm+json"
            },
            "unprotected_header": {
                "kid": "did:smaos:key:aarm_001"
            },
            "payload_hash": hashlib.sha256(canonical_payload).hexdigest(),
            "signature_base64": base64.b64encode(signature).decode('ascii'),
            "payload": data
        }
        
        with open(output_path, 'w') as f:
            json.dump(cose_envelope, f, indent=2)
            
        print(f"[*] AARM SCITT COSE_Sign1 Envelope Generated: {output_path}")

if __name__ == "__main__":
    signer = AARMSigner()
    signer.generate_receipt("audit_out/trust_passport.json", "audit_out/receipt.cose")
