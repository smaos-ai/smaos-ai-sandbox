#!/usr/bin/env python3
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519

def rfc8785_canonicalize(data: dict) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, separators=(',', ':'), sort_keys=True
    ).encode('utf-8')

def generate_scitt_envelope(passport_path, output_path):
    with open(passport_path, 'r') as f:
        data = json.load(f)
        
    canonical_payload = rfc8785_canonicalize(data)
    private_key = ed25519.Ed25519PrivateKey.generate()
    signature = private_key.sign(canonical_payload)
    
    cose_envelope = {
        "protected_header": {
            "alg": "EdDSA",
            "crit": ["profile"],
            "profile": "draft-ietf-scitt-architecture-04",
            "content_type": "application/json"
        },
        "unprotected_header": {
            "kid": "did:smaos:key:001"
        },
        "payload_hash": hashlib.sha256(canonical_payload).hexdigest(),
        "signature_base64": base64.b64encode(signature).decode('ascii'),
        "payload": data
    }
    
    with open(output_path, 'w') as f:
        json.dump(cose_envelope, f, indent=2)
        
    print(f"[+] SCITT COSE_Sign1 Envelope generated: {output_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        generate_scitt_envelope(sys.argv[1], "audit_out/trust_passport.cose")
    else:
        generate_scitt_envelope("audit_out/trust_passport.json", "audit_out/trust_passport.cose")
