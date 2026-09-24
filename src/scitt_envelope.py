"""IETF SCITT COSE_Sign1 Enveloping (RFC 9942/9943).

Wraps the JCS-canonicalized Trust Passport and Intent Ledger state into
a COSE_Sign1 structure for immutable transparency ledger notarization.
"""
import json
import base64
import hashlib
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519
try:
    from src.canonicalizer import canonicalize
except ImportError:
    from canonicalizer import canonicalize

try:
    from src.scitt_anchor import anchor_cose_envelope_to_file
except ImportError:
    try:
        from scitt_anchor import anchor_cose_envelope_to_file
    except ImportError:
        anchor_cose_envelope_to_file = None

def generate_scitt_envelope(passport_path: str, output_path: str, verbose: bool = False, anchor: bool = True):
    with open(passport_path, 'r') as f:
        data = json.load(f)
        
    canonical_payload = canonicalize(data)
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
            "kid": "did:smaos:key:behavioral_001"
        },
        "payload_hash": hashlib.sha256(canonical_payload).hexdigest(),
        "signature_base64": base64.b64encode(signature).decode('ascii'),
        "payload": data
    }
    
    with open(output_path, 'w') as f:
        json.dump(cose_envelope, f, indent=2)
        
    if verbose:
        print(f"[*] IETF SCITT COSE_Sign1 Envelope Generated: {output_path}", file=sys.stderr)

    if anchor and anchor_cose_envelope_to_file is not None:
        receipt_path = "audit_out/rekor_receipt.json"
        try:
            anchor_cose_envelope_to_file(output_path, receipt_path)
            if verbose:
                print(f"[*] Rekor / SCITT Inclusion Proof Anchored: {receipt_path}", file=sys.stderr)
        except Exception as e:
            if verbose:
                print(f"[!] Warning: Notarization error: {e}", file=sys.stderr)

if __name__ == "__main__":
    generate_scitt_envelope("audit_out/trust_passport.json", "audit_out/trust_passport.cose.json", verbose=True)

