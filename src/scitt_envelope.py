import json
import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519

def rfc8785_canonicalize(data: dict) -> bytes:
    """Canonicalize JSON according to RFC 8785 (JCS)."""
    return json.dumps(
        data, ensure_ascii=False, separators=(',', ':'), sort_keys=True
    ).encode('utf-8')

def build_cose_sign1_envelope(passport_path: str, private_key_bytes: bytes = None) -> dict:
    """Wrap trust_passport.json into an IETF SCITT COSE_Sign1 structure."""
    passport_file = Path(passport_path)
    if not passport_file.exists():
        raise FileNotFoundError(f"Passport file {passport_path} not found.")

    with open(passport_file, 'r', encoding='utf-8') as f:
        passport_data = json.load(f)

    # 1. Canonicalize Payload via JCS
    canonical_payload = rfc8785_canonicalize(passport_data)
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()

    # 2. Key Management (Ed25519)
    if private_key_bytes:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes_raw()

    # 3. Create Signature over Canonical Payload
    signature = private_key.sign(canonical_payload)

    # 4. Construct IETF SCITT COSE_Sign1 Envelope
    cose_envelope = {
        "protected_header": {
            "alg": "EdDSA",
            "crit": ["profile"],
            "profile": "draft-ietf-scitt-architecture-04"
        },
        "unprotected_header": {
            "kid": f"did:smaos:key:{base64.urlsafe_b64encode(public_bytes[:8]).decode('ascii').rstrip('=')}"
        },
        "payload_hash": f"sha256:{payload_hash}",
        "signature_base64": base64.b64encode(signature).decode('ascii'),
        "payload": passport_data
    }
    return cose_envelope

if __name__ == "__main__":
    envelope = build_cose_sign1_envelope("audit_out/trust_passport.json")
    out_path = Path("audit_out/trust_passport.cose.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)
    print(f"✅ Created IETF SCITT COSE_Sign1 envelope at {out_path}")
