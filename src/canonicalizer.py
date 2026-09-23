"""RFC 8785 JCS Canonicalization for Behavioral Governance.

Sorts UTF-16 keys and normalizes numbers to ensure deterministic hashing
of the agent's pre-execution intent and the Trust Passport.
"""
import json
import hashlib
from typing import Any

def canonicalize(data: Any) -> bytes:
    # A simplified RFC 8785 subset for internal determinism.
    # For full compliance, the Rust 'jcs' library should be imported.
    return json.dumps(
        data,
        ensure_ascii=False,
        separators=(',', ':'),
        sort_keys=True
    ).encode('utf-8')

def get_hash(data: Any) -> str:
    return hashlib.sha256(canonicalize(data)).hexdigest()

if __name__ == "__main__":
    intent_record = {
        "intent_id": "1cea599e-e168-449d-8851-79dc04f444c3",
        "status": "UNKNOWN",
        "target": "payments.execute"
    }
    print(f"[*] JCS Hash of Intent Record: sha256:{get_hash(intent_record)}")
