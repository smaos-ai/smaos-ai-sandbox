#!/usr/bin/env python3
import json
import hashlib
from datetime import datetime
from pathlib import Path

def generate_tabletop_bundle():
    bundle = {
        "diagnostic_id": "diag-1a2b3c",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "provenance": "synthetic_test",
        "metrics": {
            "approval_binding": "FAIL",
            "retry_exposure": "CRITICAL",
            "authority_freshness": "PASS",
            "evidence_continuity": "PARTIAL"
        },
        "event_ladder": [
            {
                "step": "authorization",
                "state": "approved",
                "action": "execute_wire_transfer"
            },
            {
                "step": "dispatch",
                "state": "dispatched_unconfirmed",
                "network_response": "504 Gateway Timeout"
            },
            {
                "step": "reconciliation",
                "state": "required",
                "observation": "Agent SDK initiated automatic retry without idempotency check."
            }
        ]
    }
    
    # Generate O(1) Session Proof (SHA-256 cascade simulation)
    bundle_str = json.dumps(bundle, sort_keys=True).encode('utf-8')
    session_proof = hashlib.sha256(bundle_str).hexdigest()
    bundle["session_proof"] = f"smos_acc:1:{session_proof}"
    
    out_path = Path("scratch/dora_tabletop_bundle.json")
    with out_path.open('w') as f:
        json.dump(bundle, f, indent=2)
        
    print(f"[+] Generated synthetic diagnostic bundle: {out_path}")

if __name__ == "__main__":
    generate_tabletop_bundle()
