#!/usr/bin/env python3
import json
import hashlib
from pathlib import Path
import argparse

def generate_tabletop_bundle(timestamp_override=None):
    bundle = {
        "schema_version": "smaos.tabletop-scenario.v1",
        "scenario_id": "synthetic-post-write-timeout-v1",
        "provenance": "synthetic_test",
        "evidence_quality": "declared_fixture",
        "non_claims": [
            "not_a_network_capture",
            "not_a_customer_incident_record",
            "not_a_dora_submission",
            "not_an_external_effect_confirmation",
        ],
        "created_at_utc": timestamp_override or "2026-09-27T00:00:00Z",
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
    
    # Integrity identifier for this local synthetic file only.
    # This is an unkeyed SHA-256 digest, not a signature, Merkle proof,
    # independently verifiable receipt, or DORA evidence artifact.
    canonical = json.dumps(
        bundle,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    bundle["artifact_sha256"] = hashlib.sha256(canonical).hexdigest()
    
    out_path = Path("scratch/execution_integrity_tabletop_bundle.json")
    with out_path.open('w') as f:
        json.dump(bundle, f, indent=2)
        
    print(f"[+] Generated synthetic tabletop bundle: {out_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamp", help="Override the static timestamp")
    args = parser.parse_args()
    generate_tabletop_bundle(args.timestamp)
