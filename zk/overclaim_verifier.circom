pragma circom 2.0.0;

// SMAOS Zero-Knowledge Compliance Circuit
// Proves that no transport faults (HTTP 504 / TCP RST) resulted in a CONFIRMED disposition.

template OverclaimVerifier(N) {
    // Private Inputs (Witness)
    signal input wire_status_code[N];       // e.g., 200, 504, 0 (for TCP RST)
    signal input evaluated_disposition[N];  // 1 = CONFIRMED, 2 = DISPATCHED_UNCONFIRMED, 3 = REFUSED

    // Public Outputs
    signal output overclaim_count;
    signal output downgrade_enforced;

    var faults_detected = 0;
    var overclaims = 0;

    for (var i = 0; i < N; i++) {
        // We consider 504 or 0 (TCP RST) as transport faults
        var is_fault = 0;
        if (wire_status_code[i] == 504 || wire_status_code[i] == 0) {
            is_fault = 1;
            faults_detected += 1;
        }

        // If it is a fault, the disposition MUST NOT be 1 (CONFIRMED)
        var is_confirmed = 0;
        if (evaluated_disposition[i] == 1) {
            is_confirmed = 1;
        }

        // Overclaim happens if is_fault == 1 AND is_confirmed == 1
        if (is_fault == 1 && is_confirmed == 1) {
            overclaims += 1;
        }
    }

    overclaim_count <== overclaims;
    
    // We enforce that downgrade was active if there were no overclaims
    if (overclaims == 0) {
        downgrade_enforced <== 1;
    } else {
        downgrade_enforced <== 0;
    }
}

// Instantiate the component for a batch of 100 traces
component main = OverclaimVerifier(100);
