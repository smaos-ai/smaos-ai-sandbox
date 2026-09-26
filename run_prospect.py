"""Automated Prospect Diagnostic Pipeline Driver with O(1) Accumulation."""
import argparse
import json
import hashlib
from pathlib import Path
from src.diagnostic_normalizer import normalize_stream
from src.diagnostic_report import generate_report
from src.accumulator import StateAccumulator

def calculate_risk_and_accumulate(normalized_path: Path, atv: float) -> tuple[dict, str]:
    """Calculates balance-sheet exposure and generates the O(1) state proof."""
    accumulator = StateAccumulator()
    unconfirmed = 0
    total = 0
    
    with normalized_path.open() as f:
        for line in f:
            if not line.strip(): continue
            row = json.loads(line)
            total += 1
            
            # O(1) Absorption
            # We canonicalize the JSON row to ensure deterministic hashing
            event_digest = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).digest()
            accumulator.absorb_event(event_digest)
            
            if row.get("disposition") == "DISPATCHED_UNCONFIRMED":
                unconfirmed += 1
    
    # 7-day rate extrapolated to annual risk
    weekly_exposure = unconfirmed * atv
    annual_exposure = weekly_exposure * 52.14
    
    risk = {
        "total_events": total,
        "unconfirmed_events": unconfirmed,
        "unconfirmed_rate": (unconfirmed / total) if total else 0.0,
        "weekly_exposure": weekly_exposure,
        "annual_exposure": annual_exposure
    }
    return risk, accumulator.get_session_proof()

def run_pipeline(raw_log: Path, customer: str, atv: float):
    artifacts_dir = Path("artifacts")
    reports_dir = Path("reports")
    artifacts_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)

    normalized_log = artifacts_dir / f"{customer.lower().replace(' ', '_')}.normalized.jsonl"
    report_out = reports_dir / f"{customer.lower().replace(' ', '_')}.execution_integrity_diagnostic.md"

    print(f"[*] Ingesting raw logs: {raw_log}")
    count = normalize_stream(str(raw_log), str(normalized_log))
    print(f"[+] Normalized {count} events -> {normalized_log}")

    # Risk Calculation + Accumulator Absorption
    risk, session_proof = calculate_risk_and_accumulate(normalized_log, atv)
    print(f"[!] Risk Calculated: {risk['unconfirmed_events']} ambiguous drops. Annual Exposure: €{risk['annual_exposure']:,.2f}")

    print("[*] Generating CISO Deliverable Report...")
    generate_report(raw_log, normalized_log, report_out, customer, workflows=None)
    
    # Append the O(1) proof to the CISO Markdown report
    with open(report_out, "a") as f:
        f.write(f"\n## Cryptographic Session Proof (O(1) Verification)\n")
        f.write(f"`{session_proof}`\n")

    print(f"[SUCCESS] O(1) Session Proof: {session_proof}")
    print(f"[SUCCESS] Client Report Generated: {report_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_log", type=Path)
    parser.add_argument("--customer", required=True)
    parser.add_argument("--atv", type=float, default=250.0, help="Average Transaction Value in EUR")
    args = parser.parse_args()
    run_pipeline(args.raw_log, args.customer, args.atv)
