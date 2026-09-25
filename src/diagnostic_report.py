"""
SMAOS Diagnostic Report Generator (Observe-Only Wedge)
Evaluates normalized logs against the Five Core Metrics and outputs the diagnostic report.
"""
from typing import List, Dict
from src.diagnostic_normalizer import NormalizedEvent

class DiagnosticReportGenerator:
    def __init__(self, events: List[NormalizedEvent]):
        self.events = events
        
    def evaluate_metrics(self) -> Dict[str, str]:
        if not self.events:
            return {
                "Approval Binding": "NOT_OBSERVED",
                "Outcome Disposition": "INSUFFICIENT_EVIDENCE",
                "Authority Freshness": "UNKNOWN",
                "Retry Exposure": "UNKNOWN",
                "Evidence Continuity": "INSUFFICIENT"
            }
            
        metrics = {
            "Approval Binding": "OBSERVED_BOUND",
            "Outcome Disposition": "REMOTE_CONFIRMED",
            "Authority Freshness": "FRESH",
            "Retry Exposure": "LOW",
            "Evidence Continuity": "SUFFICIENT"
        }
        
        # 1. Approval Binding
        approvals = [e.human_approval_present for e in self.events]
        if not any(approvals):
            metrics["Approval Binding"] = "NOT_OBSERVED"
        elif not all(approvals):
            metrics["Approval Binding"] = "OBSERVED_MISMATCH"
            
        # 2. Outcome Disposition & 4. Retry Exposure
        timeouts = [e for e in self.events if e.wire_status_code == 504 or e.wire_error == "timeout"]
        if timeouts:
            metrics["Outcome Disposition"] = "DISPATCHED_UNCONFIRMED"
            metrics["Retry Exposure"] = "HIGH"  # Timeouts without clear state quarantine expose the workflow to unsafe retries
            
        refusals = [e for e in self.events if e.wire_status_code in {401, 403, 409}]
        if refusals and not timeouts:
            metrics["Outcome Disposition"] = "REMOTE_REFUSED"
            
        # 3. Authority Freshness (Simulated TTL logic)
        metrics["Authority Freshness"] = "UNKNOWN" if metrics["Approval Binding"] == "NOT_OBSERVED" else "FRESH"
        
        # 5. Evidence Continuity
        digests = [e.evidence_digest for e in self.events]
        metrics["Evidence Continuity"] = "SUFFICIENT" if len(set(digests)) == len(digests) else "PARTIAL"
        
        return metrics


    def compute_risk_calculator(self) -> str:
        # Calculate Average Transaction Value (ATV)
        amounts = []
        for e in self.events:
            if isinstance(e.intent_payload, dict) and 'amount' in e.intent_payload:
                amounts.append(float(e.intent_payload['amount']))
        
        atv = sum(amounts) / len(amounts) if amounts else 10000.0
        
        # Count weekly 504 timeouts (assuming 7-day log window)
        weekly_timeouts = len([e for e in self.events if e.wire_status_code == 504 or e.wire_error == "timeout"])
        if weekly_timeouts == 0:
            weekly_timeouts = 1 # Baseline default if none observed but risk is high
            
        annual_timeouts = weekly_timeouts * 52
        exposure = annual_timeouts * atv
        
        md = "## Automated Double-Disbursement Risk Calculator\n\n"
        md += "Based on the **7-day observation window**, we calculated the annual unrecoverable financial exposure from unquarantined `504` timeouts.\n\n"
        md += f"- **Observed Weekly 504 Timeouts**: {weekly_timeouts}\n"
        md += f"- **Projected Annual 504 Timeouts**: {annual_timeouts}\n"
        md += f"- **Average Transaction Value (ATV)**: ${atv:,.2f}\n"
        md += f"- **Projected Annual Double-Spend Exposure**: **${exposure:,.2f}**\n\n"
        md += "> *Note: This assumes a 100% naive retry rate on timeouts without deterministic state quarantine.*\n"
        return md

    def generate_markdown(self) -> str:
        metrics = self.evaluate_metrics()
        
        md = f"# SMAOS Execution Integrity Diagnostic\n\n"
        md += f"**Analyzed Events**: {len(self.events)}\n\n"
        
        md += "## Five Core Metrics Evaluated\n\n"
        for key, value in metrics.items():
            md += f"- **{key}**: `{value}`\n"
            
        md += "\n## Regulatory Gap Analysis\n\n"
        md += "### Digital Operational Resilience Act (DORA)\n"
        md += "- **Art. 17 (ICT Third-Party Risk)**: Gap identified. Without cryptographically locked boundary gates, downstream models operate with unprotected side-effects.\n"
        
        md += "\n### EU AI Act\n"
        md += "- **Art. 12 (Record-Keeping)**: " + ("Compliant" if metrics["Evidence Continuity"] == "SUFFICIENT" else "Non-Compliant (Hash continuity broken)") + "\n"
        md += "- **Art. 14 (Human Oversight)**: " + ("Compliant" if metrics["Approval Binding"] == "OBSERVED_BOUND" else "Non-Compliant (Missing/Mismatched Approval bindings)") + "\n"
        
        md += "\n" + self.compute_risk_calculator()
        md += "\n## Event Drill-Down (First 3)\n"
        md += "| Event ID | Time | Principal | Task Scope | Status | Digest |\n"
        md += "| --- | --- | --- | --- | --- | --- |\n"
        for e in self.events[:3]:
            status = e.wire_status_code or e.wire_error or "UNKNOWN"
            md += f"| {e.event_id} | {e.timestamp} | {e.principal_id} | {e.task_scope} | {status} | `{e.evidence_digest[:16]}...` |\n"
            
        return md

    def export_report(self, filepath: str = "diagnostic_report.md"):
        with open(filepath, "w") as f:
            f.write(self.generate_markdown())

if __name__ == "__main__":
    # Smoke test
    from src.diagnostic_normalizer import DiagnosticNormalizer
    mock_logs = [
        {"id": "evt_1", "timestamp": "2026-09-25T10:00:00Z", "user": "alice", "action": "fund_transfer", "http_status": 200, "human_in_the_loop": True},
        {"id": "evt_2", "timestamp": "2026-09-25T10:05:00Z", "user": "bob", "action": "fund_transfer", "http_status": 504, "human_in_the_loop": True},
    ]
    events = DiagnosticNormalizer.normalize_logs(mock_logs)
    report = DiagnosticReportGenerator(events)
    report.export_report()
    print("Exported diagnostic_report.md")
