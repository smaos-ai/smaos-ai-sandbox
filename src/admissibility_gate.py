"""Behavioral Governance: The Admissibility Gate.

Evaluates the pre-declared intent against the delegation ceiling.
Returns ALLOW, BLOCK, or ESCALATE (EU AI Act Art 14 Human Oversight).
"""
import json
from typing import Dict, Any

class AdmissibilityVerdict:
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"

class AdmissibilityGate:
    def __init__(self, passport_path: str = "audit_out/trust_passport.json"):
        self.passport = {}
        try:
            with open(passport_path, 'r') as f:
                self.passport = json.load(f)
        except Exception:
            self.passport = {}

        authority = self.passport.get("authority", {})
        self.allowed_apis = authority.get("action_scope") or authority.get("permitted") or [
            "payments.execute", "audit.write", "POST /v1/settle", "GET /v1/status"
        ]
        self.max_limit_minor = (
            authority.get("max_limit_minor")
            or authority.get("constraints", {}).get("max_amount_eur", 50000) * 100
            or 5000000
        )

    def evaluate(self, target_api: str, payload: Dict[str, Any]) -> str:
        """
        Evaluate intent against delegation ceiling.
        - BLOCK: Agent attempts to access an unauthorized API.
        - ESCALATE: Action exceeds financial risk threshold (EU AI Act Art 14).
        - ALLOW: Action is within mandate.
        """
        if target_api not in self.allowed_apis:
            return "BLOCK"

        amount = payload.get("amount_minor", 0)
        if amount == 0 and "amount" in payload:
            amount = int(payload["amount"] * 100)

        if amount > self.max_limit_minor:
            return "ESCALATE"

        return "ALLOW"

if __name__ == "__main__":
    gate = AdmissibilityGate()
    print("Normal:", gate.evaluate("payments.execute", {"amount_minor": 10000}))
    print("Overlimit:", gate.evaluate("payments.execute", {"amount_minor": 20000000}))
    print("Unauthorized:", gate.evaluate("system.escalate_privileges", {}))
