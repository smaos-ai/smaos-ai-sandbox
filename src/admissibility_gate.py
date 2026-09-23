"""Behavioral Governance: The Admissibility Gate.

Evaluates the pre-declared intent against the delegation ceiling.
Returns ALLOW, DENY, or AWAITING_HUMAN (EU AI Act Art 14).
"""
import json
from typing import Dict, Any

class AdmissibilityGate:
    def __init__(self, passport_path: str = "audit_out/trust_passport.json"):
        try:
            with open(passport_path, 'r') as f:
                self.passport = json.load(f)
        except FileNotFoundError:
            # Fallback if passport hasn't been generated yet
            self.passport = {
                "authority": {
                    "action_scope": ["payments.execute", "audit.write"],
                    "max_limit_minor": 50000
                }
            }
        
        self.allowed_apis = self.passport.get("authority", {}).get("action_scope", [])
        self.max_limit_minor = self.passport.get("authority", {}).get("max_limit_minor", 0)

    def evaluate(self, target_api: str, payload: Dict[str, Any]) -> str:
        """
        Evaluate intent against delegation ceiling.
        - DENY: Agent attempts to access an unauthorized API.
        - AWAITING_HUMAN: Action exceeds financial risk threshold.
        - ALLOW: Action is within mandate.
        """
        if target_api not in self.allowed_apis:
            print(f"[X] GATE DENY: Unauthorized target {target_api}")
            return "DENY"
            
        amount = payload.get("amount_minor", 0)
        if amount > self.max_limit_minor:
            print(f"[!] GATE AWAITING_HUMAN: Amount {amount} exceeds ceiling {self.max_limit_minor}")
            return "AWAITING_HUMAN"
            
        print(f"[+] GATE ALLOW: Action admissible.")
        return "ALLOW"

if __name__ == "__main__":
    gate = AdmissibilityGate()
    
    # 1. Normal execution
    gate.evaluate("payments.execute", {"amount_minor": 10000})
    
    # 2. Exceeds financial threshold (Art 14 Human-in-the-loop)
    gate.evaluate("payments.execute", {"amount_minor": 200000})
    
    # 3. Unauthorized API lateral movement
    gate.evaluate("system.escalate_privileges", {"amount_minor": 0})
