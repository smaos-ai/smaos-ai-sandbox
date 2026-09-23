import pytest
from src.admissibility_gate import AdmissibilityGate

def test_unauthorized_scope_returns_block():
    gate = AdmissibilityGate()
    gate.allowed_apis = ["payments.read"]
    verdict = gate.evaluate("payments.execute", {})
    assert verdict == "BLOCK"

def test_authorized_scope_within_ceiling_returns_allow():
    gate = AdmissibilityGate()
    gate.allowed_apis = ["payments.execute"]
    gate.max_limit_minor = 5000000
    verdict = gate.evaluate("payments.execute", {"amount_minor": 100000})
    assert verdict == "ALLOW"

def test_exceeding_ceiling_returns_escalate():
    gate = AdmissibilityGate()
    gate.allowed_apis = ["payments.execute"]
    gate.max_limit_minor = 5000000
    verdict = gate.evaluate("payments.execute", {"amount_minor": 9000000})
    assert verdict == "ESCALATE"
