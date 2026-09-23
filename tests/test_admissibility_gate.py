import pytest
from src.admissibility_gate import AdmissibilityGate

def test_unauthorized_scope_returns_block():
    gate = AdmissibilityGate()
    # Modify allowed_apis for test
    gate.allowed_apis = ["payments.read"]
    verdict = gate.evaluate("payments.execute", {})
    assert verdict == "DENY"
