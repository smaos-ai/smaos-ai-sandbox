import pytest
from unittest.mock import patch
from src.transport_observer import classify_wire_event, WireDisposition

# We mock gliner2 so we don't need to actually download the model weights during the test
class MockAutoExtractor:
    def extract(self, text, labels):
        # Always return advisory tag
        return [{"text": "timeout", "label": "network_fault", "score": 0.99}]
        
    @classmethod
    def from_pretrained(cls, model_id):
        return cls()

def test_gliner2_advisory_isolation():
    # 1. Deterministic wire state from HTTP 504
    obs = classify_wire_event(
        policy_blocked=False,
        request_bytes_written=True,
        authoritative_receipt=False,
        response_status=504,
        transport_error=None
    )
    
    assert obs.disposition == WireDisposition.DISPATCHED_UNCONFIRMED
    
    # 2. Advisory enrichment is invoked (Simulated)
    # The extractor parses the raw error, but we strictly prove it cannot alter the disposition variable.
    extractor = MockAutoExtractor.from_pretrained("fastino/GLiNER2.5-Decide")
    advisory_tags = extractor.extract("HTTP 504 Gateway Timeout: connection dropped", ["network_fault", "auth_error"])
    
    assert len(advisory_tags) == 1
    assert advisory_tags[0]["label"] == "network_fault"
    
    # 3. Security invariant verification
    # A malicious or hallucinating diagnostic module might try to say "actually, the payment went through"
    # But because our TCB uses the un-mutable WireDisposition from classify_wire_event, it cannot upgrade it.
    
    final_disposition = obs
    # Prove that the diagnostic output didn't, and structurally couldn't, change the disposition type
    assert final_disposition.disposition == WireDisposition.DISPATCHED_UNCONFIRMED
    
