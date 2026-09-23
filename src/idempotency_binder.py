"""Idempotency Key Generator for Agent Tool Calls.

Generates cryptographically deterministic UUIDv5 keys based on:
  1. The Agent Session ID
  2. The Sequence Number (iteration of the tool call)
  3. The RFC 8785 canonical hash of the payload

This ensures that retries of the exact same payload within the same
sequence state will yield the same Idempotency-Key header, preventing
downstream double-execution even if the transport layer drops the ACK.
"""
import uuid
from typing import Any
from src.canonicalizer import digest

# A dedicated namespace UUID for SMAOS Idempotency Binding
SMAOS_NAMESPACE = uuid.UUID("f3b2b8c9-0a14-49c8-9d62-111111111111")

def generate_idempotency_key(session_id: str, sequence_number: int, payload: Any) -> str:
    """Generate a deterministic UUIDv5 idempotency key.
    
    Args:
        session_id: The unique identifier for the current agent session.
        sequence_number: The monotonic counter for agent actions.
        payload: The JSON-serializable dictionary representing the tool call parameters.
        
    Returns:
        A string representation of the UUIDv5 key.
    """
    payload_hash = digest(payload)
    
    # Concatenate the binding elements deterministically
    binding_string = f"{session_id}:{sequence_number}:{payload_hash}"
    
    # Generate the UUIDv5
    idemp_key = uuid.uuid5(SMAOS_NAMESPACE, binding_string)
    
    return str(idemp_key)

def bind_headers(headers: dict, session_id: str, sequence_number: int, payload: Any) -> dict:
    """Mutate and return the headers dictionary with the 'Idempotency-Key' injected."""
    key = generate_idempotency_key(session_id, sequence_number, payload)
    headers["Idempotency-Key"] = key
    return headers


if __name__ == "__main__":
    session = "sess_9942_abc"
    seq = 4
    payload_v1 = {
        "action": "transfer",
        "amount_minor": 50000,
        "currency": "EUR",
        "destination": "CZ6508000000001234567890"
    }
    
    # 1. Generate key for the first attempt
    key1 = generate_idempotency_key(session, seq, payload_v1)
    print(f"Attempt 1 (Original): {key1}")
    
    # 2. Generate key for a retry (same session, same seq, same payload)
    key2 = generate_idempotency_key(session, seq, payload_v1)
    print(f"Attempt 2 (Retry)   : {key2}")
    
    # 3. Generate key for a mutated payload retry (malicious or hallucinated mutation)
    payload_mutated = payload_v1.copy()
    payload_mutated["amount_minor"] = 50001
    key3 = generate_idempotency_key(session, seq, payload_mutated)
    print(f"Attempt 3 (Mutated) : {key3}")
    
    # 4. Generate key for the NEXT legitimate action (sequence + 1)
    key4 = generate_idempotency_key(session, seq + 1, payload_v1)
    print(f"Attempt 4 (Next Seq): {key4}")
    
    assert key1 == key2, "Idempotency failed: Retry keys must match"
    assert key1 != key3, "Binding failed: Mutated payload must generate different key"
    assert key1 != key4, "Binding failed: New sequence must generate different key"
    print("✅ All idempotency binding assertions passed.")
