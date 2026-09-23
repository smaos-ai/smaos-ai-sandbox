"""Transport observer for agent tool calls.

Wraps a callable (the tool invocation) and classifies the outcome.
Updates the Intent Ledger from PENDING to UNKNOWN or CONFIRMED based on wire truth.
"""
import socket
from dataclasses import dataclass
from typing import Any, Callable, Optional
import requests
from src.intent_ledger import IntentLedger

@dataclass
class Observation:
    disposition: str
    http_status: Optional[int]
    error_type: Optional[str]
    error_message: Optional[str]
    dispatched: bool
    reason: str

UNKNOWN_STATUS_CODES = {500, 502, 503, 504}
REFUSED_STATUS_CODES = {401, 403, 409, 422, 429}

def observe_tool_call(
    fn: Callable[..., Any],
    intent_ledger: IntentLedger,
    intent_id: str,
    *args,
    **kwargs,
) -> tuple[Any, Observation]:
    try:
        result = fn(*args, **kwargs)
    except requests.Timeout as exc:
        obs = Observation("UNKNOWN", None, "Timeout", str(exc), True, "request dispatched, no response received")
        intent_ledger.resolve_intent(intent_id, "UNKNOWN")
        return None, obs
    except (requests.ConnectionError, ConnectionResetError, socket.error) as exc:
        obs = Observation("UNKNOWN", None, type(exc).__name__, str(exc), True, "connection reset or refused")
        intent_ledger.resolve_intent(intent_id, "UNKNOWN")
        return None, obs
    except Exception as exc:
        obs = Observation("UNKNOWN", None, type(exc).__name__, str(exc), False, "unclassified exception")
        intent_ledger.resolve_intent(intent_id, "UNKNOWN")
        return None, obs

    status = getattr(result, "status_code", None)
    if isinstance(result, dict) and status is None:
        status = result.get("status_code") or result.get("status")

    if status is None:
        obs = Observation("CONFIRMED", None, None, None, True, "callable yielded result without status")
        intent_ledger.resolve_intent(intent_id, "CONFIRMED")
        return result, obs

    if 200 <= status < 300:
        obs = Observation("CONFIRMED", status, None, None, True, f"HTTP {status}")
        intent_ledger.resolve_intent(intent_id, "CONFIRMED")
        return result, obs

    if status in UNKNOWN_STATUS_CODES:
        obs = Observation("UNKNOWN", status, None, None, True, f"HTTP {status}")
        intent_ledger.resolve_intent(intent_id, "UNKNOWN")
        return None, obs

    if status in REFUSED_STATUS_CODES:
        obs = Observation("REFUSED", status, None, None, True, f"HTTP {status} explicit refusal")
        intent_ledger.resolve_intent(intent_id, "REFUSED")
        return None, obs

    obs = Observation("INVALID_INPUT", status, None, None, False, f"HTTP {status} unrecognized")
    intent_ledger.resolve_intent(intent_id, "INVALID_INPUT")
    return None, obs

if __name__ == "__main__":
    ledger = IntentLedger()
    intent_id_504 = ledger.declare_intent("agent_01", "payments.execute", {"amount": 100})
    intent_id_200 = ledger.declare_intent("agent_01", "payments.execute", {"amount": 50})
    
    def _fake_504():
        class R:
            status_code = 504
        return R()

    def _fake_200():
        class R:
            status_code = 200
        return R()

    print("\n--- Testing 504 Transport Drop ---")
    _, obs1 = observe_tool_call(_fake_504, ledger, intent_id_504)
    print(f"Outcome: {obs1.disposition}")
    
    print("\n--- Testing 200 Success ---")
    _, obs2 = observe_tool_call(_fake_200, ledger, intent_id_200)
    print(f"Outcome: {obs2.disposition}")
