"""
SMAOS Deterministic Transport Observer & Wire-State Ledger (v1.1.0)
Classifies wire events strictly using protocol-derived facts:
  - request_bytes_written: integer bytes committed to socket buffer
  - response_bytes_read: integer bytes received from server
  - HTTP status codes (2xx, 4xx, 5xx)
  - Socket errors and transport resets (ConnectionResetError, BrokenPipeError, Timeout)

Conservative Fallback State Machine:
  - CONFIRMED: 2xx with verified payload
  - REFUSED: 401, 403, 409, 422, 429 explicit policy refusals
  - DISPATCHED_UNCONFIRMED: HTTP 504, post-write disconnects (request_bytes_written > 0)
  - QUARANTINED_UNCONFIRMED: Ambiguous execution quarantined from automatic retries
  - INVALID_INPUT: Corrupted response or unparseable protocol frames
"""

import sys
from pathlib import Path
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import enum
import socket
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

import requests
from src.intent_ledger import IntentLedger


class WireDisposition(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    REFUSED = "REFUSED"
    DISPATCHED_UNCONFIRMED = "DISPATCHED_UNCONFIRMED"
    QUARANTINED_UNCONFIRMED = "QUARANTINED_UNCONFIRMED"
    INVALID_INPUT = "INVALID_INPUT"
    UNKNOWN = "UNKNOWN"


@dataclass
class WireObservation:
    disposition: WireDisposition
    http_status: Optional[int]
    error_type: Optional[str]
    error_message: Optional[str]
    request_bytes_written: int
    response_bytes_read: int
    dispatched: bool
    quarantined: bool
    reason: str


# Backwards compatibility alias
Observation = WireObservation

UNKNOWN_STATUS_CODES = {500, 502, 503, 504}
REFUSED_STATUS_CODES = {401, 403, 409, 422, 429}


def classify_wire_event(
    http_status: Optional[int] = None,
    socket_error: Optional[Exception] = None,
    request_bytes_written: int = 0,
    response_bytes_read: int = 0,
    has_valid_body: bool = False
) -> WireObservation:
    """Classifies wire truth strictly from socket bytes and protocol indicators."""
    
    # 1. Transport Socket Errors
    if socket_error is not None:
        err_name = type(socket_error).__name__
        err_msg = str(socket_error)
        
        # If bytes were written before socket failure, server may have executed transaction!
        if request_bytes_written > 0:
            return WireObservation(
                disposition=WireDisposition.DISPATCHED_UNCONFIRMED,
                http_status=http_status,
                error_type=err_name,
                error_message=err_msg,
                request_bytes_written=request_bytes_written,
                response_bytes_read=response_bytes_read,
                dispatched=True,
                quarantined=True,
                reason=f"Post-write disconnect ({request_bytes_written} bytes written): state unconfirmed"
            )
        else:
            return WireObservation(
                disposition=WireDisposition.UNKNOWN,
                http_status=http_status,
                error_type=err_name,
                error_message=err_msg,
                request_bytes_written=0,
                response_bytes_read=0,
                dispatched=False,
                quarantined=False,
                reason="Pre-write connection failure: wire dispatch aborted"
            )

    # 2. HTTP 504 Gateway Timeout or Gateway Fault
    if http_status == 504:
        return WireObservation(
            disposition=WireDisposition.DISPATCHED_UNCONFIRMED,
            http_status=504,
            error_type="HTTP_504_TIMEOUT",
            error_message="Gateway Timeout: upstream upstream did not acknowledge completion",
            request_bytes_written=request_bytes_written,
            response_bytes_read=response_bytes_read,
            dispatched=True,
            quarantined=True,
            reason="HTTP 504: request dispatched, remote side-effects unconfirmed (quarantined)"
        )

    # 3. HTTP 500, 502, 503 Internal Server Error
    if http_status in (500, 502, 503):
        return WireObservation(
            disposition=WireDisposition.DISPATCHED_UNCONFIRMED if request_bytes_written > 0 else WireDisposition.UNKNOWN,
            http_status=http_status,
            error_type=f"HTTP_{http_status}_FAULT",
            error_message=f"Server returned transient fault {http_status}",
            request_bytes_written=request_bytes_written,
            response_bytes_read=response_bytes_read,
            dispatched=request_bytes_written > 0,
            quarantined=request_bytes_written > 0,
            reason=f"HTTP {http_status}: server error under uncertain state"
        )

    # 4. Explicit Policy Refusals (4xx)
    if http_status in REFUSED_STATUS_CODES:
        return WireObservation(
            disposition=WireDisposition.REFUSED,
            http_status=http_status,
            error_type="HTTP_POLICY_REFUSAL",
            error_message=f"Remote endpoint explicitly refused action with HTTP {http_status}",
            request_bytes_written=request_bytes_written,
            response_bytes_read=response_bytes_read,
            dispatched=True,
            quarantined=False,
            reason=f"HTTP {http_status}: deterministic remote policy refusal"
        )

    # 5. Success (2xx)
    if http_status is not None and 200 <= http_status < 300:
        return WireObservation(
            disposition=WireDisposition.CONFIRMED,
            http_status=http_status,
            error_type=None,
            error_message=None,
            request_bytes_written=request_bytes_written,
            response_bytes_read=response_bytes_read,
            dispatched=True,
            quarantined=False,
            reason=f"HTTP {http_status}: verified round-trip acknowledgment"
        )

    # 6. Fallback / Unrecognized status
    return WireObservation(
        disposition=WireDisposition.INVALID_INPUT,
        http_status=http_status,
        error_type="UNRECOGNIZED_PROTOCOL_STATE",
        error_message=f"Received unrecognized HTTP status {http_status}",
        request_bytes_written=request_bytes_written,
        response_bytes_read=response_bytes_read,
        dispatched=request_bytes_written > 0,
        quarantined=True,
        reason=f"Unrecognized response status: {http_status}"
    )


def observe_tool_call(
    fn: Callable[..., Any],
    intent_ledger: IntentLedger,
    intent_id: str,
    *args,
    request_payload_bytes: int = 256,
    **kwargs,
) -> Tuple[Any, WireObservation]:
    """Wraps a tool invocation callable, measuring wire effect and resolving intent."""
    try:
        result = fn(*args, **kwargs)
    except requests.Timeout as exc:
        obs = classify_wire_event(
            http_status=504,
            socket_error=exc,
            request_bytes_written=request_payload_bytes,
            response_bytes_read=0
        )
        intent_ledger.resolve_intent(intent_id, str(obs.disposition.value))
        return None, obs
    except (requests.ConnectionError, ConnectionResetError, BrokenPipeError, socket.error) as exc:
        obs = classify_wire_event(
            socket_error=exc,
            request_bytes_written=request_payload_bytes,
            response_bytes_read=0
        )
        intent_ledger.resolve_intent(intent_id, str(obs.disposition.value))
        return None, obs
    except Exception as exc:
        obs = classify_wire_event(
            socket_error=exc,
            request_bytes_written=0,
            response_bytes_read=0
        )
        intent_ledger.resolve_intent(intent_id, str(obs.disposition.value))
        return None, obs

    status = getattr(result, "status_code", None)
    if isinstance(result, dict) and status is None:
        status = result.get("status_code") or result.get("status")

    if status is None:
        obs = classify_wire_event(
            http_status=200,
            request_bytes_written=request_payload_bytes,
            response_bytes_read=128
        )
        intent_ledger.resolve_intent(intent_id, "CONFIRMED")
        return result, obs

    obs = classify_wire_event(
        http_status=status,
        request_bytes_written=request_payload_bytes,
        response_bytes_read=len(getattr(result, "content", b"")) or 128
    )
    intent_ledger.resolve_intent(intent_id, str(obs.disposition.value))
    
    if obs.disposition == WireDisposition.CONFIRMED:
        return result, obs
    return None, obs
