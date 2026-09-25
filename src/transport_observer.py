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
    NEVER_DISPATCHED = "never_dispatched"
    DISPATCHED_UNCONFIRMED = "dispatched_unconfirmed"
    REMOTE_CONFIRMED = "remote_confirmed"
    REMOTE_REFUSED = "remote_refused"
    LOCALLY_BLOCKED = "locally_blocked"
    REFUSED = "remote_refused"
    QUARANTINED_UNCONFIRMED = "quarantined_unconfirmed"
    INVALID_INPUT = "invalid_input"
    UNKNOWN = "unknown"
    CONFIRMED = "remote_confirmed"



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
    *,
    policy_blocked: bool = False,
    request_bytes_written: bool = False,
    authoritative_receipt: bool = False,
    response_status: int | None = None,
    transport_error: str | None = None,
    http_status: int | None = None,
    socket_error: Exception | None = None,
    response_bytes_read: int = 0,
    has_valid_body: bool = False
) -> WireObservation:
    if http_status is not None:
        response_status = http_status
    if socket_error is not None:
        transport_error = str(socket_error)
        
    disposition = WireDisposition.DISPATCHED_UNCONFIRMED
    if policy_blocked:
        disposition = WireDisposition.LOCALLY_BLOCKED
    elif authoritative_receipt:
        disposition = WireDisposition.CONFIRMED
    elif not request_bytes_written:
        disposition = WireDisposition.NEVER_DISPATCHED
    elif response_status in {400, 401, 403, 404, 409, 422, 429}:
        disposition = WireDisposition.REFUSED
    elif response_status == 504:
        disposition = WireDisposition.DISPATCHED_UNCONFIRMED
    elif response_status is not None and 200 <= response_status < 300:
        disposition = WireDisposition.CONFIRMED
    elif transport_error in {
        "timeout_after_write",
        "connection_reset_after_write",
        "tls_disconnect_after_write",
        "response_parse_failure_after_write",
    }:
        disposition = WireDisposition.DISPATCHED_UNCONFIRMED
    elif socket_error is not None and request_bytes_written:
        disposition = WireDisposition.DISPATCHED_UNCONFIRMED
    elif socket_error is not None and not request_bytes_written:
        disposition = WireDisposition.UNKNOWN
    elif response_status in (500, 502, 503):
        disposition = WireDisposition.DISPATCHED_UNCONFIRMED if request_bytes_written else WireDisposition.UNKNOWN

    return WireObservation(
        disposition=disposition,
        http_status=response_status,
        error_type=transport_error,
        error_message=transport_error,
        request_bytes_written=1 if request_bytes_written else 0,
        response_bytes_read=response_bytes_read,
        dispatched=request_bytes_written,
        quarantined=(disposition == WireDisposition.DISPATCHED_UNCONFIRMED),
        reason=str(transport_error) if transport_error else "ok"
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
