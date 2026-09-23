"""Transport observer for agent tool calls.

Wraps a callable (the tool invocation) and classifies the outcome into
one of four dispositions:

  CONFIRMED     - downstream returned an explicit success signal
  REFUSED       - downstream returned an explicit refusal
  UNKNOWN       - transport failure after dispatch; effect unconfirmed
  INVALID_INPUT - the call could not be dispatched

This module does NOT prevent the underlying SDK from seeing transport
exceptions. It prevents the calling code from misclassifying them.
"""
import socket
from dataclasses import dataclass
from typing import Any, Callable, Optional

import requests


@dataclass
class Observation:
    disposition: str
    http_status: Optional[int]
    error_type: Optional[str]
    error_message: Optional[str]
    dispatched: bool
    reason: str


# Status codes that mean "the request reached the server, the server
# accepted it, but the response is not a business confirmation."
# Treat these as UNKNOWN, never as CONFIRMED.
UNKNOWN_STATUS_CODES = {500, 502, 503, 504}

# Status codes that mean the downstream explicitly refused.
REFUSED_STATUS_CODES = {401, 403, 409, 422, 429}


def observe_tool_call(
    fn: Callable[..., Any],
    /,
    *args,
    **kwargs,
) -> tuple[Any, Observation]:
    """Execute `fn(*args, **kwargs)` and classify the outcome.

    Returns (result, observation). `result` is None when the call did not
    produce a business confirmation. The caller must not treat None as
    success.
    """
    try:
        result = fn(*args, **kwargs)
    except requests.Timeout as exc:
        return None, Observation(
            disposition="UNKNOWN",
            http_status=None,
            error_type="Timeout",
            error_message=str(exc),
            dispatched=True,
            reason="request dispatched, no response received",
        )
    except (requests.ConnectionError, ConnectionResetError, socket.error) as exc:
        return None, Observation(
            disposition="UNKNOWN",
            http_status=None,
            error_type=type(exc).__name__,
            error_message=str(exc),
            dispatched=True,
            reason="connection reset or refused by transport layer",
        )
    except Exception as exc:
        # Unknown exception: treat as unclassified, never as success.
        return None, Observation(
            disposition="UNKNOWN",
            http_status=None,
            error_type=type(exc).__name__,
            error_message=str(exc),
            dispatched=False,
            reason="unclassified exception before any disposition was observed",
        )

    status = _extract_status(result)

    if status is None:
        return result, Observation(
            disposition="CONFIRMED",
            http_status=None,
            error_type=None,
            error_message=None,
            dispatched=True,
            reason="callable returned without raising and yielded a result",
        )

    if 200 <= status < 300:
        return result, Observation(
            disposition="CONFIRMED",
            http_status=status,
            error_type=None,
            error_message=None,
            dispatched=True,
            reason=f"HTTP {status} from downstream",
        )

    if status in UNKNOWN_STATUS_CODES:
        return None, Observation(
            disposition="UNKNOWN",
            http_status=status,
            error_type=None,
            error_message=None,
            dispatched=True,
            reason=f"HTTP {status} means the server did not confirm the effect",
        )

    if status in REFUSED_STATUS_CODES:
        return None, Observation(
            disposition="REFUSED",
            http_status=status,
            error_type=None,
            error_message=None,
            dispatched=True,
            reason=f"HTTP {status} is an explicit downstream refusal",
        )

    return None, Observation(
        disposition="INVALID_INPUT",
        http_status=status,
        error_type=None,
        error_message=None,
        dispatched=False,
        reason=f"HTTP {status} is outside the recognized classification set",
    )


def _extract_status(result: Any) -> Optional[int]:
    """Return the HTTP status code if the result exposes one."""
    status = getattr(result, "status_code", None)
    if isinstance(status, int):
        return status
    if isinstance(result, dict):
        s = result.get("status_code") or result.get("status")
        if isinstance(s, int):
            return s
    return None


if __name__ == "__main__":
    def _fake_504():
        class R:
            status_code = 504
        return R()

    def _fake_200():
        class R:
            status_code = 200
            body = {"settled": True}
        return R()

    for name, fn in [("504", _fake_504), ("200", _fake_200)]:
        result, obs = observe_tool_call(fn)
        print(f"{name}: disposition={obs.disposition} reason={obs.reason}")
