"""
SMAOS Diagnostic Normalizer (Observe-Only Wedge)
Ingests heterogeneous customer agent logs, normalizes them into standard evidence schemas,
and computes SHA-256 evidence digests for cryptographic continuity.
"""

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: str
    principal_id: str
    task_scope: str
    intent_payload: Dict[str, Any]
    wire_status_code: int | None
    wire_error: str | None
    human_approval_present: bool
    evidence_digest: str

class DiagnosticNormalizer:
    @staticmethod
    def _compute_digest(data: dict) -> str:
        """Canonicalize and compute SHA-256 digest of the raw log entry."""
        jcs_bytes = json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
        return hashlib.sha256(jcs_bytes).hexdigest()

    @staticmethod
    def normalize_logs(raw_logs: List[Dict[str, Any]]) -> List[NormalizedEvent]:
        """
        Takes a list of unstructured/semi-structured customer logs and standardizes them.
        """
        normalized_events = []
        for log in raw_logs:
            # Simulated normalization logic (adapt to customer log shape)
            digest = DiagnosticNormalizer._compute_digest(log)
            
            event = NormalizedEvent(
                event_id=log.get("id", log.get("trace_id", "unknown")),
                timestamp=log.get("timestamp", "unknown_time"),
                principal_id=log.get("user", log.get("principal", "system")),
                task_scope=log.get("action", log.get("scope", "unknown_scope")),
                intent_payload=log.get("payload", log.get("args", {})),
                wire_status_code=log.get("http_status", log.get("status_code")),
                wire_error=log.get("error"),
                human_approval_present=bool(log.get("approved_by") or log.get("human_in_the_loop")),
                evidence_digest=digest
            )
            normalized_events.append(event)
            
        return normalized_events
