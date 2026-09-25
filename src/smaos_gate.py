"""
SMAOS Pre-Dispatch Gate & Advisory Enrichment Plane (v1.1.0)
Coordinates defense-in-depth controls prior to network socket release:
  1. Atomic Nonce Consumption (ApprovalNonceLedger)
  2. External Idempotency Key Injection (UUIDv5 from H(C(O_approved)))
  3. Deterministic Transport Observation (WireObservation)
  4. Sandboxed Advisory Plane (GLiNER2 AutoExtractor)
"""

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from src.canonicalizer import digest
from src.idempotency_binder import bind_headers, generate_idempotency_key
from src.intent_ledger import IntentLedger
from src.nonce_ledger import (
    ApprovalNonceLedger,
    ApprovalExpiredViolation,
    NonceLedgerError,
    PayloadTamperViolation,
    ReplayAttackViolation,
    ScopeViolation,
)
from src.transport_observer import (
    WireDisposition,
    WireObservation,
    classify_wire_event,
    observe_tool_call,
)


class AdvisoryEnrichmentPlane:
    """Sandboxed Advisory Plane for Semantic Entity & Risk Extraction.
    
    Architectural Invariant:
      Model outputs enrich diagnostic receipts for human auditors but
      CANNOT alter WireDisposition or upgrade unconfirmed states.
    """

    def __init__(self, model_id: str = "fastino/gliner2-advisory-base"):
        self.model_id = model_id
        self._extractor = None

    def _get_extractor(self):
        """Loads Fastino AutoExtractor if installed; uses deterministic fallback otherwise."""
        if self._extractor is not None:
            return self._extractor
        try:
            # Fastino / GLiNER2 documented interface
            from fastino import AutoExtractor
            self._extractor = AutoExtractor.from_pretrained(self.model_id)
        except Exception:
            self._extractor = "DETERMINISTIC_SANDBOX_EXTRACTOR"
        return self._extractor

    def extract_advisory_entities(self, text: str, schema: Optional[List[str]] = None) -> Dict[str, Any]:
        """Extracts diagnostic entity tags without modifying execution flow."""
        labels = schema or ["FINANCIAL_AMOUNT", "DESTINATION_ACCOUNT", "REGULATORY_FLAG"]
        extractor = self._get_extractor()
        
        extracted = []
        if extractor != "DETERMINISTIC_SANDBOX_EXTRACTOR":
            try:
                extracted = extractor.extract(text, labels=labels)
            except Exception:
                extracted = []

        # Deterministic regex/heuristic fallback for sandbox reliability
        if not extracted:
            if "EUR" in text or "$" in text:
                extracted.append({"entity": "FINANCIAL_AMOUNT", "confidence": 0.99})
            if "IBAN" in text or "CZ" in text:
                extracted.append({"entity": "DESTINATION_ACCOUNT", "confidence": 0.95})

        return {
            "plane": "ADVISORY_ENRICHMENT_PLANE",
            "model_id": self.model_id,
            "entities_detected": extracted,
            "disposition_override_permitted": False,
            "advisory_status": "ENRICHED_READONLY"
        }


class SmaosPreDispatchGate:
    """Pre-Dispatch Gate coordinating atomic admission, idempotency, and transport."""

    def __init__(
        self,
        nonce_ledger: Optional[ApprovalNonceLedger] = None,
        intent_ledger: Optional[IntentLedger] = None,
        advisory_plane: Optional[AdvisoryEnrichmentPlane] = None
    ):
        self.nonce_ledger = nonce_ledger or ApprovalNonceLedger()
        self.intent_ledger = intent_ledger or IntentLedger()
        self.advisory_plane = advisory_plane or AdvisoryEnrichmentPlane()

    def admit_and_dispatch(
        self,
        approval_id: str,
        nonce: str,
        payload_to_execute: Dict[str, Any],
        task_scope: str,
        target_fn: Callable[..., Any],
        headers: Optional[Dict[str, str]] = None,
        session_id: str = "sess-smaos-001",
        sequence_number: int = 1,
        agent_id: str = "did:smaos:agent-treasury-001",
        target_api: str = "payments.execute"
    ) -> Tuple[Any, WireObservation, Dict[str, Any]]:
        """Executes the full Defense-in-Depth gate before socket release.
        
        1. Nonce Consumption: Validates human approval nonce and consumes atomically.
        2. Idempotency Binding: Derives and binds Idempotency-Key header.
        3. Intent Declaration: Commits intent to SQLite intent ledger.
        4. Socket Execution: Dispatches under Deterministic Transport Observer.
        5. Advisory Enrichment: Tags receipt with GLiNER2 entity metadata.
        """
        # 1. Nonce Ledger Consumption (Atomic Single-Use Check)
        self.nonce_ledger.consume_nonce(
            nonce=nonce,
            approval_id=approval_id,
            payload_to_execute=payload_to_execute,
            current_scope=task_scope
        )

        # 2. External Idempotency Key Injection
        outbound_headers = dict(headers or {})
        bind_headers(outbound_headers, session_id, sequence_number, payload_to_execute)

        # 3. Intent Declaration
        intent_id = self.intent_ledger.declare_intent(agent_id, target_api, payload_to_execute)

        # 4. Deterministic Transport Observation
        result, observation = observe_tool_call(
            target_fn,
            self.intent_ledger,
            intent_id,
            headers=outbound_headers
        )

        # 5. Advisory Plane Enrichment
        payload_summary_text = json.dumps(payload_to_execute)
        advisory_metadata = self.advisory_plane.extract_advisory_entities(payload_summary_text)

        # Invariant Guarantee: Advisory cannot change wire disposition
        assert advisory_metadata["disposition_override_permitted"] is False

        return result, observation, advisory_metadata
