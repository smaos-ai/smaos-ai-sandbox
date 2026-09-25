"""
SMAOS Atomic Approval Nonce Ledger (v1.1.0)
Cryptographic and database state machine enforcing single-use human authorizations.

Protects against:
  - Authorization replay attacks (reusing a valid signature or token)
  - Post-approval payload mutations (modifying parameters after user sign-off)
  - Scope escalation and cross-context execution
  - Expired delegation window executions (TTL expiration)

Enforces:
  SQLite atomic transactions via BEGIN IMMEDIATE with UNIQUE(nonce, approval_id).
"""

import datetime
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from src.canonicalizer import digest


class NonceLedgerError(Exception):
    """Base error for approval nonce ledger operations."""
    pass


class ReplayAttackViolation(NonceLedgerError):
    """Raised when an attempt is made to replay or reuse an authorization nonce."""
    pass


class PayloadTamperViolation(NonceLedgerError):
    """Raised when payload differs from the human-approved canonical hash."""
    pass


class ScopeViolation(NonceLedgerError):
    """Raised when execution context does not match the approved task scope."""
    pass


class ApprovalExpiredViolation(NonceLedgerError):
    """Raised when execution is attempted after the approval TTL window has lapsed."""
    pass


class ApprovalNonceLedger:
    """Atomic SQLite-backed ledger for human approvals and execution nonces."""

    def __init__(self, db_path: str = "approval_nonce_ledger.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_nonce_ledger (
                    nonce TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    task_scope TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    consumed_at REAL,
                    status TEXT NOT NULL,
                    PRIMARY KEY (nonce),
                    UNIQUE (nonce, approval_id)
                );
            """)
            conn.commit()

    def record_approval(
        self,
        approval_id: str,
        approved_payload: Dict[str, Any],
        principal_id: str,
        task_scope: str,
        policy_hash: str = "sha256:default_policy_root",
        ttl_seconds: int = 300,
        custom_nonce: Optional[str] = None
    ) -> str:
        """Registers a verified human approval and issues a single-use execution nonce."""
        payload_hash = digest(approved_payload)
        nonce = custom_nonce or f"nonce-{uuid.uuid4().hex}"
        created_at = time.time()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE;")
            cursor.execute(
                """
                INSERT INTO approval_nonce_ledger (
                    nonce, approval_id, payload_hash, principal_id,
                    task_scope, policy_hash, ttl_seconds, created_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING');
                """,
                (nonce, approval_id, payload_hash, principal_id, task_scope, policy_hash, ttl_seconds, created_at)
            )
            conn.commit()

        return nonce

    def consume_nonce(
        self,
        nonce: str,
        approval_id: str,
        payload_to_execute: Dict[str, Any],
        current_scope: str
    ) -> bool:
        """Atomically validates and consumes the approval nonce prior to socket dispatch.
        
        Raises:
            ReplayAttackViolation: If nonce is already consumed or unknown.
            PayloadTamperViolation: If payload hash differs from approved hash.
            ScopeViolation: If current scope does not match approved task scope.
            ApprovalExpiredViolation: If approval TTL has elapsed.
        """
        now = time.time()
        actual_hash = digest(payload_to_execute)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE;")

            cursor.execute(
                """
                SELECT payload_hash, task_scope, ttl_seconds, created_at, status
                FROM approval_nonce_ledger
                WHERE nonce = ? AND approval_id = ?;
                """,
                (nonce, approval_id)
            )
            row = cursor.fetchone()

            if not row:
                raise ReplayAttackViolation(
                    f"Replay or Unknown Authorization: Nonce '{nonce}' with approval '{approval_id}' not found."
                )

            expected_hash, task_scope, ttl_seconds, created_at, status = row

            if status == "CONSUMED":
                raise ReplayAttackViolation(
                    f"Authorization Replay Rejected: Nonce '{nonce}' for approval '{approval_id}' has already been consumed."
                )

            if status != "PENDING":
                raise ReplayAttackViolation(
                    f"Invalid Authorization State: Nonce '{nonce}' is in status '{status}'."
                )

            # 1. TTL Expiration Check
            if (now - created_at) > ttl_seconds:
                cursor.execute(
                    "UPDATE approval_nonce_ledger SET status = 'EXPIRED' WHERE nonce = ?;",
                    (nonce,)
                )
                conn.commit()
                raise ApprovalExpiredViolation(
                    f"Approval Expired: Nonce expired {(now - created_at) - ttl_seconds:.2f}s ago (TTL: {ttl_seconds}s)."
                )

            # 2. Scope Binding Check
            if task_scope != current_scope:
                raise ScopeViolation(
                    f"Scope Escalation Blocked: Nonce approved for '{task_scope}', but execution requested '{current_scope}'."
                )

            # 3. Post-Approval Payload Mutation Check
            if actual_hash != expected_hash:
                raise PayloadTamperViolation(
                    f"Post-Approval Payload Tampering Detected: Expected hash {expected_hash}, got {actual_hash}."
                )

            # 4. Atomic Consumption
            cursor.execute(
                """
                UPDATE approval_nonce_ledger
                SET status = 'CONSUMED', consumed_at = ?
                WHERE nonce = ? AND status = 'PENDING';
                """,
                (now, nonce)
            )
            if cursor.rowcount != 1:
                raise ReplayAttackViolation("Concurrent race detected: Nonce was consumed by a parallel thread.")

            conn.commit()

        return True
