"""Behavioral Governance: The Intent Ledger.

Agents must cryptographically declare what they are about to touch
before the wire request fires. This local SQLite ledger tracks intent
and prevents post-execution hallucination and multi-agent resource collisions (Foremerge pattern).
"""
import sqlite3
import json
import uuid
from typing import Any, Dict, Optional

class IntentCollisionError(Exception):
    """Raised when concurrent agents attempt to lock the same resource."""
    pass

class IntentLedger:
    def __init__(self, db_path="intent_ledger.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("PRAGMA journal_mode = WAL;")
        self.cursor.execute("PRAGMA synchronous = NORMAL;")
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS intents (
                id TEXT PRIMARY KEY,
                agent_id TEXT,
                target_api TEXT,
                payload TEXT,
                status TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def declare_intent(self, agent_id: str, target_api: str, payload: Dict[str, Any]) -> str:
        """Register the agent's intent before execution with atomic collision check."""
        self.cursor.execute(
            "SELECT id, agent_id FROM intents WHERE target_api = ? AND status = 'PENDING'",
            (target_api,)
        )
        existing = self.cursor.fetchone()
        if existing and existing[1] != agent_id:
            raise IntentCollisionError(
                f"Collision detected: Agent '{agent_id}' cannot lock resource '{target_api}'; "
                f"already locked by Agent '{existing[1]}' (intent {existing[0]})"
            )

        intent_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO intents (id, agent_id, target_api, payload, status) VALUES (?, ?, ?, ?, ?)",
            (intent_id, agent_id, target_api, json.dumps(payload), "PENDING")
        )
        self.conn.commit()
        return intent_id

    def resolve_intent(self, intent_id: str, final_status: str):
        """Update the intent status based on physical wire truth."""
        self.cursor.execute(
            "UPDATE intents SET status = ? WHERE id = ?",
            (final_status, intent_id)
        )
        self.conn.commit()
