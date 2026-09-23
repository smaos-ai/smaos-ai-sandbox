"""Behavioral Governance: The Intent Ledger.

Agents must cryptographically declare what they are about to touch
before the wire request fires. This local SQLite ledger tracks intent
and prevents post-execution hallucination.
"""
import sqlite3
import json
import uuid
from typing import Any, Dict

class IntentLedger:
    def __init__(self, db_path="intent_ledger.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
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
        """Register the agent's intent before execution."""
        intent_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO intents (id, agent_id, target_api, payload, status) VALUES (?, ?, ?, ?, ?)",
            (intent_id, agent_id, target_api, json.dumps(payload), "PENDING")
        )
        self.conn.commit()
        print(f"[*] Intent Declared: {intent_id} -> {target_api} (Status: PENDING)")
        return intent_id

    def resolve_intent(self, intent_id: str, final_status: str):
        """Update the intent status based on physical wire truth."""
        self.cursor.execute(
            "UPDATE intents SET status = ? WHERE id = ?",
            (final_status, intent_id)
        )
        self.conn.commit()
        print(f"[*] Intent Resolved: {intent_id} -> {final_status}")
