"""
SMAOS SeekDB Driver & Branch State Machine
Binds lifecycle transitions to SeekDB SQL commands with strict state invariants.
"""
from enum import Enum, auto
from typing import Optional

class StateError(Exception):
    pass

class BranchState(Enum):
    EXECUTING = "executing"
    MERGED = "merged"
    QUARANTINED_UNCONFIRMED = "quarantined_unconfirmed"
    DROPPED = "dropped"

class SeekDBBranch:
    def __init__(self, branch_id: str, db_name: str):
        self.branch_id = branch_id
        self.db_name = db_name
        self.state = BranchState.EXECUTING
        # Simulate FORK
        self._execute_sql(f"FORK DATABASE {self.db_name} AS {self.branch_id};")

    def _execute_sql(self, query: str):
        """Mock execution of SeekDB specific commands."""
        # In a real driver, this would execute against the SeekDB socket.
        pass

    def diff(self) -> str:
        """Returns the difference generated on this branch."""
        if self.state != BranchState.EXECUTING:
            raise StateError("Can only diff while executing.")
        self._execute_sql(f"DIFF TABLE {self.branch_id};")
        return "mock_diff_payload"

    def merge_fail_closed(self) -> None:
        """Attempts to merge using the STRATEGY FAIL."""
        if self.state != BranchState.EXECUTING:
            raise StateError(f"Cannot merge from {self.state.value}.")
        self._execute_sql(f"MERGE DATABASE {self.branch_id} INTO {self.db_name} STRATEGY FAIL;")
        self.state = BranchState.MERGED

    def quarantine_unconfirmed(self) -> None:
        """Locks branch into quarantine due to ambiguous network timeout (e.g. 504)."""
        if self.state != BranchState.EXECUTING:
            raise StateError(f"Cannot quarantine from {self.state.value}.")
        self.state = BranchState.QUARANTINED_UNCONFIRMED

    def drop(self, reason: str = "") -> None:
        """Safely discards a branch. Enforces retention invariants."""
        if self.state == BranchState.QUARANTINED_UNCONFIRMED:
            if not reason.startswith("retention_expired:"):
                raise StateError(
                    "quarantined_unconfirmed may only be dropped with a "
                    "reason beginning 'retention_expired:'; unconfirmed "
                    "external effects must not be discarded silently"
                )
        self._execute_sql(f"DROP DATABASE {self.branch_id};")
        self.state = BranchState.DROPPED
