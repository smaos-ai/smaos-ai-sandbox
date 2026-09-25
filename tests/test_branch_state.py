import pytest
from src.branch_state import SeekDBBranch, BranchState, StateError

def test_branch_state_machine():
    branch = SeekDBBranch("branch_123", "prod_db")
    
    # 1. Diff is allowed while executing
    assert branch.diff() == "mock_diff_payload"
    
    # 2. Quarantine on timeout
    branch.quarantine_unconfirmed()
    assert branch.state == BranchState.QUARANTINED_UNCONFIRMED
    
    # 3. Attempt silent drop of unconfirmed branch
    with pytest.raises(StateError) as excinfo:
        branch.drop(reason="timeout_cleanup")
    
    assert "retention_expired:" in str(excinfo.value)
    
    # 4. Valid drop after retention
    branch.drop(reason="retention_expired: TTL 7 days reached")
    assert branch.state == BranchState.DROPPED
