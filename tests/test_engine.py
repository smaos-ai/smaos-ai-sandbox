import json
import subprocess
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from run import evaluate_disposition, TraceScrubber, WIRE_NO_RESPONSE

@pytest.mark.parametrize("wire_status,sdk_claim,exp_disp,exp_flag", [
    (504, "CONFIRMED", "dispatched_unconfirmed", "VERIFIED_TOXIC_RECEIPT"),
    (WIRE_NO_RESPONSE, "CONFIRMED", "dispatched_unconfirmed", "VERIFIED_TOXIC_RECEIPT"),
    (WIRE_NO_RESPONSE, "FAILED", "CONFLICT", "UNVERIFIED_STATE"),
    (WIRE_NO_RESPONSE, "RETRY_DISPATCH", "CONFLICT", "UNVERIFIED_STATE"),
    ("INVALID", "INVALID_INPUT", "INVALID_INPUT", "SCHEMA_TAMPER"),
    (200, "CONFIRMED", "CONFIRMED", "VERIFIED_VALID"),
    (403, "REFUSED", "REFUSED", "POLICY_GATE_REJECT"),
    (WIRE_NO_RESPONSE, "UNKNOWN", "dispatched_unconfirmed", "UNCERTAIN"),
])
def test_evaluate_disposition(wire_status, sdk_claim, exp_disp, exp_flag):
    got_disp, got_flag = evaluate_disposition(wire_status, sdk_claim)
    assert got_disp == exp_disp
    assert got_flag == exp_flag

def test_trace_scrubber():
    assert TraceScrubber.sanitize("CZ6508000000001234567890") == "[REDACTED_IBAN]"
    assert TraceScrubber.sanitize("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.x") == "Bearer [REDACTED_JWT]"
    assert TraceScrubber.sanitize("4111 1111 1111 1111") == "[REDACTED_PAN]"
    assert TraceScrubber.sanitize("test@example.com") == "[REDACTED_EMAIL]"

@pytest.mark.parametrize("scenario,exp_disp,exp_disc", [
    ("504_timeout", "dispatched_unconfirmed", True),
    ("confirmed", "CONFIRMED", False),
    ("refused", "REFUSED", False),
    ("tcp_reset", "dispatched_unconfirmed", False),
    ("delayed_confirmation", "dispatched_unconfirmed", True),
    ("duplicate_retry_same_payload", "CONFLICT", True),
    ("payload_mutation_on_retry", "CONFLICT", True),
    ("malformed_response", "INVALID_INPUT", True),
])
def test_run_single_scenario_cli(tmp_path, scenario, exp_disp, exp_disc):
    cmd = [sys.executable, str(ROOT / "run.py"), "--scenario", scenario, "--export-dir", str(tmp_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Stderr: {res.stderr}"

    obj = json.loads(res.stdout)
    assert obj["evaluated_disposition"] == exp_disp
    assert obj["discrepancy_detected"] == exp_disc

    raw_iban = "CZ6508000000001234567890"
    assert raw_iban not in res.stdout

    # Artifact checks
    mermaid = (tmp_path / "audit_trace.mermaid").read_text()
    assert "sequenceDiagram" in mermaid
    assert raw_iban not in mermaid

    dr = json.loads((tmp_path / "disposition_report.json").read_text())
    assert dr["final_disposition"] == exp_disp

    assert (tmp_path / "dora_art17_gap_report.json").exists()

    java = (tmp_path / "ProofOrStopFilter.java").read_text()
    assert "class AgentDiscrepancyException" in java
    assert "IOException" in java

def test_demo_launcher_cli():
    cmd = [sys.executable, str(ROOT / "demo_launcher.py")]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    assert res.returncode == 0
    assert "DISCREPANCY DETECTED" in res.stdout
    assert "[REDACTED_IBAN]" in res.stdout
    assert "CZ6508000000001234567890" not in res.stdout

def test_invalid_scenario():
    cmd = [sys.executable, str(ROOT / "run.py"), "--scenario", "invalid"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 2

def test_scenario_alias_cli(tmp_path):
    cmd = [sys.executable, str(ROOT / "run.py"), "--scenario", "prevent_silent_double_spend_on_504", "--export-dir", str(tmp_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    obj = json.loads(res.stdout)
    assert obj["scenario_id"] == "504_timeout"
    assert obj["scenario_alias"] == "prevent_silent_double_spend_on_504"
    assert obj["human_oversight"]["status"] == "awaiting_human_validation"
    assert (tmp_path / "trust_passport.json").exists()

def test_ghost_audit_scanner():
    cmd = [sys.executable, str(ROOT / "ghost_audit_scanner.py")]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    assert res.returncode == 0
    assert "GOVERNANCE INTENSITY INDEX (GII)" in res.stdout
    assert "0 bytes of egress" in res.stdout

def test_validate_dora_register():
    cmd = [sys.executable, str(ROOT / "validate_dora_register.py")]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    assert res.returncode == 0
    assert "SMAOS DORA xBRL-CSV Compiler" in res.stdout
    assert "R0010" in res.stdout
