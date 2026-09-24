import sqlite3
import pytest
from pathlib import Path
from src.hcl_compiler.parser import HCLParser
from src.hcl_compiler.compiler import HCLCompiler

SAMPLE_HCL = """system "test_sys" {
  version = "2.0.0"
  egress_mode = "zero_egress"
}

agent "risk_agent" {
  intent_lock_required = true
  max_transaction_value = 50000.00
  allowed_currencies = ["EUR"]
}

network_boundary "sandbox" {
  allowed_ports = [8080, 9090]
  bpf_lsm_drop = true
}

isolation "sqlite_wal" {
  journal_mode = "WAL"
  synchronous = "NORMAL"
}
"""

def test_hcl_parser_ast():
    parser = HCLParser(SAMPLE_HCL)
    ast = parser.parse()
    assert "system" in ast
    assert ast["system"]["test_sys"]["version"] == "2.0.0"
    assert ast["agent"]["risk_agent"]["max_transaction_value"] == 50000.0
    assert ast["network_boundary"]["sandbox"]["allowed_ports"] == [8080, 9090]

def test_hcl_compiler_bpf_and_scitt():
    parser = HCLParser(SAMPLE_HCL)
    ast = parser.parse()
    compiler = HCLCompiler(ast)

    bpf_h, bpf_json = compiler.compile_bpf_maps()
    assert "#define ADMISSIBILITY_MAX_PORTS 2" in bpf_h
    assert "8080, 9090" in bpf_h
    assert bpf_json["allowed_ports"] == [8080, 9090]

    scitt_schema = compiler.compile_scitt_schema()
    assert scitt_schema["type"] == "object"
    assert "payload_hash" in scitt_schema["required"]

def test_sqlite_wal_invariants_live_enforcement():
    parser = HCLParser(SAMPLE_HCL)
    ast = parser.parse()
    compiler = HCLCompiler(ast)

    sql_ddl = compiler.compile_sqlite_wal_invariants()
    
    # Test on a real in-memory SQLite connection
    conn = sqlite3.connect(":memory:")
    conn.executescript(sql_ddl)

    cur = conn.cursor()

    # 1. Allowed transaction <= 50,000.0
    cur.execute(
        "INSERT INTO intent_cow_branches (branch_id, agent_id, transaction_value, status) VALUES (?, ?, ?, ?)",
        ("br_001", "risk_agent", 49999.0, "PENDING")
    )
    conn.commit()

    cur.execute("SELECT status FROM intent_cow_branches WHERE branch_id = 'br_001'")
    assert cur.fetchone()[0] == "PENDING"

    # 2. Exceeding limit > 50,000.0 must be aborted by trigger
    with pytest.raises(sqlite3.IntegrityError, match="Transaction value exceeds HCL declared limit"):
        cur.execute(
            "INSERT INTO intent_cow_branches (branch_id, agent_id, transaction_value, status) VALUES (?, ?, ?, ?)",
            ("br_002", "risk_agent", 60000.0, "PENDING")
        )

    # 3. Status update to DENIED must trigger CoW rollback (row deletion)
    cur.execute("UPDATE intent_cow_branches SET status = 'DENIED' WHERE branch_id = 'br_001'")
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM intent_cow_branches WHERE branch_id = 'br_001'")
    assert cur.fetchone()[0] == 0
