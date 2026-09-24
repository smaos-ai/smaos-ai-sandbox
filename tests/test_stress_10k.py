import pytest
from src.stress_fuzzer_10k import StressFuzzer10K, StressRunResult, HEAP_CEILING_MB


def test_stress_fuzzer_10k_invariants(tmp_path):
    """Validates that StressFuzzer10K maintains 0.0% overclaims, 0 bytes egress, and <1.0ms p99 latency."""
    db_test = str(tmp_path / "test_stress_wal.db")
    fuzzer = StressFuzzer10K(
        iterations=1000,
        chaos_ratio=0.75,
        heap_ceiling_mb=HEAP_CEILING_MB,
        db_path=db_test
    )

    res = fuzzer.run()

    assert res.total_transactions == 1000
    assert res.chaos_transactions == 750
    assert res.healthy_transactions == 250
    assert res.status == "PASSED"

    # Core Verification Invariants
    assert res.overclaim_count == 0, "Overclaim count must be exactly 0"
    assert res.overclaim_rate_pct == 0.0, "Overclaim rate must be 0.0%"
    assert res.egress_bytes_leaked == 0, "Zero egress leak invariant breached"
    assert res.egress_packets_dropped == 100, "Must drop 100/100 unauthorized probes"

    # Latency and Performance SLAs
    assert res.p99_latency_ms < 1.0, f"p99 latency {res.p99_latency_ms}ms exceeded 1.0ms target"
    assert res.avg_latency_ms < 0.5, f"avg latency {res.avg_latency_ms}ms exceeded 0.5ms target"
    assert res.throughput_tx_per_sec > 1000.0, "Throughput below SLA target"

    # Cryptographic & Memory Invariants
    assert res.cryptographic_signatures_generated == 1000
    assert res.cryptographic_integrity_pct == 100.0
    assert res.memory_ceiling_respected is True
    assert res.peak_memory_mb <= HEAP_CEILING_MB

    # Report Generation
    j_p, m_p = fuzzer.generate_report(res, out_dir=str(tmp_path))
    assert j_p.exists()
    assert m_p.exists()
