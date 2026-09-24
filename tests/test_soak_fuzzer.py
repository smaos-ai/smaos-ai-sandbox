import json
from pathlib import Path
import pytest
from src.soak_fuzzer import SoakFuzzer, SoakBenchmarkResult, HEAP_CEILING_MB


def test_soak_fuzzer_execution_and_metrics(tmp_path):
    """Validates that SoakFuzzer runs iterations, respects latency (<0.5ms) and memory ceiling (<64MB)."""
    iterations = 1800  # 200 cycles across all 9 scenarios
    fuzzer = SoakFuzzer(iterations=iterations, heap_ceiling_mb=HEAP_CEILING_MB)

    res = fuzzer.run()

    assert res.iterations == iterations
    assert res.status == "PASSED"
    assert res.false_positives == 0
    assert res.discrepancy_drift_detected is False

    # Performance assertions
    assert res.throughput_tx_per_sec > 1000.0
    assert res.avg_latency_ms < 0.5, f"Avg latency {res.avg_latency_ms}ms exceeded 0.5ms SLA"
    assert res.p95_latency_ms < 0.5, f"p95 latency {res.p95_latency_ms}ms exceeded 0.5ms SLA"

    # Memory ceiling assertions
    assert res.memory_ceiling_respected is True
    assert res.peak_memory_mb <= HEAP_CEILING_MB

    # Export reports test
    json_path, md_path = fuzzer.export_reports(res, out_dir=str(tmp_path))
    assert json_path.exists()
    assert md_path.exists()

    with open(json_path, "r") as f:
        data = json.load(f)
        assert data["iterations"] == iterations
        assert data["status"] == "PASSED"

    md_text = md_path.read_text(encoding="utf-8")
    assert "SMAOS High-Throughput Soak Benchmark Report" in md_text
    assert "PASSED" in md_text
