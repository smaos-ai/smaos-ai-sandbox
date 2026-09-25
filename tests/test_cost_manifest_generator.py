import json
from src.cost_manifest_generator import generate_cost_manifest

def test_generate_cost_manifest():
    manifest = generate_cost_manifest(
        target_system="Qwen3-8B-SMAOS-Pipeline",
        execution_latency_ms=167.5,
        compute_cost_usd=0.00042,
        peak_memory_mb=4096.0,
        network_egress_bytes=0,
        token_utilization=1050,
        throughput_ops_sec=5.9,
        infrastructure_overhead_usd=0.01
    )
    
    assert manifest["manifest_version"] == "smaos-cost-v1"
    assert manifest["dimensions"]["execution_latency_ms"] == 167.5
    assert manifest["dimensions"]["network_egress_bytes"] == 0
    assert "signature" in manifest
    assert manifest["signature"]["algorithm"] == "Ed25519"
    assert len(manifest["signature"]["value"]) == 64
