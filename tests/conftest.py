"""
Pytest configuration & Sovereign Airgap Enforcer.
Activates the 0-byte airgap socket monitor across all test suites,
ensuring zero bytes are transmitted outside loopback (127.0.0.1).
"""

import pytest
from src.security.airgap_monitor import AirgapSocketMonitor


@pytest.fixture(scope="session", autouse=True)
def sovereign_airgap_guard():
    """Autouse session fixture verifying strict 0-byte external network egress."""
    monitor = AirgapSocketMonitor(strict_mode=True)
    monitor.install()
    
    yield monitor
    
    # Session teardown
    monitor.uninstall()
    assert monitor.metrics["external_bytes_transmitted"] == 0, (
        f"Cryptographic Airgap Failure: {monitor.metrics['external_bytes_transmitted']} bytes "
        "transmitted to external networks during test execution!"
    )
    receipt_path = monitor.export_telemetry_receipt("audit_out/airgap_telemetry_receipt.json")
    print(f"\n🛡️ Sovereign Airgap Verified: 0 external bytes transmitted (Receipt: {receipt_path})")
