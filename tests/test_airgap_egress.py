"""
Unit tests for Sovereign 0-Byte Airgap Socket Inspection.
"""

import json
import socket
from pathlib import Path
import pytest
from src.security.airgap_monitor import AirgapSocketMonitor, AirgapViolationError


def test_airgap_allows_loopback_address_evaluation():
    """Validates that loopback addresses (127.0.0.1, ::1, localhost) are permitted."""
    monitor = AirgapSocketMonitor(strict_mode=True)
    allowed, host, port = monitor._is_allowed_address(("127.0.0.1", 8080))
    assert allowed is True
    assert host == "127.0.0.1"
    assert port == 8080

    allowed_v6, host_v6, _ = monitor._is_allowed_address(("::1", 8080))
    assert allowed_v6 is True

    allowed_local, host_local, _ = monitor._is_allowed_address(("localhost", 8080))
    assert allowed_local is True

    # Unix domain socket check
    allowed_unix, path_unix, _ = monitor._is_allowed_address("/tmp/smaos.sock")
    assert allowed_unix is True


def test_airgap_blocks_unauthorized_external_tcp_egress():
    """Validates that TCP connection attempts to external IPs are blocked immediately."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(AirgapViolationError) as exc_info:
        client.connect(("198.51.100.1", 443))

    assert "Cryptographic Airgap Breach" in str(exc_info.value)
    assert "198.51.100.1:443" in str(exc_info.value)
    client.close()


def test_airgap_blocks_unauthorized_external_udp_egress():
    """Validates that UDP packets to external IPs are blocked."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with pytest.raises(AirgapViolationError) as exc_info:
        sock.sendto(b"LEAK_DATA", ("8.8.8.8", 53))

    assert "Cryptographic Airgap Breach" in str(exc_info.value)
    sock.close()


def test_airgap_telemetry_receipt_generation(tmp_path):
    """Validates generation of the immutable 0-byte airgap telemetry receipt."""
    receipt_file = tmp_path / "airgap_receipt.json"
    monitor = AirgapSocketMonitor(strict_mode=False)
    # Simulate an external egress block
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    monitor.hook_connect(client, ("203.0.113.5", 8080))
    client.close()

    receipt_path = monitor.export_telemetry_receipt(str(receipt_file))
    assert Path(receipt_path).is_file()

    with open(receipt_path) as f:
        data = json.load(f)

    assert data["external_bytes_transmitted"] == 0
    assert data["external_connections_blocked"] == 1
    assert data["disposition"] == "CONFIRMED_ZERO_EGRESS"
    assert data["status"] == "AIRGAP_INTACT"
