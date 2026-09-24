import os
from pathlib import Path
import pytest
from src.ebpf_xdp_driver import XDPEgressFilter, XDPAction


def test_ebpf_xdp_c_source_validity():
    """Validates existence and structure of the Ring-0 C kernel bytecode source."""
    ebpf_dir = Path(__file__).resolve().parent.parent / "ebpf"
    c_source = ebpf_dir / "smaos_egress_xdp.bpf.c"

    assert c_source.exists(), "ebpf/smaos_egress_xdp.bpf.c must exist"
    content = c_source.read_text(encoding="utf-8")

    # Assert essential BPF maps and SEC directives
    assert 'SEC("xdp_egress")' in content
    assert "allowed_ipv4" in content
    assert "allowed_ports" in content
    assert "egress_telemetry" in content
    assert "XDP_DROP" in content
    assert "XDP_PASS" in content
    assert "ETH_P_IP" in content


def test_xdp_filter_pass_allowed_traffic():
    """Validates that packets matching allowed IP and port pass through."""
    filter_driver = XDPEgressFilter(allowed_ips=["127.0.0.1"], allowed_ports=[8080])
    packet = filter_driver.create_mock_packet(dest_ip="127.0.0.1", dest_port=8080, payload=b"VALID_TX")

    action, elapsed_ns = filter_driver.inspect_packet(packet)
    assert action == XDPAction.XDP_PASS
    assert elapsed_ns >= 0
    assert filter_driver.metrics["packets_inspected"] == 1
    assert filter_driver.metrics["packets_allowed"] == 1
    assert filter_driver.metrics["packets_dropped"] == 0


def test_xdp_filter_drop_unauthorized_ip():
    """Validates Ring-0 packet drop on unauthorized destination IP."""
    filter_driver = XDPEgressFilter(allowed_ips=["127.0.0.1"], allowed_ports=[8080])
    unauthorized_packet = filter_driver.create_mock_packet(
        dest_ip="198.51.100.1", dest_port=8080, payload=b"EGRESS_LEAK"
    )

    action, elapsed_ns = filter_driver.inspect_packet(unauthorized_packet)
    assert action == XDPAction.XDP_DROP
    assert filter_driver.metrics["packets_inspected"] == 1
    assert filter_driver.metrics["packets_allowed"] == 0
    assert filter_driver.metrics["packets_dropped"] == 1
    assert filter_driver.metrics["drop_bad_ip"] == 1


def test_xdp_filter_drop_unauthorized_port():
    """Validates Ring-0 packet drop on unauthorized destination port."""
    filter_driver = XDPEgressFilter(allowed_ips=["127.0.0.1"], allowed_ports=[8080])
    unauthorized_port_packet = filter_driver.create_mock_packet(
        dest_ip="127.0.0.1", dest_port=443, payload=b"UNAUTHORIZED_PORT"
    )

    action, elapsed_ns = filter_driver.inspect_packet(unauthorized_port_packet)
    assert action == XDPAction.XDP_DROP
    assert filter_driver.metrics["packets_inspected"] == 1
    assert filter_driver.metrics["packets_allowed"] == 0
    assert filter_driver.metrics["packets_dropped"] == 1
    assert filter_driver.metrics["drop_bad_port"] == 1


def test_xdp_filter_dynamic_map_mutation():
    """Validates live mutation of BPF hash maps for IPs and ports."""
    filter_driver = XDPEgressFilter(allowed_ips=["127.0.0.1"], allowed_ports=[8080])

    packet_new_ip = filter_driver.create_mock_packet(dest_ip="10.0.0.5", dest_port=8080)
    # Initially blocked
    action, _ = filter_driver.inspect_packet(packet_new_ip)
    assert action == XDPAction.XDP_DROP

    # Add IP to BPF map
    filter_driver.update_allowed_ip("10.0.0.5", allowed=True)
    action, _ = filter_driver.inspect_packet(packet_new_ip)
    assert action == XDPAction.XDP_PASS

    # Remove IP from BPF map
    filter_driver.update_allowed_ip("10.0.0.5", allowed=False)
    action, _ = filter_driver.inspect_packet(packet_new_ip)
    assert action == XDPAction.XDP_DROP


def test_xdp_filter_short_and_non_ipv4_frames():
    """Validates handling of malformed or short packets without crashing."""
    filter_driver = XDPEgressFilter()

    # Empty frame
    action, _ = filter_driver.inspect_packet(b"")
    assert action == XDPAction.XDP_PASS

    # Short truncated frame (<14 bytes)
    action, _ = filter_driver.inspect_packet(b"\x00" * 10)
    assert action == XDPAction.XDP_PASS

    # Non-IPv4 frame (e.g. ARP = 0x0806)
    arp_frame = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28
    action, _ = filter_driver.inspect_packet(arp_frame)
    assert action == XDPAction.XDP_PASS
