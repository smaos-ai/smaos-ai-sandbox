#!/usr/bin/env bash
# SMAOS Isolated Ring-0 Kernel Suite Runner (v1.1.0)
# Runs bare-metal eBPF XDP hardware integration tests

set -euo pipefail

echo "================================================================================"
echo "🛡️  SMAOS ISOLATED RING-0 KERNEL TEST SUITE"
echo "================================================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Warning: Not running as root. Hardware bpftool veth attachment tests will be skipped."
    echo "    To run full bare-metal test: sudo bash scripts/run_kernel_tests.sh"
fi

python3 -m pytest tests/kernel/ -v --tb=short

echo "================================================================================"
echo "✅ Kernel physics driver assertions complete."
echo "================================================================================"
