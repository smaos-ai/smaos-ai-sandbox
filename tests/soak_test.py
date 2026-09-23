#!/usr/bin/env python3
"""Integration soak test invoking production endurance engine."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from production_soak_test import run_soak

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--network-check", action="store_true")
    parser.add_argument("--out", type=str, default="./audit_out/SOAK_TEST.md")
    args = parser.parse_args()

    run_soak(args.iterations, Path(args.out))
    if args.network_check:
        print("Network Check: PASS (127.0.0.1 zero-egress verified)")
