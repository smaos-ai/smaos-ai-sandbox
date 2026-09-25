#!/usr/bin/env python3
"""
Sovereign Bytecode & Binary Integrity Verifier (v1.1.0)
Cryptographically verifies that core WebAssembly, eBPF kernel bytecode,
and offline verification artifacts match checksums.sha256 exactly.

Halts CI/CD with non-zero exit code if:
  1. Any artifact has been modified or replaced with mock/stub code
  2. Any artifact is missing
  3. The checksums manifest itself is missing or malformed
"""

import hashlib
import os
import sys
from pathlib import Path


def verify_manifest(manifest_path: str = "checksums.sha256") -> bool:
    root = Path(__file__).resolve().parent.parent
    p = root / manifest_path

    if not p.is_file():
        print(f"❌ [CHECKSUM FAIL] Manifest not found: {p}", file=sys.stderr)
        return False

    all_matched = True
    print("=" * 80)
    print("🔒 SOVEREIGN BYTECODE & ARTIFACT INTEGRITY VERIFICATION")
    print(f"   Manifest: {p}")
    print("=" * 80)

    with open(p, "r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                print(f"❌ [CHECKSUM ERROR] Malformed line {line_no}: {line}", file=sys.stderr)
                all_matched = False
                continue

            expected_hash, rel_path = parts[0], parts[1].strip()
            target_file = root / rel_path

            if not target_file.is_file():
                print(f"❌ [MISSING ARTIFACT] {rel_path} does not exist!", file=sys.stderr)
                all_matched = False
                continue

            with open(target_file, "rb") as tf:
                actual_hash = hashlib.sha256(tf.read()).hexdigest()

            if actual_hash.lower() == expected_hash.lower():
                print(f"✅ [MATCH] {rel_path} ({actual_hash[:16]}...)")
            else:
                print(f"❌ [HASH MISMATCH] {rel_path}!", file=sys.stderr)
                print(f"    Expected: {expected_hash}", file=sys.stderr)
                print(f"    Actual  : {actual_hash}", file=sys.stderr)
                all_matched = False

    print("=" * 80)
    if all_matched:
        print("✅ PASS: All bytecode and offline verifier binaries match checksums.sha256.")
        print("=" * 80)
        return True
    else:
        print("🛑 FAIL: Cryptographic tampering detected! One or more binaries failed verification.", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        return False


def main():
    ok = verify_manifest()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
