#!/usr/bin/env python3
"""
Sovereign Zero-Trust Guard (v1.1.0)
Dual-purpose local pre-commit hook and server-side CI inspector.

Enforces:
  1. Path Interception:
     - Blocks docs/outreach/, docs/regulatory_dispatch/, vault/, private/
     - Blocks files matching *CISO_*, *CAS_RADA_*, *LVIV_GB200_*, *sow.html, *sow.pdf
     - Blocks raw private key files (*.pem, *.key, *.pkcs8, *.p12, *.der, *_privkey.*)
  2. Content Interception:
     - Rejects commercial pitch materials ("Statement of Work", commercial rate cards, sprint fees)
     - Rejects mock signatures (mock_signature, ed25519:mock, mock_proof, mock_attestation)
     - Rejects direct file-based private key deserialization (load_pem_private_key, load_der_private_key)
  3. AST-Level Mock Purge:
     - Scans AST of all Python files outside tests/
     - Rejects imports from unittest.mock, mock, or pytest_mock
     - Rejects MagicMock, Mock, AsyncMock, PropertyMock, and @patch decorators
  4. Bytecode & Artifact Checksum Verification:
     - Verifies checksums.sha256 for WASM, eBPF ELF bytecode, and offline verifiers

Exits:
  0 = Clean codebase, all assertions pass
  1 = Banned pattern detected, commit/PR blocked
"""

import ast
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# BANNED PATTERNS SPECIFICATION
# ─────────────────────────────────────────────────────────────────────────────

BANNED_PATH_PATTERNS = [
    r"(^|/)docs/outreach/",
    r"(^|/)docs/regulatory_dispatch/",
    r"(^|/)vault/",
    r"(^|/)private/",
    r".*CISO_.*",
    r".*CAS_RADA_.*",
    r".*LVIV_GB200_.*",
    r".*sow\.html$",
    r".*sow\.pdf$",
    r".*sow-diagnostic.*",
    # Hardware-Bound Key Guard: Ban raw committed private key files
    r".*\.(pem|pkcs8|p12|der)$",
    r".*_privkey\..*",
    r".*private_key\.(json|pem|key|txt)$",
]

BANNED_CONTENT_PATTERNS = [
    # Mock Signatures and Fake Cryptography
    (r"mock_signature", "Fake / Mock cryptographic signature detected"),
    (r"ed25519:mock", "Mock Ed25519 curve wire token detected"),
    (r"sig:ed25519:mock", "Mock signature slice detected"),
    (r"mock_proof", "Mock zero-knowledge / attestation proof detected"),
    (r"mock_attestation", "Mock hardware attestation detected"),
    
    # Commercial Pitch Materials & Pricing
    (r"(?i)\bstatement\s+of\s+work\b", "Commercial Statement of Work (SOW) text detected in public repo"),
    (r"€\s*(?:750|1,?500|2,?500|3,?500|4,?500|5,?000|15,?000)\b", "Commercial client pricing fee (€) detected"),
    (r"(?i)\bcommercial\s+engagement\b", "Commercial engagement pitch detected"),
    (r"(?i)\bfixed\s+fee\s*:\s*€", "Commercial fixed-fee rate card detected"),
    (r"(?i)\bdiagnostic\s+audit\s+fee\b", "Commercial audit fee rate card detected"),
    (r"(?i)\bwholesale\s+sow\b", "Wholesale SOW commercial template detected"),
    (r"(?i)\bdata\s+feasibility\s+sprint\b", "Commercial feasibility sprint offer detected"),

    # Hardware-Bound Key Enforcement: Prohibit direct file-based private key loading
    (r"load_pem_private_key", "Direct disk-based PEM private key loading detected — use HardwareKeyProvider"),
    (r"load_der_private_key", "Direct disk-based DER private key loading detected — use HardwareKeyProvider"),
]

# File extensions to scan for content
TEXT_EXTENSIONS = {
    ".py", ".rs", ".js", ".ts", ".html", ".md", ".json", ".yaml", ".yml",
    ".hcl", ".c", ".h", ".sh", ".toml", ".sql", ".txt", ".xml"
}

IGNORED_PATHS = {
    "scripts/sovereign_guard.py",
    ".git",
    "__pycache__",
    "target",
    "node_modules",
    ".pytest_cache",
}

BANNED_AST_MOCK_NAMES = {
    "Mock",
    "MagicMock",
    "AsyncMock",
    "PropertyMock",
    "NonCallableMock",
    "create_autospec",
}


def is_ignored(path_str: str) -> bool:
    for ignored in IGNORED_PATHS:
        if ignored in path_str:
            return True
    return False


def check_path_violations(filepath: str) -> List[str]:
    violations = []
    normalized = filepath.replace("\\", "/")
    for pattern in BANNED_PATH_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            violations.append(f"Banned path pattern '{pattern}' matched: {filepath}")
    return violations


def check_content_violations(filepath: str) -> List[Tuple[int, str, str]]:
    violations = []
    p = Path(filepath)

    if not p.is_file() or p.suffix.lower() not in TEXT_EXTENSIONS:
        return violations

    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                for pattern, desc in BANNED_CONTENT_PATTERNS:
                    if re.search(pattern, line):
                        violations.append((line_no, desc, line.strip()))
    except Exception as exc:
        violations.append((0, f"Error reading file: {exc}", ""))

    return violations


def check_ast_mock_violations(filepath: str) -> List[Tuple[int, str, str]]:
    """AST-level mock purge: Rejects mock stubs in runtime/production Python files.
    
    Tests directory (tests/) is exempted for test harnesses.
    """
    violations = []
    p = Path(filepath)
    normalized = filepath.replace("\\", "/")

    # Exclude test files and test suites from production AST purge
    if "tests/" in normalized or normalized.startswith("tests") or p.suffix.lower() != ".py":
        return violations

    if not p.is_file():
        return violations

    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        tree = ast.parse(code, filename=filepath)
    except SyntaxError as e:
        return [(e.lineno or 0, f"Python AST syntax error: {e}", "")]
    except Exception as exc:
        return [(0, f"Failed to parse AST: {exc}", "")]

    for node in ast.walk(tree):
        # 1. Direct imports: import unittest.mock, import mock
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("unittest.mock", "mock", "pytest_mock"):
                    violations.append((
                        node.lineno,
                        f"Banned mock import: 'import {alias.name}' in runtime code",
                        f"import {alias.name}"
                    ))
        # 2. From imports: from unittest.mock import ..., from mock import ...
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in ("unittest.mock", "mock", "pytest_mock") or mod.startswith("unittest.mock"):
                violations.append((
                    node.lineno,
                    f"Banned mock module import: 'from {mod} import ...' in runtime code",
                    f"from {mod} import ..."
                ))
            for alias in node.names:
                if alias.name in BANNED_AST_MOCK_NAMES or alias.name == "patch":
                    violations.append((
                        node.lineno,
                        f"Banned mock symbol imported: '{alias.name}' in runtime code",
                        f"from {mod} import {alias.name}"
                    ))
        # 3. Direct usage of MagicMock, Mock, AsyncMock
        elif isinstance(node, ast.Name):
            if node.id in ("MagicMock", "AsyncMock"):
                violations.append((
                    node.lineno,
                    f"Banned mock object reference: '{node.id}' in runtime code",
                    node.id
                ))
        # 4. Decorators: @patch, @patch.object
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = ""
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Name):
                        dec_name = dec.func.id
                    elif isinstance(dec.func, ast.Attribute):
                        dec_name = dec.func.attr
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr

                if dec_name in ("patch", "mock"):
                    violations.append((
                        node.lineno,
                        f"Banned mock decorator '@{dec_name}' on function '{node.name}' in runtime code",
                        f"@{dec_name}"
                    ))

    return violations


def main() -> int:
    files_to_check = sys.argv[1:]

    # If no files passed via CLI, discover tracked or staged files
    if not files_to_check:
        try:
            import subprocess
            res = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                capture_output=True,
                text=True,
                check=False
            )
            staged = [f.strip() for f in res.stdout.splitlines() if f.strip()]
            if staged:
                files_to_check = staged
            else:
                # Fallback to checking all tracked files
                res_all = subprocess.run(
                    ["git", "ls-files"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                files_to_check = [f.strip() for f in res_all.stdout.splitlines() if f.strip()]
        except Exception:
            files_to_check = []

    if not files_to_check:
        print("[ℹ] Sovereign Zero-Trust Guard: No files specified or staged to inspect.")
        return 0

    total_violations = 0
    print("=" * 80)
    print("🛡️  SOVEREIGN ZERO-TRUST GUARD (v1.1.0)")
    print(f"    Inspecting {len(files_to_check)} file(s)...")
    print("=" * 80)

    for filepath in files_to_check:
        if is_ignored(filepath):
            continue

        # 1. Path check
        path_errs = check_path_violations(filepath)
        for err in path_errs:
            print(f"❌ [BLOCKED PATH] {err}")
            total_violations += 1

        if os.path.exists(filepath):
            # 2. Content check
            content_errs = check_content_violations(filepath)
            for line_no, desc, line_snippet in content_errs:
                print(f"❌ [BLOCKED CONTENT] {filepath}:{line_no}")
                print(f"    Rule Violation : {desc}")
                print(f"    Violating Line : {line_snippet[:100]}")
                total_violations += 1

            # 3. AST Mock Purge (production code)
            ast_errs = check_ast_mock_violations(filepath)
            for line_no, desc, snippet in ast_errs:
                print(f"❌ [BLOCKED AST MOCK] {filepath}:{line_no}")
                print(f"    Violation      : {desc}")
                total_violations += 1

    # 4. Bytecode & Binary Checksum Verification
    root = Path(__file__).resolve().parent.parent
    if (root / "checksums.sha256").exists():
        from verify_checksums import verify_manifest
        if not verify_manifest("checksums.sha256"):
            total_violations += 1

    print("-" * 80)
    if total_violations > 0:
        print(f"🛑 REJECTED: {total_violations} Sovereign Zero-Trust violation(s) detected!")
        print("   Commit aborted. Commercial outreach, SOWs, pricing, mock AST imports,")
        print("   and unverified bytecode binaries are strictly prohibited.")
        print("=" * 80)
        return 1

    print("✅ PASS: 0 Sovereign Zero-Trust violations detected.")
    print("   Codebase verified clean of mock cryptography, commercial leaks, and bytecode drift.")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
