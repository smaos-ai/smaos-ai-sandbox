#!/usr/bin/env python3
"""
Pre-Ingestion PII Sanitizer
A client-side utility provided to prospects to safely scrub PII (IBANs, emails, names) 
and redact secrets locally before exporting their log telemetry for SMAOS Diagnostic ingestion.
Removes GDPR and data-privacy friction.
"""

import json
import hashlib
import re
import argparse
from pathlib import Path

# Regex patterns for sensitive data
IBAN_REGEX = re.compile(r'\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9a-zA-Z]{4}){4}(?:[ ]?[0-9a-zA-Z]{1,3})?\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
TOKEN_REGEX = re.compile(r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*')

def anonymize_value(val: str) -> str:
    """One-way HMAC mask for sensitive exact values."""
    return f"REDACTED_{hashlib.sha256(val.encode()).hexdigest()[:12]}"

def sanitize_payload(payload):
    """Recursively scrub payload dictionary."""
    if isinstance(payload, dict):
        sanitized = {}
        for k, v in payload.items():
            if k.lower() in ["iban", "account_number", "email", "ssn", "secret", "token", "password"]:
                sanitized[k] = anonymize_value(str(v))
            else:
                sanitized[k] = sanitize_payload(v)
        return sanitized
    elif isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    elif isinstance(payload, str):
        s = IBAN_REGEX.sub("REDACTED_IBAN", payload)
        s = EMAIL_REGEX.sub("REDACTED_EMAIL", s)
        s = TOKEN_REGEX.sub("Bearer REDACTED_TOKEN", s)
        return s
    return payload

def main():
    parser = argparse.ArgumentParser(description="Scrub PII from agent telemetry logs.")
    parser.add_argument("input_log", type=Path, help="Raw input JSONL log file")
    parser.add_argument("output_log", type=Path, help="Sanitized output JSONL log file")
    args = parser.parse_args()

    count = 0
    with args.input_log.open('r') as infile, args.output_log.open('w') as outfile:
        for line in infile:
            if not line.strip(): continue
            try:
                row = json.loads(line)
                if "payload" in row:
                    row["payload"] = sanitize_payload(row["payload"])
                outfile.write(json.dumps(row) + "\n")
                count += 1
            except json.JSONDecodeError:
                pass

    print(f"[SUCCESS] Sanitized {count} events. Safe for export: {args.output_log}")

if __name__ == "__main__":
    main()
