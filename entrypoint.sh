#!/bin/sh
set -e

echo "🚀 [SMAOS Container Engine v0.1.0] Starting zero-egress verification harness..."
echo "🔒 Runtimes Configured: RUNTIME=$RUNTIME, FRAMEWORK=$FRAMEWORK, FAULT_MODES=$FAULT_MODES"
echo "🛡️  Privacy Guard Active: $PRIVACY_GUARD (In-memory IBAN/PAN/JWT Scrubbing)"

mkdir -p /app/audit_out

# Run the Python wire-observer fuzzer
python3 /app/run.py --all-scenarios --export-dir /app/audit_out

# Also generate the interactive HTML dashboard if demo_launcher exists
if [ -f "/app/demo_launcher.py" ]; then
    python3 /app/demo_launcher.py || true
fi

echo "✅ Audit execution completed. Artifacts written to /app/audit_out."

if [ "$DEMO_MODE" = "live" ] || [ -f "/app/audit_out/index.html" ]; then
    echo "📊 Serving SMAOS Executive Dashboard on http://127.0.0.1:8765 ..."
    cd /app/audit_out && exec python3 -m http.server 8765 --bind 127.0.0.1
fi
