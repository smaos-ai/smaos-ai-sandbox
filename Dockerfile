# SMAOS Sovereign Autonomous Operating System (v0.5.0)
FROM python:3.11-slim

LABEL maintainer="SovereignNexus <andrii@sovereignnexus.org>"
LABEL description="Air-gapped settlement fuzzer & wire-truth verifier for autonomous AI agents"

WORKDIR /app

# Ensure non-root execution
RUN groupadd -g 1000 smaos && useradd -u 1000 -g smaos -m smaos

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt || true

# Copy application files
COPY run.py demo_launcher.py entrypoint.sh verify.sh production_soak_test.py /app/
COPY bin/ /app/bin/
COPY src/ /app/src/
COPY docs/ /app/docs/
COPY fixtures/ /app/fixtures/
COPY schemas/ /app/schemas/
COPY smaos_verify/ /app/smaos_verify/

RUN mkdir -p /app/audit_out && chown -R smaos:smaos /app && chmod +x /app/*.sh /app/bin/*.sh

USER smaos

EXPOSE 8765

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEMO_MODE=live

ENTRYPOINT ["/app/entrypoint.sh"]
