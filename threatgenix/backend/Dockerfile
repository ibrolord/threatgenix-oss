FROM python:3.12-slim

WORKDIR /app
ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev shared-mime-info curl ca-certificates unzip tar \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Security scanning tools are optional — set true only for validation worker builds
ARG INSTALL_VALIDATION_TOOLS=false
ARG NUCLEI_VERSION=3.8.0
ARG OSV_SCANNER_VERSION=2.3.5
ARG TRIVY_VERSION=0.70.0
ARG SEMGREP_VERSION=1.157.0
ARG CHECKOV_VERSION=3.2.520
ARG TRUFFLEHOG_VERSION=3.83.7
COPY scripts/install_validation_tools.sh /tmp/install_validation_tools.sh
RUN if [ "$INSTALL_VALIDATION_TOOLS" = "true" ]; then \
      NUCLEI_VERSION="$NUCLEI_VERSION" \
      OSV_SCANNER_VERSION="$OSV_SCANNER_VERSION" \
      TRIVY_VERSION="$TRIVY_VERSION" \
      SEMGREP_VERSION="$SEMGREP_VERSION" \
      CHECKOV_VERSION="$CHECKOV_VERSION" \
      TRUFFLEHOG_VERSION="$TRUFFLEHOG_VERSION" \
      sh /tmp/install_validation_tools.sh; \
    fi \
    && rm -f /tmp/install_validation_tools.sh

RUN mkdir -p /tmp/threatgenix-validation-targets \
    && chmod 1777 /tmp/threatgenix-validation-targets

COPY . .

# Run as non-root user for defence-in-depth
RUN useradd --no-create-home --shell /bin/false appuser \
    && chown -R appuser:appuser /app
ENV HOME=/tmp
USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
