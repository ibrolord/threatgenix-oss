#!/usr/bin/env sh
set -eu

NUCLEI_VERSION="${NUCLEI_VERSION:-3.8.0}"
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-2.3.5}"
TRIVY_VERSION="${TRIVY_VERSION:-0.70.0}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.157.0}"
CHECKOV_VERSION="${CHECKOV_VERSION:-3.2.520}"
TRUFFLEHOG_VERSION="${TRUFFLEHOG_VERSION:-3.95.2}"

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)
    github_arch="amd64"
    trivy_arch="64bit"
    ;;
  aarch64|arm64)
    github_arch="arm64"
    trivy_arch="ARM64"
    ;;
  *)
    echo "validation tool installer supports linux/amd64 and linux/arm64 only; got $arch" >&2
    exit 1
    ;;
esac

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "Installing Nuclei ${NUCLEI_VERSION}"
curl -fsSL \
  "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${github_arch}.zip" \
  -o "$tmpdir/nuclei.zip"
unzip -q "$tmpdir/nuclei.zip" -d "$tmpdir/nuclei"
install -m 0755 "$tmpdir/nuclei/nuclei" /usr/local/bin/nuclei

echo "Installing OSV-Scanner ${OSV_SCANNER_VERSION}"
curl -fsSL \
  "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${github_arch}" \
  -o /usr/local/bin/osv-scanner
chmod 0755 /usr/local/bin/osv-scanner

echo "Installing Trivy ${TRIVY_VERSION}"
curl -fsSL \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" \
  -o "$tmpdir/trivy.tar.gz"
tar -xzf "$tmpdir/trivy.tar.gz" -C "$tmpdir"
install -m 0755 "$tmpdir/trivy" /usr/local/bin/trivy

echo "Installing Semgrep ${SEMGREP_VERSION} and Checkov ${CHECKOV_VERSION} (isolated venv)"
# Use a separate venv so semgrep/checkov deps don't pollute the app's starlette/fastapi versions
python3 -m venv /opt/validation-venv
/opt/validation-venv/bin/pip install --no-cache-dir \
  "semgrep==${SEMGREP_VERSION}" \
  "checkov==${CHECKOV_VERSION}"

# Expose as system-wide CLI wrappers
printf '#!/bin/sh\nexec /opt/validation-venv/bin/semgrep "$@"\n' > /usr/local/bin/semgrep
printf '#!/bin/sh\nexec /opt/validation-venv/bin/checkov "$@"\n' > /usr/local/bin/checkov
chmod 0755 /usr/local/bin/semgrep /usr/local/bin/checkov

echo "Installing Trufflehog (using upstream install script for the pinned version)"
# The official install.sh respects the -b install-dir and last positional argument as version tag.
curl -fsSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b /usr/local/bin "v${TRUFFLEHOG_VERSION}"
chmod 0755 /usr/local/bin/trufflehog

echo "Validation tools installed: nuclei, semgrep, osv-scanner, trivy, checkov, and trufflehog."
