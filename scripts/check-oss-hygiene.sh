#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "OSS hygiene check requires ripgrep (rg)." >&2
  exit 1
fi

COMMON_EXCLUDES=(
  -g '!.git/**'
  -g '!node_modules/**'
  -g '!.venv/**'
  -g '!dist/**'
  -g '!*.lock'
)

fail_with_hits() {
  local label="$1"
  local hits="$2"
  if [[ -n "$hits" ]]; then
    echo "OSS hygiene check failed: $label" >&2
    echo "$hits" >&2
    exit 1
  fi
}

secret_hits="$(
  rg -a -n --hidden "${COMMON_EXCLUDES[@]}" \
    '(BEGIN (RSA|OPENSSH|PRIVATE) KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(ant|proj|or-v1)-[A-Za-z0-9_-]{12,})' \
    . || true
)"
fail_with_hits "high-signal secret pattern found" "$secret_hits"

private_brand_hits="$(
  rg -a -n --hidden "${COMMON_EXCLUDES[@]}" \
    'ibrobaba|EQ Bank|eqbank|Reachly|reachly|semantic-review-runtime|/Users/ibrobaba|BMO|Tangerine|Equitable|sk-ant-test' \
    . | rg -v '^\./scripts/check-oss-hygiene\.sh:' || true
)"
fail_with_hits "private or customer-specific string found" "$private_brand_hits"

legacy_name_hits="$(
  rg -a -n --hidden "${COMMON_EXCLUDES[@]}" 'Semantic Security Review' . \
    | rg -v '^\./threatgenix/frontend/src/productIdentity\.test\.ts:' \
    | rg -v '^\./scripts/check-oss-hygiene\.sh:' || true
)"
fail_with_hits "legacy product name found outside the regression test" "$legacy_name_hits"

tracked_env_hits="$(git ls-files | rg '(^|/)\.env$' || true)"
fail_with_hits "tracked .env file found" "$tracked_env_hits"

uncommented_provider_key_hits="$(
  rg -n \
    '^(ANTHROPIC_API_KEY|OPENAI_API_KEY|OPENROUTER_API_KEY|GEMINI_API_KEY|XAI_API_KEY|PERPLEXITY_API_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)=' \
    threatgenix/.env.example threatgenix/backend/.env.example || true
)"
fail_with_hits "uncommented provider credential in env example" "$uncommented_provider_key_hits"

echo "OSS hygiene checks passed."
