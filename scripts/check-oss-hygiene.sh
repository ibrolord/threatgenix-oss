#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
DEFAULT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="${THREATGENIX_OSS_HYGIENE_ROOT:-$DEFAULT_ROOT}"

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

scan_tree() {
  local root="$1"
  cd "$root"

  secret_hits="$(
    rg -a -n --hidden "${COMMON_EXCLUDES[@]}" \
      '(-----BEGIN [A-Z0-9 _-]*PRIVATE KEY-----|BEGIN [A-Z0-9 _-]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(ant|proj|or-v1)-[A-Za-z0-9_-]{12,})' \
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

  env_example_files=()
  for env_example in threatgenix/.env.example threatgenix/backend/.env.example; do
    if [[ -f "$env_example" ]]; then
      env_example_files+=("$env_example")
    fi
  done
  uncommented_provider_key_hits=""
  if [[ "${#env_example_files[@]}" -gt 0 ]]; then
    uncommented_provider_key_hits="$(
      rg -n \
        '^(ANTHROPIC_API_KEY|OPENAI_API_KEY|OPENROUTER_API_KEY|GEMINI_API_KEY|XAI_API_KEY|PERPLEXITY_API_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)=' \
        "${env_example_files[@]}" || true
    )"
  fi
  fail_with_hits "uncommented provider credential in env example" "$uncommented_provider_key_hits"

  frontend_dockerfile="threatgenix/frontend/Dockerfile"
  frontend_dockerignore="threatgenix/frontend/.dockerignore"
  if [[ -f "$frontend_dockerfile" ]]; then
    if [[ ! -f "$frontend_dockerignore" ]]; then
      fail_with_hits \
        "frontend Docker context can copy host dependencies" \
        "$frontend_dockerignore is missing"
    fi
    docker_context_hits=""
    for required_exclude in node_modules dist; do
      if ! rg -q "^${required_exclude}/?$" "$frontend_dockerignore"; then
        docker_context_hits+="${frontend_dockerignore} must exclude ${required_exclude}"$'\n'
      fi
    done
    fail_with_hits \
      "frontend Docker context can copy host dependencies" \
      "$docker_context_hits"
  fi
}

create_clean_fixture() {
  local fixture="$1"
  mkdir -p "$fixture/threatgenix/backend"
  printf 'ThreatGenix OSS hygiene fixture\n' > "$fixture/README.md"
  printf '# ANTHROPIC_API_KEY=\n' > "$fixture/threatgenix/backend/.env.example"
  git -C "$fixture" init -q
  git -C "$fixture" add README.md threatgenix/backend/.env.example
}

run_fixture_scan() {
  local fixture="$1"
  local output="$2"
  THREATGENIX_OSS_HYGIENE_ROOT="$fixture" "$SCRIPT_PATH" >"$output" 2>&1
}

expect_fixture_passes() {
  local fixture="$SELF_TEST_TMP/pass"
  local output="$SELF_TEST_TMP/pass.out"
  create_clean_fixture "$fixture"
  if ! run_fixture_scan "$fixture" "$output"; then
    echo "OSS hygiene self-test failed: clean fixture did not pass" >&2
    cat "$output" >&2
    exit 1
  fi
}

setup_secret_fixture() {
  printf 'aws=%s%s\n' 'AKIA' 'ABCDEFGHIJKLMNOP' > "$1/leak.txt"
}

setup_private_key_fixture() {
  printf '%s\n%s\n%s\n' \
    '-----BEGIN OPENSSH '"PRIVATE KEY-----" \
    'fixture-key-body' \
    '-----END OPENSSH '"PRIVATE KEY-----" > "$1/private-key.txt"
}

setup_private_fixture() {
  printf 'owner=ibrobaba\n' > "$1/private.txt"
}

setup_legacy_fixture() {
  printf 'legacy=Semantic Security Review\n' > "$1/legacy.txt"
}

setup_tracked_env_fixture() {
  printf 'DEBUG=true\n' > "$1/.env"
  git -C "$1" add .env
}

setup_provider_key_fixture() {
  printf 'ANTHROPIC_API_KEY=test-value\n' > "$1/threatgenix/backend/.env.example"
  git -C "$1" add threatgenix/backend/.env.example
}

setup_unsafe_frontend_docker_context_fixture() {
  mkdir -p "$1/threatgenix/frontend"
  printf 'FROM node:20-alpine\nCOPY . .\n' > "$1/threatgenix/frontend/Dockerfile"
}

expect_fixture_fails() {
  local name="$1"
  local expected_label="$2"
  local setup_fn="$3"
  local fixture="$SELF_TEST_TMP/$name"
  local output="$SELF_TEST_TMP/$name.out"

  create_clean_fixture "$fixture"
  "$setup_fn" "$fixture"
  if run_fixture_scan "$fixture" "$output"; then
    echo "OSS hygiene self-test failed: $name fixture passed unexpectedly" >&2
    exit 1
  fi
  if ! rg -q -F "OSS hygiene check failed: $expected_label" "$output"; then
    echo "OSS hygiene self-test failed: $name fixture failed for the wrong reason" >&2
    cat "$output" >&2
    exit 1
  fi
}

run_self_test() {
  SELF_TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/threatgenix-hygiene.XXXXXX")"
  trap 'rm -rf "$SELF_TEST_TMP"' EXIT

  expect_fixture_passes
  expect_fixture_fails "secret" "high-signal secret pattern found" setup_secret_fixture
  expect_fixture_fails "private-key" "high-signal secret pattern found" setup_private_key_fixture
  expect_fixture_fails "private" "private or customer-specific string found" setup_private_fixture
  expect_fixture_fails "legacy" "legacy product name found outside the regression test" setup_legacy_fixture
  expect_fixture_fails "tracked-env" "tracked .env file found" setup_tracked_env_fixture
  expect_fixture_fails "provider-key" "uncommented provider credential in env example" setup_provider_key_fixture
  expect_fixture_fails \
    "unsafe-frontend-docker-context" \
    "frontend Docker context can copy host dependencies" \
    setup_unsafe_frontend_docker_context_fixture

  echo "OSS hygiene self-test passed."
}

if [[ "${1:-}" == "--self-test" ]]; then
  run_self_test
  exit 0
fi

if [[ "$#" -gt 0 ]]; then
  echo "Usage: $0 [--self-test]" >&2
  exit 2
fi

scan_tree "$ROOT"
echo "OSS hygiene checks passed."
