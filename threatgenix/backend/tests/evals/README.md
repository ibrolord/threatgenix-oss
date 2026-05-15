# Threat Modeler Audit Harness

This package runs a benchmark-grade audit of ThreatGenix threat outputs.

## What it covers

- Gold DFD engine-only runs
- Structured and narrative document runs
- Narrative repair runs with a fixed repair script
- Delta re-analysis runs with triage persistence checks
- Dual-model judging through local `claude` and `gemini` CLIs
- Consolidated scorecards, summaries, failures, and manual-review queues

## Claude CLI wrapper

ThreatGenix now uses a project wrapper around the local Claude Code CLI instead of
shelling out to `claude -p` directly. The wrapper:

- forces non-interactive print mode
- uses Claude's JSON schema support for structured judge output
- strips inherited shell-function exports from the child environment
- raises a clear project error when Claude is installed but not authenticated

Authenticate once with your subscription before running Claude-backed flows:

- `claude auth login`
- or `claude setup-token`

Manual project usage:

- `make claude-prompt PROMPT_FILE=/tmp/prompt.txt MODEL=opus`
- `cd backend && python -m app.services.claude_cli_wrapper --prompt-file /tmp/prompt.txt --model opus`

## Entry points

- Materialize scenario assets only:
  - `cd backend && python -m tests.evals.run_threat_modeler_audit --build-scenarios-only`
- Run the full campaign against a managed backend:
  - `make eval-threat-modeler`
- Run against an existing backend:
  - `cd backend && python -m tests.evals.run_threat_modeler_audit --base-url http://127.0.0.1:8000/api`

## Managed backend mode

`--manage-backend` launches `uvicorn app.main:app` on a temporary port and is the
only deterministic way to run the `*_threat_intel_unavailable` variants.

The managed backend uses non-public audit env flags:

- `AUDIT_FORCE_AI_UNAVAILABLE=true`
- `AUDIT_FORCE_INVALID_MODEL_CONFIG=true`
- `AUDIT_DISABLE_THREAT_INTEL=true`

No public API changes are required or used by the harness.

## Outputs

Each run writes artifacts under `/tmp/threatgenix-evals/<timestamp>/<scenario>/<mode>/`,
including:

- DFD snapshots
- analyze and rules-only responses
- threat list and CSV export
- judge input and judge outputs
- scorecard and rendered snapshot image

The campaign root also contains:

- `summary.md`
- `scores.csv`
- `judge_outputs/claude.json`
- `judge_outputs/gemini.json`
- `manual_review_queue.json`
- `failures.md`
