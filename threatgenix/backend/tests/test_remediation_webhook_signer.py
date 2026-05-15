from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.services.remediation_webhooks import sign_remediation_webhook_body

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "remediation_webhook_signer.py"


def test_remediation_webhook_signer_matches_backend_signature(tmp_path: Path):
    payload = b'{"issue":{"body":"action_id: threat:1:remediation_note"}}'
    payload_file = tmp_path / "payload.json"
    payload_file.write_bytes(payload)
    expected = sign_remediation_webhook_body(
        timestamp="1800000000",
        nonce="nonce-cli",
        raw_body=payload,
        secret="test-secret",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--payload-file",
            str(payload_file),
            "--secret",
            "test-secret",
            "--timestamp",
            "1800000000",
            "--nonce",
            "nonce-cli",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "X-SSR-Webhook-Timestamp: 1800000000" in result.stdout
    assert "X-SSR-Webhook-Nonce: nonce-cli" in result.stdout
    assert f"X-SSR-Webhook-Signature: {expected}" in result.stdout


def test_remediation_webhook_signer_prints_tester_json_from_stdin():
    payload = '{"issue":{"body":"action_id: threat:1:remediation_note"}}'

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--stdin",
            "--secret",
            "test-secret",
            "--timestamp",
            "1800000000",
            "--nonce",
            "nonce-cli",
            "--provider",
            "github",
            "--format",
            "tester-json",
        ],
        input=payload,
        check=True,
        capture_output=True,
        text=True,
    )

    body = json.loads(result.stdout)
    assert body["provider"] == "github"
    assert body["payload_text"] == payload
    assert body["headers"]["X-SSR-Webhook-Timestamp"] == "1800000000"
    assert body["headers"]["X-SSR-Webhook-Nonce"] == "nonce-cli"
    assert body["headers"]["X-SSR-Webhook-Signature"].startswith("sha256=")


def test_remediation_webhook_signer_requires_one_payload_source():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--secret", "test-secret"],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Choose exactly one payload source" in result.stderr
