#!/usr/bin/env python3
"""Generate ThreatGenix remediation webhook HMAC headers.

The signer is intentionally standalone so customer-owned relay code can copy or
run it without importing the backend application.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path

SIGNATURE_PREFIX = "sha256="
TIMESTAMP_HEADER = "X-SSR-Webhook-Timestamp"
NONCE_HEADER = "X-SSR-Webhook-Nonce"
SIGNATURE_HEADER = "X-SSR-Webhook-Signature"


def _read_payload(args: argparse.Namespace) -> bytes:
    sources = [
        args.payload_file is not None,
        args.payload_text is not None,
        args.stdin,
    ]
    if sum(sources) != 1:
        raise SystemExit(
            "Choose exactly one payload source: --payload-file, --payload-text, or --stdin."
        )
    if args.payload_file is not None:
        return Path(args.payload_file).read_bytes()
    if args.payload_text is not None:
        return args.payload_text.encode("utf-8")
    return sys.stdin.buffer.read()


def _read_secret(args: argparse.Namespace) -> str:
    if args.secret:
        return args.secret
    for name in args.secret_env:
        value = os.environ.get(name)
        if value:
            return value
    raise SystemExit(
        "Missing signing secret. Set REMEDIATION_WEBHOOK_SIGNATURE_SECRET or pass --secret."
    )


def sign_payload(
    *,
    timestamp: str,
    nonce: str,
    payload: bytes,
    secret: str,
) -> str:
    base = f"{timestamp}.{nonce}.".encode("utf-8") + payload
    digest = hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def _headers(*, timestamp: str, nonce: str, signature: str) -> dict[str, str]:
    return {
        TIMESTAMP_HEADER: timestamp,
        NONCE_HEADER: nonce,
        SIGNATURE_HEADER: signature,
    }


def _print_shell_headers(headers: dict[str, str]) -> None:
    for name, value in headers.items():
        print(f"{name}: {value}")


def _print_curl_headers(headers: dict[str, str]) -> None:
    for name, value in headers.items():
        print(f"-H {json.dumps(f'{name}: {value}')}")


def _print_tester_json(
    *,
    provider: str | None,
    payload: bytes,
    headers: dict[str, str],
) -> None:
    payload_text = payload.decode("utf-8")
    body: dict[str, object] = {
        "payload_text": payload_text,
        "headers": headers,
    }
    if provider:
        body["provider"] = provider
    print(json.dumps(body, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate SSR remediation callback timestamp, nonce, and "
            "HMAC-SHA256 signature headers for an exact provider payload."
        )
    )
    source = parser.add_argument_group("payload source")
    source.add_argument("--payload-file", help="Read exact payload bytes from a file.")
    source.add_argument("--payload-text", help="Sign this UTF-8 payload string.")
    source.add_argument(
        "--stdin",
        action="store_true",
        help="Read exact payload bytes from standard input.",
    )
    parser.add_argument(
        "--secret",
        help="Signing secret. Prefer the default environment variables for shared use.",
    )
    parser.add_argument(
        "--secret-env",
        action="append",
        default=["REMEDIATION_WEBHOOK_SIGNATURE_SECRET", "SECRET_KEY"],
        help=(
            "Environment variable to read the signing secret from. May be passed "
            "more than once; defaults to REMEDIATION_WEBHOOK_SIGNATURE_SECRET, "
            "then SECRET_KEY."
        ),
    )
    parser.add_argument(
        "--timestamp",
        default=None,
        help="Unix timestamp seconds. Defaults to the current time.",
    )
    parser.add_argument(
        "--nonce",
        default=None,
        help="Unique replay nonce. Defaults to a random URL-safe nonce.",
    )
    parser.add_argument(
        "--provider",
        choices=["github", "linear", "jira"],
        help="Provider name to include when printing tester JSON.",
    )
    parser.add_argument(
        "--format",
        choices=["headers", "curl-headers", "tester-json"],
        default="headers",
        help="Output format.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    payload = _read_payload(args)
    secret = _read_secret(args)
    timestamp = args.timestamp or str(int(time.time()))
    nonce = args.nonce or secrets.token_urlsafe(24)
    signature = sign_payload(
        timestamp=timestamp,
        nonce=nonce,
        payload=payload,
        secret=secret,
    )
    headers = _headers(timestamp=timestamp, nonce=nonce, signature=signature)

    try:
        if args.format == "curl-headers":
            _print_curl_headers(headers)
        elif args.format == "tester-json":
            _print_tester_json(
                provider=args.provider,
                payload=payload,
                headers=headers,
            )
        else:
            _print_shell_headers(headers)
    except UnicodeDecodeError as exc:
        raise SystemExit("tester-json output requires a UTF-8 payload.") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
