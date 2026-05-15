"""Stdio MCP-compatible wrapper for the ThreatGenix agent API."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, BinaryIO, Callable

from app.cli.threatgenix import DEFAULT_SERVER_URL, CliError, ThreatGenixClient

SERVER_NAME = "threatgenix"
SERVER_VERSION = "0.1.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

DEFAULT_RATE_LIMIT_ANNOTATION = {
    "scope": "tenant_and_token",
    "retry_after_header": "Retry-After",
}
READ_QUOTA_COST = {
    "api_calls": 1,
    "scan_minutes": 0,
    "ai_tokens": 0,
    "bundle_storage_bytes": 0,
}


MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "threatgenix.review.orchestrate",
        "description": (
            "Run a tenant-scoped ThreatGenix security review from app profile, "
            "intake answers, bundle manifest, and approved scanner tools."
        ),
        "annotations": {
            "threatgenix_rate_limit": DEFAULT_RATE_LIMIT_ANNOTATION,
            "threatgenix_quota_cost": {
                "api_calls": 1,
                "scan_minutes": "2 per requested scanner tool",
                "ai_tokens": "1000 when evaluate_decision is true",
                "bundle_storage_bytes": "sum of bundle.manifest[].byte_size",
            },
        },
        "inputSchema": {
            "type": "object",
            "required": ["review"],
            "properties": {
                "threat_model": {"type": ["object", "null"]},
                "review": {"type": "object"},
                "bundle": {"type": ["object", "null"]},
                "scanner_tools": {"type": ["array", "null"], "items": {"type": "string"}},
                "external_active_authorized": {"type": "boolean"},
                "external_targets": {"type": "array", "items": {"type": "string"}},
                "rebuild_context": {"type": "boolean"},
                "evaluate_decision": {"type": "boolean"},
            },
        },
    },
    {
        "name": "threatgenix.review.status",
        "description": "Read review status, decision, public web URL, and agent hints.",
        "annotations": {
            "threatgenix_rate_limit": DEFAULT_RATE_LIMIT_ANNOTATION,
            "threatgenix_quota_cost": READ_QUOTA_COST,
        },
        "inputSchema": {
            "type": "object",
            "required": ["review_id"],
            "properties": {"review_id": {"type": "string"}},
        },
    },
    {
        "name": "threatgenix.review.findings",
        "description": "Read scanner findings from the tenant-scoped context index.",
        "annotations": {
            "threatgenix_rate_limit": DEFAULT_RATE_LIMIT_ANNOTATION,
            "threatgenix_quota_cost": READ_QUOTA_COST,
        },
        "inputSchema": {
            "type": "object",
            "required": ["review_id"],
            "properties": {
                "review_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
        },
    },
    {
        "name": "threatgenix.review.rerun",
        "description": "Rebuild review context and rerun the deterministic decision.",
        "annotations": {
            "threatgenix_rate_limit": DEFAULT_RATE_LIMIT_ANNOTATION,
            "threatgenix_quota_cost": {
                "api_calls": 1,
                "scan_minutes": 0,
                "ai_tokens": 1000,
                "bundle_storage_bytes": 0,
            },
        },
        "inputSchema": {
            "type": "object",
            "required": ["review_id"],
            "properties": {"review_id": {"type": "string"}},
        },
    },
    {
        "name": "threatgenix.review.open",
        "description": "Return the public web review URL for a human reviewer.",
        "annotations": {
            "threatgenix_rate_limit": DEFAULT_RATE_LIMIT_ANNOTATION,
            "threatgenix_quota_cost": READ_QUOTA_COST,
        },
        "inputSchema": {
            "type": "object",
            "required": ["review_id"],
            "properties": {"review_id": {"type": "string"}},
        },
    },
]


def build_client(
    client_factory: Callable[[str, str | None], ThreatGenixClient] = ThreatGenixClient,
) -> ThreatGenixClient:
    server_url = os.getenv("THREATGENIX_API_URL", DEFAULT_SERVER_URL).rstrip("/")
    token = os.getenv("THREATGENIX_TOKEN")
    if not token:
        raise CliError("Missing THREATGENIX_TOKEN for tenant-scoped MCP calls.")
    return client_factory(server_url, token)


def call_tool(
    name: str,
    arguments: dict[str, Any],
    *,
    client: ThreatGenixClient | None = None,
) -> dict[str, Any]:
    api = client or build_client()
    if name == "threatgenix.review.orchestrate":
        return api.post_json("/api/agent/reviews/orchestrations", arguments)
    review_id = str(arguments.get("review_id") or "").strip()
    if not review_id:
        raise CliError(f"{name} requires review_id.")
    if name == "threatgenix.review.status":
        return api.get_json(f"/api/agent/reviews/{review_id}/status")
    if name == "threatgenix.review.findings":
        params = {"limit": str(arguments.get("limit", 20))}
        return api.get_json(f"/api/agent/reviews/{review_id}/findings", params)
    if name == "threatgenix.review.rerun":
        return api.post_json(f"/api/agent/reviews/{review_id}/rerun", {})
    if name == "threatgenix.review.open":
        return api.get_json(f"/api/agent/reviews/{review_id}/open")
    raise CliError(f"Unknown ThreatGenix MCP tool: {name}")


def handle_request(
    message: dict[str, Any],
    *,
    client_factory: Callable[[str, str | None], ThreatGenixClient] = ThreatGenixClient,
) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None:
        return None
    try:
        if method == "initialize":
            params = message.get("params") or {}
            result = {
                "protocolVersion": params.get("protocolVersion", DEFAULT_PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }
        elif method == "tools/list":
            result = {"tools": MCP_TOOLS}
        elif method == "tools/call":
            params = message.get("params") or {}
            tool_result = call_tool(
                str(params.get("name") or ""),
                params.get("arguments") or {},
                client=build_client(client_factory),
            )
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(tool_result, sort_keys=True),
                    }
                ],
                "structuredContent": tool_result,
                "isError": False,
            }
        else:
            return _error(request_id, -32601, f"Unsupported method: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        return _error(request_id, -32000, str(exc))


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def read_framed_message(stream: BinaryIO) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if line == b"":
            return None
        if line in {b"\r\n", b"\n"}:
            break
        key, _, value = line.decode("ascii").partition(":")
        headers[key.casefold()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    payload = stream.read(length)
    return json.loads(payload.decode("utf-8"))


def write_framed_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
    stream.write(payload)
    stream.flush()


def serve_stdio(
    input_stream: BinaryIO = sys.stdin.buffer,
    output_stream: BinaryIO = sys.stdout.buffer,
    *,
    client_factory: Callable[[str, str | None], ThreatGenixClient] = ThreatGenixClient,
) -> int:
    while message := read_framed_message(input_stream):
        response = handle_request(message, client_factory=client_factory)
        if response is not None:
            write_framed_message(output_stream, response)
    return 0


def main() -> int:
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
