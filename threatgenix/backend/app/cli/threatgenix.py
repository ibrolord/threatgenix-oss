"""Thin ThreatGenix CLI for invoke-anywhere application reviews."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import importlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable
from urllib import parse, request
from urllib.error import HTTPError, URLError

from app.intake_mapping import threat_model_fields_from_intake

DEFAULT_CONFIG_PATH = ".threatgenix.yml"
DEFAULT_SERVER_URL = "http://localhost:8000"
DEFAULT_MCP_COMMAND = "threatgenix-mcp"
DEFAULT_MCP_MODULE = "app.cli.threatgenix_mcp"
KEYRING_SERVICE = "threatgenix-cli"
TOKEN_DIR = Path.home() / ".config" / "threatgenix" / "tokens"
TERMINAL_REVIEW_STATUSES = {
    "completed",
    "blocked_by_policy",
    "blocked_by_permission",
    "failed_terminal",
    "cancelled",
}


class CliError(RuntimeError):
    """User-facing CLI error."""


class ThreatGenixClient:
    def __init__(self, server_url: str, token: str | None) -> None:
        self.server_url = server_url.rstrip("/")
        self.token = token

    def get_json(self, path: str, params: dict[str, str] | None = None) -> dict:
        query = f"?{parse.urlencode(params)}" if params else ""
        return self._request("GET", f"{path}{query}")

    def post_json(self, path: str, payload: dict) -> dict:
        return self._request("POST", path, payload=payload)

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        url = f"{self.server_url}{path}"
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=30) as response:
                response_body = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8")
            raise CliError(f"ThreatGenix API returned {exc.code}: {detail}") from exc
        except URLError as exc:
            raise CliError(f"Could not reach ThreatGenix API: {exc.reason}") from exc
        return json.loads(response_body or "{}")


def load_config(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    config: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        config[key.strip()] = _decode_config_value(value.strip())
    return config


def _decode_config_value(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return value.strip('"')
        return str(decoded)
    return value.strip('"')


def _encode_config_value(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def write_config(
    path: Path,
    *,
    server_url: str,
    web_url: str | None = None,
    app_name: str | None = None,
    default_review_type: str | None = None,
    git_remote: str | None = None,
    git_branch: str | None = None,
    git_commit: str | None = None,
    token_file: str | None = None,
    intake_answers: dict[str, str] | None = None,
) -> None:
    lines = [
        "# ThreatGenix CLI config",
        f"server_url: {_encode_config_value(server_url.rstrip('/'))}",
    ]
    if web_url:
        lines.append(f"web_url: {_encode_config_value(web_url.rstrip('/'))}")
    if app_name:
        lines.append(f"app_name: {_encode_config_value(app_name)}")
    if default_review_type:
        lines.append(f"review_type: {_encode_config_value(default_review_type)}")
    if git_remote:
        lines.append(f"git_remote: {_encode_config_value(git_remote)}")
    if git_branch:
        lines.append(f"git_branch: {_encode_config_value(git_branch)}")
    if git_commit:
        lines.append(f"git_commit: {_encode_config_value(git_commit)}")
    if token_file:
        lines.append(f"token_file: {_encode_config_value(token_file)}")
    for key, value in sorted((intake_answers or {}).items()):
        lines.append(f"answer.{key}: {_encode_config_value(value)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def resolve_server_url(config: dict[str, str], explicit: str | None = None) -> str:
    return (
        explicit
        or os.getenv("THREATGENIX_API_URL")
        or config.get("server_url")
        or DEFAULT_SERVER_URL
    ).rstrip("/")


def resolve_token(
    config: dict[str, str],
    explicit: str | None = None,
    *,
    server_url: str | None = None,
) -> str | None:
    if explicit:
        return explicit
    env_token = os.getenv("THREATGENIX_TOKEN")
    if env_token:
        return env_token
    if server_url:
        keyring_token = read_keyring_token(server_url)
        if keyring_token:
            return keyring_token
        file_token = read_file_token(server_url, config.get("token_file"))
        if file_token:
            return file_token
    return config.get("token")


def read_keyring_token(server_url: str) -> str | None:
    try:
        keyring = importlib.import_module("keyring")
        token = keyring.get_password(KEYRING_SERVICE, server_url.rstrip("/"))
    except Exception:
        return None
    return token if isinstance(token, str) and token else None


def store_keyring_token(server_url: str, token: str) -> bool:
    try:
        keyring = importlib.import_module("keyring")
        keyring.set_password(KEYRING_SERVICE, server_url.rstrip("/"), token)
    except Exception:
        return False
    return True


def token_file_path(server_url: str, explicit_path: str | None = None) -> Path:
    if explicit_path:
        return Path(explicit_path).expanduser()
    digest = hashlib.sha256(server_url.rstrip("/").encode("utf-8")).hexdigest()[:24]
    return TOKEN_DIR / f"{digest}.token"


def read_file_token(server_url: str, explicit_path: str | None = None) -> str | None:
    path = token_file_path(server_url, explicit_path)
    if not path.exists():
        return None
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise CliError(f"Refusing to read token file with unsafe permissions: {path}")
    token = path.read_text(encoding="utf-8").strip()
    return token or None


def store_file_token(server_url: str, token: str, explicit_path: str | None = None) -> Path:
    path = token_file_path(server_url, explicit_path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(token.strip() + "\n")
    os.chmod(path, 0o600)
    return path


def store_token(
    server_url: str,
    token: str,
    *,
    token_file: str | None = None,
    use_keyring: bool = True,
) -> tuple[str, str | None]:
    if use_keyring and store_keyring_token(server_url, token):
        return "keyring", None
    path = store_file_token(server_url, token, token_file)
    return "file", str(path)


def parse_answers(
    raw_answers: list[str],
    questions: list[dict],
) -> dict[str, object]:
    question_types = {question["id"]: question["answer_type"] for question in questions}
    parsed: dict[str, object] = {}
    for raw_answer in raw_answers:
        if "=" not in raw_answer:
            raise CliError("--answer values must use key=value")
        key, value = raw_answer.split("=", 1)
        key = key.strip()
        if key not in question_types:
            raise CliError(f"Unknown intake answer: {key}")
        parsed[key] = _parse_answer_value(question_types[key], value)
    return parsed


def parse_configured_answers(
    config: dict[str, str],
    questions: list[dict],
) -> dict[str, object]:
    raw_answers = [
        f"{key.removeprefix('answer.')}={value}"
        for key, value in config.items()
        if key.startswith("answer.")
    ]
    return parse_answers(raw_answers, questions)


def _parse_answer_value(answer_type: str, value: str) -> object:
    if answer_type in {"multi_select", "string_list"}:
        return [item.strip() for item in value.split(",") if item.strip()]
    if answer_type == "boolean":
        normalized = value.strip().casefold()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0"}:
            return False
        raise CliError("boolean answers must be true or false")
    return value.strip()


def parse_raw_answer_strings(raw_answers: list[str] | None) -> dict[str, str]:
    answers: dict[str, str] = {}
    for raw_answer in raw_answers or []:
        if "=" not in raw_answer:
            raise CliError("--answer values must use key=value")
        key, value = raw_answer.split("=", 1)
        key = key.strip()
        if not key:
            raise CliError("--answer values must include a non-empty key")
        answers[key] = value.strip()
    return answers


def detect_git_context(repo_path: str) -> dict[str, str]:
    cwd = Path(repo_path).expanduser()
    return {
        key: value
        for key, value in {
            "git_remote": _git(["config", "--get", "remote.origin.url"], cwd),
            "git_branch": _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd),
            "git_commit": _git(["rev-parse", "HEAD"], cwd),
        }.items()
        if value
    }


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


SKIPPED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
}

DEPENDENCY_LOCK_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "poetry.lock",
    "pipfile.lock",
    "go.sum",
    "cargo.lock",
    "gemfile.lock",
}

IAC_SUFFIXES = {".tf", ".tfvars"}
CONFIG_SUFFIXES = {".yaml", ".yml", ".toml", ".ini", ".conf"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php", ".cs"}
TEST_PATH_PARTS = {"test", "tests", "__tests__", "spec", "specs"}
DOC_SUFFIXES = {".md", ".mdx", ".rst", ".txt"}


def build_manifest(paths: list[str], *, max_files: int) -> list[dict]:
    files: list[tuple[Path, Path]] = []
    for raw_path in paths:
        root = Path(raw_path).expanduser()
        if not root.exists():
            raise CliError(f"Bundle path does not exist: {raw_path}")
        if root.is_file():
            files.append((root, root.parent))
            continue
        for candidate in root.rglob("*"):
            if len(files) >= max_files:
                break
            if not candidate.is_file() or _is_skipped_path(candidate):
                continue
            files.append((candidate, root))
    unique_files = sorted(
        {(path.resolve(), base.resolve()) for path, base in files},
        key=lambda item: str(item[0]),
    )
    manifest = [_manifest_item(path, base) for path, base in unique_files]
    if not manifest:
        raise CliError("No bundle files found after applying safety exclusions.")
    return manifest


def _is_skipped_path(path: Path) -> bool:
    return any(part.casefold() in SKIPPED_DIRS for part in path.parts)


def _manifest_item(path: Path, base: Path) -> dict:
    digest = hashlib.sha256()
    byte_size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            byte_size += len(chunk)
            digest.update(chunk)
    return {
        "path": _display_path(path, base),
        "file_kind": _classify_file(path),
        "sha256": digest.hexdigest(),
        "byte_size": byte_size,
        "source": "cli",
    }


def _display_path(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.name


def _classify_file(path: Path) -> str:
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    parts = {part.casefold() for part in path.parts}
    if name in DEPENDENCY_LOCK_NAMES:
        return "dependency_lock"
    if suffix in IAC_SUFFIXES or name in {"dockerfile", "cloudbuild.yaml"}:
        return "iac"
    if parts & TEST_PATH_PARTS or name.startswith("test_") or name.endswith(".test.ts"):
        return "test"
    if suffix in DOC_SUFFIXES:
        return "doc"
    if suffix in SOURCE_SUFFIXES:
        return "source"
    if suffix in CONFIG_SUFFIXES:
        return "config"
    return "other"


def build_review_payload(args: argparse.Namespace, answers: dict[str, object]) -> dict:
    payload = {
        "app_name": args.app_name,
        "threat_model_id": args.threat_model_id,
        "invocation_surface": "cli",
        "input_kind": args.review_type,
        "commit_sha": args.commit_sha,
        "bundle_hash": args.bundle_hash,
        "requested_tools": args.tool or [],
        "intake_answers": answers,
    }
    if args.idempotency_key:
        payload["idempotency_key"] = args.idempotency_key
    return {
        key: value
        for key, value in payload.items()
        if value is not None and value != ""
    }


def build_threat_model_payload(args: argparse.Namespace, answers: dict[str, object]) -> dict:
    return threat_model_fields_from_intake(answers, fallback_app_name=args.app_name)


def wait_for_review(
    client: ThreatGenixClient,
    review_id: str,
    *,
    timeout_seconds: float,
    interval_seconds: float,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last_status: str | None = None
    while True:
        response = client.get_json(f"/api/agent/reviews/{review_id}/status")
        review = response.get("review", response)
        status = str(review.get("status") or "unknown")
        if status != last_status:
            print(f"wait_status={status}")
            last_status = status
        if status in TERMINAL_REVIEW_STATUSES:
            return response
        if time.monotonic() >= deadline:
            raise CliError(
                f"Timed out waiting for review {review_id} after {timeout_seconds:g}s; "
                f"last_status={status}"
            )
        time.sleep(max(interval_seconds, 0.0))


def start_review_decision(client: ThreatGenixClient, review_id: str) -> dict:
    return client.post_json(f"/api/agent/reviews/{review_id}/rerun", {})


def command_login(
    args: argparse.Namespace,
    client_factory: Callable[[str, str | None], ThreatGenixClient],
) -> int:
    config = load_config(Path(args.config))
    server_url = resolve_server_url(config, args.server_url)
    token = args.token
    if not token:
        if not args.email:
            raise CliError("Use --token or --email to log in.")
        password = args.password or getpass.getpass("ThreatGenix password: ")
        response = client_factory(server_url, None).post_json(
            "/api/auth/login",
            {"email": args.email, "password": password},
        )
        token = response.get("access_token")
    if not isinstance(token, str) or not token.strip():
        raise CliError("Login did not return an access token.")
    backend, path = store_token(
        server_url,
        token,
        token_file=args.token_file,
        use_keyring=not args.no_keyring,
    )
    print(f"Logged in to {server_url}")
    if backend == "keyring":
        print("token_storage=keyring")
    else:
        print(f"token_storage=file path={path}")
        print("warning=keyring unavailable; fallback token file is restricted to 0600")
    return 0


def command_init(args: argparse.Namespace, _: Callable[[str, str | None], ThreatGenixClient]) -> int:
    config_path = Path(args.config)
    git_context = detect_git_context(args.repo_path) if args.detect_git else {}
    app_name = args.app_name or Path(args.repo_path).expanduser().resolve().name
    write_config(
        config_path,
        server_url=args.server_url,
        web_url=args.web_url,
        app_name=app_name,
        default_review_type=args.review_type,
        git_remote=git_context.get("git_remote"),
        git_branch=git_context.get("git_branch"),
        git_commit=git_context.get("git_commit"),
        intake_answers=parse_raw_answer_strings(args.answer),
    )
    print(f"Wrote {config_path}")
    print(f"app_name={app_name}")
    if git_context.get("git_remote"):
        print(f"git_remote={git_context['git_remote']}")
    print("secrets_written=false")
    return 0


def command_review(
    args: argparse.Namespace,
    client_factory: Callable[[str, str | None], ThreatGenixClient],
) -> int:
    config = load_config(Path(args.config))
    server_url = resolve_server_url(config, args.server_url)
    token = resolve_token(config, args.token, server_url=server_url)
    if not token:
        raise CliError("Missing token. Run threatgenix login, set THREATGENIX_TOKEN, or pass --token.")
    args.app_name = args.app_name or config.get("app_name")
    if not args.app_name:
        raise CliError("Missing app name. Run threatgenix init --app-name or pass --app-name.")
    args.review_type = args.review_type or config.get("review_type") or "diff"
    if not args.commit_sha:
        args.commit_sha = _git(["rev-parse", "HEAD"], Path.cwd()) or config.get("git_commit")
    client = client_factory(server_url, token)
    question_bank = client.get_json(
        "/api/reviews/intake/questions",
        {"review_type": args.review_type},
    )
    answers = {
        **parse_configured_answers(config, question_bank["questions"]),
        **parse_answers(args.answer or [], question_bank["questions"]),
    }
    validation = client.post_json(
        "/api/reviews/intake/validate",
        {
            "version": question_bank["version"],
            "review_type": args.review_type,
            "answers": answers,
        },
    )
    if not validation.get("valid"):
        missing = ", ".join(validation.get("missing_required", []))
        errors = ", ".join(validation.get("errors", []))
        raise CliError(f"Invalid intake answers. missing=[{missing}] errors=[{errors}]")
    if args.create_threat_model and args.threat_model_id:
        raise CliError("Use either --threat-model-id or --create-threat-model, not both.")
    if args.enqueue_scanners and not args.upload_bundle:
        raise CliError("--enqueue-scanners requires --upload-bundle.")
    if args.enqueue_scanners and not (args.threat_model_id or args.create_threat_model):
        raise CliError(
            "--enqueue-scanners requires --threat-model-id or --create-threat-model "
            "because scanner jobs are linked to a threat model."
        )
    if args.create_threat_model:
        model = client.post_json(
            "/api/threat-models",
            build_threat_model_payload(args, validation["normalized_answers"]),
        )
        args.threat_model_id = model["id"]
        print(f"threat_model_id={model['id']}")
    review = client.post_json(
        "/api/reviews",
        build_review_payload(args, validation["normalized_answers"]),
    )
    print(f"review_id={review['id']}")
    print(f"status={review['status']}")
    if args.upload_bundle:
        manifest = build_manifest(args.source_path or ["."], max_files=args.max_bundle_files)
        bundle = client.post_json(
            f"/api/reviews/{review['id']}/bundles",
            {
                "bundle_kind": args.review_type,
                "source": "cli",
                "manifest": manifest,
            },
        )
        print(f"bundle_id={bundle['id']}")
        print(f"bundle_hash={bundle['content_hash']}")
        print(f"bundle_files={bundle['file_count']}")
        if args.enqueue_scanners:
            enqueue = client.post_json(
                f"/api/reviews/{review['id']}/scanner-jobs",
                {
                    "bundle_id": bundle["id"],
                    "tools": args.tool or None,
                    "external_active_authorized": args.external_active_authorized,
                    "external_targets": args.external_target or [],
                },
            )
            print(f"scanner_jobs={len(enqueue.get('jobs', []))}")
    web_url = config.get("web_url")
    if web_url:
        print(f"url={web_url.rstrip('/')}/reviews/{review['id']}")
    if args.wait:
        rerun = start_review_decision(client, review["id"])
        print(f"rerun_indexed_entries={rerun.get('indexed_entry_count', 0)}")
        rerun_decision = rerun.get("decision")
        if isinstance(rerun_decision, dict) and rerun_decision.get("decision"):
            print(f"rerun_decision={rerun_decision['decision']}")
        status_response = wait_for_review(
            client,
            review["id"],
            timeout_seconds=args.wait_timeout,
            interval_seconds=args.wait_interval,
        )
        waited_review = status_response.get("review", status_response)
        if waited_review.get("decision"):
            print(f"decision={waited_review['decision']}")
        if status_response.get("web_url"):
            print(f"url={status_response['web_url']}")
    return 0


def command_status(
    args: argparse.Namespace,
    client_factory: Callable[[str, str | None], ThreatGenixClient],
) -> int:
    config = load_config(Path(args.config))
    server_url = resolve_server_url(config, args.server_url)
    token = resolve_token(config, args.token, server_url=server_url)
    if not token:
        raise CliError("Missing token. Run threatgenix login, set THREATGENIX_TOKEN, or pass --token.")
    status = client_factory(server_url, token).get_json(
        f"/api/agent/reviews/{args.review_id}/status"
    )
    review = status.get("review", status)
    print(f"review_id={review['id']}")
    print(f"status={review['status']}")
    if review.get("decision"):
        print(f"decision={review['decision']}")
    if status.get("web_url"):
        print(f"url={status['web_url']}")
    return 0


def command_open(
    args: argparse.Namespace,
    client_factory: Callable[[str, str | None], ThreatGenixClient],
) -> int:
    config = load_config(Path(args.config))
    server_url = resolve_server_url(config, args.server_url)
    token = resolve_token(config, args.token, server_url=server_url)
    if token:
        response = client_factory(server_url, token).get_json(
            f"/api/agent/reviews/{args.review_id}/open"
        )
        print(response["web_url"])
        return 0
    web_url = args.web_url or config.get("web_url")
    if not web_url:
        raise CliError(
            "Missing web_url or token. Run threatgenix init --web-url, pass --web-url, or set THREATGENIX_TOKEN."
        )
    print(f"{web_url.rstrip('/')}/reviews/{args.review_id}")
    return 0


def command_findings(
    args: argparse.Namespace,
    client_factory: Callable[[str, str | None], ThreatGenixClient],
) -> int:
    config = load_config(Path(args.config))
    server_url = resolve_server_url(config, args.server_url)
    token = resolve_token(config, args.token, server_url=server_url)
    if not token:
        raise CliError("Missing token. Run threatgenix login, set THREATGENIX_TOKEN, or pass --token.")
    response = client_factory(server_url, token).get_json(
        f"/api/agent/reviews/{args.review_id}/findings",
        {"limit": str(args.limit)},
    )
    findings = response.get("findings", [])
    print(f"review_id={response.get('review_id', args.review_id)}")
    print(f"findings={len(findings)}")
    for finding in findings:
        title = finding.get("title") or finding.get("summary") or finding.get("item_type") or "finding"
        severity = finding.get("severity") or finding.get("risk_rating") or "unknown"
        finding_id = finding.get("id") or finding.get("content_hash") or "unknown"
        print(f"- id={finding_id} severity={severity} title={title}")
    return 0


def build_mcp_config(
    server_url: str,
    *,
    command: str = DEFAULT_MCP_COMMAND,
    module_mode: bool = False,
) -> dict:
    args = ["-m", DEFAULT_MCP_MODULE] if module_mode else []
    return {
        "mcpServers": {
            "threatgenix": {
                "command": command,
                "args": args,
                "env": {
                    "THREATGENIX_API_URL": server_url.rstrip("/"),
                    "THREATGENIX_TOKEN": "${THREATGENIX_TOKEN}",
                },
            }
        }
    }


def command_mcp_config(
    args: argparse.Namespace,
    _: Callable[[str, str | None], ThreatGenixClient],
) -> int:
    config = load_config(Path(args.config))
    server_url = resolve_server_url(config, args.server_url)
    print(
        json.dumps(
            build_mcp_config(
                server_url,
                command=args.command,
                module_mode=args.module_mode,
            ),
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threatgenix")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser("login")
    login_parser.add_argument("--server-url")
    login_parser.add_argument("--email")
    login_parser.add_argument("--password")
    login_parser.add_argument("--token")
    login_parser.add_argument("--token-file")
    login_parser.add_argument("--no-keyring", action="store_true")
    login_parser.set_defaults(handler=command_login)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--server-url", default=DEFAULT_SERVER_URL)
    init_parser.add_argument("--web-url")
    init_parser.add_argument("--app-name")
    init_parser.add_argument("--repo-path", default=".")
    init_parser.add_argument("--review-type", choices=["diff", "snapshot", "metadata"], default="diff")
    init_parser.add_argument("--answer", action="append")
    init_parser.add_argument("--no-git-detect", dest="detect_git", action="store_false")
    init_parser.set_defaults(detect_git=True)
    init_parser.set_defaults(handler=command_init)

    review_parser = subparsers.add_parser("review")
    review_parser.add_argument("--server-url")
    review_parser.add_argument("--token")
    review_parser.add_argument("--app-name")
    review_parser.add_argument("--review-type", choices=["diff", "snapshot", "metadata"])
    review_parser.add_argument("--commit-sha")
    review_parser.add_argument("--bundle-hash")
    review_parser.add_argument("--tool", action="append")
    review_parser.add_argument("--answer", action="append")
    review_parser.add_argument("--idempotency-key")
    review_parser.add_argument("--threat-model-id")
    review_parser.add_argument("--create-threat-model", action="store_true")
    review_parser.add_argument("--upload-bundle", action="store_true")
    review_parser.add_argument("--source-path", action="append")
    review_parser.add_argument("--max-bundle-files", type=int, default=5000)
    review_parser.add_argument("--enqueue-scanners", action="store_true")
    review_parser.add_argument("--external-active-authorized", action="store_true")
    review_parser.add_argument("--external-target", action="append")
    review_parser.add_argument(
        "--wait",
        action="store_true",
        help="Poll review status until it reaches a terminal lifecycle state.",
    )
    review_parser.add_argument("--wait-timeout", type=float, default=600.0)
    review_parser.add_argument("--wait-interval", type=float, default=5.0)
    review_parser.set_defaults(handler=command_review)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--server-url")
    status_parser.add_argument("--token")
    status_parser.add_argument("review_id")
    status_parser.set_defaults(handler=command_status)

    open_parser = subparsers.add_parser("open")
    open_parser.add_argument("--server-url")
    open_parser.add_argument("--token")
    open_parser.add_argument("--web-url")
    open_parser.add_argument("review_id")
    open_parser.set_defaults(handler=command_open)

    findings_parser = subparsers.add_parser("findings")
    findings_parser.add_argument("--server-url")
    findings_parser.add_argument("--token")
    findings_parser.add_argument("--limit", type=int, default=20)
    findings_parser.add_argument("review_id")
    findings_parser.set_defaults(handler=command_findings)

    mcp_config_parser = subparsers.add_parser("mcp-config")
    mcp_config_parser.add_argument("--server-url")
    mcp_config_parser.add_argument("--command", default=DEFAULT_MCP_COMMAND)
    mcp_config_parser.add_argument(
        "--module-mode",
        action="store_true",
        help="Emit python -m app.cli.threatgenix_mcp args for source-tree usage.",
    )
    mcp_config_parser.set_defaults(handler=command_mcp_config)
    return parser


def main(
    argv: list[str] | None = None,
    client_factory: Callable[[str, str | None], ThreatGenixClient] = ThreatGenixClient,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args, client_factory)
    except CliError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
