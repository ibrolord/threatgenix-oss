from __future__ import annotations

import asyncio
import ast
import json
import os
import re
import shlex
import tarfile
import tempfile
import tomllib
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlparse

import httpx
import yaml

from app.schemas.environment_evidence import (
    CloudFinding,
    CloudScanEvidence,
    CodeControlSignal,
    CodeEvidenceSummary,
    CodeRiskSignal,
    CodeSurface,
    GitHubPullRequestChangedFile,
    GitHubPullRequestMetadata,
    IacEvidence,
    GitHubImportTransport,
    RepositoryDfdSeedBoundarySuggestion,
    RepositoryDfdSeedFlowSuggestion,
    RepositoryDfdSeedSuggestion,
    RepositoryEvidence,
    RouteAuthEntry,
)

REPOSITORY_EVIDENCE_MAX_BYTES = 25 * 1024 * 1024
CLOUD_SCAN_EVIDENCE_MAX_BYTES = 50 * 1024 * 1024
IAC_EVIDENCE_MAX_BYTES = 25 * 1024 * 1024
MAX_REPOSITORY_FILES = 250
MAX_TEXT_FILE_BYTES = 300_000
ENVIRONMENT_CONTEXT_CHAR_BUDGET = 3_000
MAX_PREVIEW_ITEMS = 8
MAX_PULL_REQUEST_CHANGED_FILES = 300
MAX_DFD_SEED_SUGGESTIONS = 12
MAX_DFD_SEED_BOUNDARY_SUGGESTIONS = 8

_ARCHIVE_EXTENSIONS = (".zip", ".tar", ".tar.gz", ".tgz")
_REPO_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt", ".kts",
    ".rs", ".php", ".cs", ".tf", ".yaml", ".yml", ".toml", ".json", ".xml",
    ".md", ".txt", ".sh",
}
_REPO_INTERESTING_FILENAMES = {
    "package.json", "pyproject.toml", "requirements.txt", "go.mod", "cargo.toml",
    "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "gemfile",
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml",
    "compose.yaml", "serverless.yml", "serverless.yaml", "vercel.json", "procfile",
    "readme.md", "readme", "main.py", "app.py", "server.py", "manage.py",
    "main.go", "main.rs", "next.config.js", "next.config.mjs", "next.config.ts",
}
_SKIP_REPO_PATH_RE = re.compile(
    r"(^|/)(\.git/|node_modules/|dist/|build/|coverage/|target/|vendor/|__pycache__/|"
    r"\.venv/|venv/|\.idea/|\.next/|\.terraform/|\.aws-sam/)",
    re.IGNORECASE,
)
_SECRET_PATH_RE = re.compile(
    r"(^|/)\.env($|\.)|secrets?|private[_-]?key|id_rsa|credentials",
    re.IGNORECASE,
)
_ENTRYPOINT_PATH_RE = re.compile(
    r"(^|/)(main|app|server|index)\.(py|js|ts|tsx|go|rb|php|java|rs)$|"
    r"(^|/)(pages/api/|app/api/|routes/|controllers/|handlers/)",
    re.IGNORECASE,
)
_AUTH_PATH_RE = re.compile(
    r"(auth|login|logout|oauth|oidc|saml|jwt|session|callback|signin|signup|mfa|admin)",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(auth|admin|callback|webhook|token|payment|billing|settlement|upload|secret|"
    r"vendor|support|break[-_]?glass|diagnostic)",
    re.IGNORECASE,
)
_FRAMEWORK_HINTS = {
    "fastapi": "FastAPI",
    "django": "Django",
    "flask": "Flask",
    "celery": "Celery",
    "next": "Next.js",
    "react": "React",
    "express": "Express",
    "nestjs": "NestJS",
    "koa": "Koa",
    "fastify": "Fastify",
    "spring-boot": "Spring Boot",
    "spring": "Spring",
    "quarkus": "Quarkus",
    "gin": "Gin",
    "chi": "Chi",
    "rails": "Rails",
    "sinatra": "Sinatra",
    "actix-web": "Actix",
    "axum": "Axum",
}
_DATA_STORE_HINTS = {
    "postgres": "PostgreSQL",
    "psycopg": "PostgreSQL",
    "mysql": "MySQL",
    "mongo": "MongoDB",
    "mongoose": "MongoDB",
    "redis": "Redis",
    "dynamodb": "DynamoDB",
    "sqlalchemy": "SQL database",
    "prisma": "SQL database",
    "typeorm": "SQL database",
    "s3": "Object storage",
}
_QUEUE_HINTS = {
    "kafka": "Kafka",
    "rabbitmq": "RabbitMQ",
    "sqs": "Amazon SQS",
    "pubsub": "Google Pub/Sub",
    "celery": "Task queue",
    "sns": "Amazon SNS",
}
_INTEGRATION_HINTS = {
    "stripe": "Stripe",
    "twilio": "Twilio",
    "sendgrid": "SendGrid",
    "auth0": "Auth0",
    "okta": "Okta",
    "plaid": "Plaid",
    "snowflake": "Snowflake",
    "slack": "Slack",
    "salesforce": "Salesforce",
    "aws-sdk": "AWS services",
}
_AUTH_MECHANISM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OAuth 2.0 / OIDC", re.compile(r"(oidc|oauth|openid|auth0|okta)", re.IGNORECASE)),
    ("JWT bearer tokens", re.compile(r"\bjwt\b|python-jose|jose", re.IGNORECASE)),
    ("Session cookies", re.compile(r"\bsession\b|cookie", re.IGNORECASE)),
    ("API keys", re.compile(r"api[_-]?key|x-api-key", re.IGNORECASE)),
    ("SAML", re.compile(r"\bsaml\b", re.IGNORECASE)),
    ("MFA", re.compile(r"\bmfa\b|multi-factor", re.IGNORECASE)),
]
_INFRA_RESOURCE_HINTS = {
    "aws_api_gateway_rest_api": "AWS API Gateway",
    "aws_apigatewayv2_api": "AWS API Gateway",
    "aws_sqs_queue": "Amazon SQS queue",
    "aws_sns_topic": "Amazon SNS topic",
    "aws_db_instance": "Amazon RDS instance",
    "aws_rds_cluster": "Amazon RDS cluster",
    "aws_lambda_function": "AWS Lambda",
    "aws_ecs_service": "Amazon ECS service",
    "aws_iam_role": "IAM role",
    "aws_s3_bucket": "Amazon S3 bucket",
}
_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
_IAC_TEXT_EXTENSIONS = {".tf", ".tfvars", ".json", ".yaml", ".yml", ".template"}
_TERRAFORM_RESOURCE_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"', re.IGNORECASE)
_K8S_KIND_RE = re.compile(r"^\s*kind:\s*([A-Za-z0-9]+)\s*$", re.MULTILINE)
_K8S_NAME_RE = re.compile(r"^\s*name:\s*([A-Za-z0-9._:-]+)\s*$", re.MULTILINE)
_FASTAPI_PREFIX_RE = re.compile(r"APIRouter\([^)]*prefix\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_PYTHON_ROUTE_RE = re.compile(r"@\s*(?:\w+\.)?(get|post|put|patch|delete|options|head)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_EXPRESS_ROUTE_RE = re.compile(r"\b(?:router|app)\.(get|post|put|patch|delete|options|head)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_EXPRESS_ROUTE_WITH_ARGS_RE = re.compile(
    r"\b(?:router|app)\.(get|post|put|patch|delete|options|head)\(\s*[\"']([^\"']+)[\"']\s*,([\s\S]{0,400}?)\)",
    re.IGNORECASE,
)
_EXPRESS_USE_RE = re.compile(r"\b(?:router|app)\.use\(([\s\S]{0,240}?)\)", re.IGNORECASE)
_NEXT_APP_ROUTE_RE = re.compile(r"(^|/)(app|pages)/api/(.+?)/(route\.[jt]sx?|index\.[jt]sx?|[^/]+\.[jt]sx?)$", re.IGNORECASE)
_EXPORTED_HANDLER_RE = re.compile(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b")
_BOTO3_CLIENT_RE = re.compile(r"boto3\.client\(\s*[\"']([^\"']+)[\"']")
_STRIPE_CALL_RE = re.compile(r"\bstripe\.[A-Za-z0-9_]+\.")
_HTTP_CLIENT_CALL_RE = re.compile(r"\b(requests|httpx|axios|fetch)\.(get|post|put|patch|delete)\b", re.IGNORECASE)
_AUTH_GUARD_NAME_RE = re.compile(
    r"(auth|login|jwt|token|session|permission|protect|guard|secure|role|scope|oauth|oidc|saml|mfa|"
    r"current_user|currentaccount|current_account|principal|identity|require_|verify_)",
    re.IGNORECASE,
)
_SENSITIVE_DATA_SIGNAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Credentials", re.compile(r"\b(password|passwd|pwd|client[_-]?secret|api[_-]?key|private[_-]?key|secret)\b", re.IGNORECASE)),
    ("Tokens and session secrets", re.compile(r"\b(token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|bearer|session[_-]?id|sessionid)\b", re.IGNORECASE)),
    ("Payment card data", re.compile(r"\b(card[_-]?number|cardnumber|pan|cvv|cvc|expiry|exp[_-]?(month|year)|payment[_-]?method)\b", re.IGNORECASE)),
    ("Financial account data", re.compile(r"\b(account[_-]?number|accountnumber|routing[_-]?number|routingnumber|iban|sort[_-]?code|bank[_-]?account)\b", re.IGNORECASE)),
    ("Government identity data", re.compile(r"\b(ssn|sin|passport|driver[_-]?license|tax[_-]?id)\b", re.IGNORECASE)),
    ("Personal contact data", re.compile(r"\b(email|phone|address|birthdate|date[_-]?of[_-]?birth|dob)\b", re.IGNORECASE)),
]
_RAW_INPUT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Raw JSON/body access", re.compile(r"(request\.(get_json|json|data|body)|await\s+request\.(json|body)\(|req\.(body|query|params)\b)", re.IGNORECASE)),
]
_VALIDATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Schema validation", re.compile(r"(pydantic|BaseModel|model_validate|marshmallow|schema\.load|schema\.parse|safeParse|Joi|zod|express-validator|validationResult)", re.IGNORECASE)),
    ("Validator middleware", re.compile(r"\b(validate\w*|validator\w*|schema\w*)\b", re.IGNORECASE)),
]
_OUTBOUND_AUTH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Authorization header", re.compile(r"(Authorization|Bearer\s+[A-Za-z0-9._-]+|['\"]Bearer ['\"]|headers\s*[:=].*(authorization|x-api-key)|x-api-key)", re.IGNORECASE | re.DOTALL)),
    ("Signature or HMAC", re.compile(r"(signature|hmac|signing|signed|x-signature|webhook_secret)", re.IGNORECASE)),
]
_EXPRESS_IGNORED_TOKENS = {
    "req", "res", "next", "async", "await", "return", "true", "false", "null", "undefined",
    "router", "app", "json", "status", "send", "Response", "Request",
}
_CLOUD_FINDING_CATEGORY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("public_storage", re.compile(r"(public.*s3|public.*bucket|publicly accessible bucket|blob public access)", re.IGNORECASE)),
    ("internet_exposure", re.compile(r"(0\.0\.0\.0/0|::/0|internet-facing|public ip|exposed to the internet|open security group)", re.IGNORECASE)),
    ("broad_iam", re.compile(r"(\*:\*|administratoraccess|iam wildcard|excessive permissions|full access)", re.IGNORECASE)),
    ("cross_account_trust", re.compile(r"(cross-account|cross account|external principal|assume role|trusted entity)", re.IGNORECASE)),
    ("encryption_gap", re.compile(r"(kms|encryption|unencrypted|not encrypted|default encryption disabled)", re.IGNORECASE)),
    ("logging_gap", re.compile(r"(cloudtrail|logging disabled|log delivery|audit log|flow logs disabled)", re.IGNORECASE)),
    ("mfa_gap", re.compile(r"(mfa disabled|no mfa|console access without mfa)", re.IGNORECASE)),
    ("vulnerable_service", re.compile(r"(vulnerab|outdated|unsupported|critical patch)", re.IGNORECASE)),
]
_GITHUB_HOSTS = {"github.com", "www.github.com"}
_GITHUB_REPOSITORY_PART_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_GITHUB_PULL_REF_RE = re.compile(r"^refs/pull/(\d+)/(?:head|merge)$")
_GIT_COMMAND_TIMEOUT_SECONDS = 60.0
_GITHUB_KNOWN_HOSTS = "\n".join(
    [
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
        "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
    ]
)


@dataclass(slots=True)
class _RouteDefinition:
    method: str
    path: str
    source_file: str
    line_number: int | None = None
    auth_guards: list[str] = field(default_factory=list)
    sensitive_data_signals: list[str] = field(default_factory=list)
    validation_signals: list[str] = field(default_factory=list)
    outbound_call_signals: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)


class EvidenceValidationError(ValueError):
    def __init__(self, detail: str, *, status_code: int = 400) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class _GitCommandError(RuntimeError):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True)
class GitHubRepositoryImportTarget:
    repository: str
    ref: str | None
    reference: str | None
    pull_request_number: int | None
    pull_request_url: str | None


@dataclass(frozen=True)
class _GitHubPullRequestUrlParts:
    repository: str
    number: int
    url: str


def normalize_github_repository_slug(repository: str) -> str:
    candidate = repository.strip()
    if not candidate:
        raise EvidenceValidationError("GitHub repository is required.")

    if candidate.startswith("git@github.com:"):
        candidate = candidate.split("git@github.com:", 1)[1]
    elif candidate.startswith(("ssh://", "git+ssh://")):
        parsed = urlparse(candidate)
        if (parsed.hostname or "").lower() not in _GITHUB_HOSTS:
            raise EvidenceValidationError(
                "GitHub repository must be a github.com URL or an owner/repo slug."
            )
        candidate = parsed.path.lstrip("/")
    elif candidate.startswith(("https://", "http://")):
        parsed = urlparse(candidate)
        if (parsed.netloc or "").lower() not in _GITHUB_HOSTS:
            raise EvidenceValidationError(
                "GitHub repository must be a github.com URL or an owner/repo slug."
            )
        candidate = parsed.path.lstrip("/")

    candidate = candidate.rstrip("/")
    if candidate.endswith(".git"):
        candidate = candidate[:-4]

    parts = [part for part in candidate.split("/") if part]
    if len(parts) < 2:
        raise EvidenceValidationError(
            "GitHub repository must be provided as owner/repo or a github.com repository URL."
        )

    owner, repo = parts[0], parts[1]
    if not _GITHUB_REPOSITORY_PART_RE.fullmatch(owner) or not _GITHUB_REPOSITORY_PART_RE.fullmatch(repo):
        raise EvidenceValidationError("GitHub repository contains unsupported characters.")
    return f"{owner}/{repo}"


def parse_github_pull_request_url(url: str | None) -> _GitHubPullRequestUrlParts | None:
    clean_url = (url or "").strip()
    if not clean_url:
        return None
    if not clean_url.startswith(("http://", "https://")):
        return None
    parsed = urlparse(clean_url)
    if parsed.scheme not in {"http", "https"} or (parsed.netloc or "").lower() not in _GITHUB_HOSTS:
        raise EvidenceValidationError("GitHub pull request URL must use github.com.")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4 or parts[2] != "pull":
        return None
    try:
        pull_request_number = int(parts[3])
    except ValueError as exc:
        raise EvidenceValidationError("GitHub pull request URL contains an invalid pull request number.") from exc
    if pull_request_number < 1:
        raise EvidenceValidationError("GitHub pull request number must be greater than zero.")
    repository_slug = normalize_github_repository_slug(f"{parts[0]}/{parts[1]}")
    return _GitHubPullRequestUrlParts(
        repository=repository_slug,
        number=pull_request_number,
        url=f"https://github.com/{repository_slug}/pull/{pull_request_number}",
    )


def resolve_github_repository_import_target(
    *,
    repository: str,
    ref: str | None = None,
    reference: str | None = None,
    pull_request_number: int | None = None,
    pull_request_url: str | None = None,
) -> GitHubRepositoryImportTarget:
    repository_pr = parse_github_pull_request_url(repository)
    explicit_pr = parse_github_pull_request_url(pull_request_url)
    repository_slug = (
        repository_pr.repository if repository_pr is not None else normalize_github_repository_slug(repository)
    )

    if explicit_pr is not None and explicit_pr.repository != repository_slug:
        raise EvidenceValidationError(
            "GitHub pull request URL must belong to the same repository as the import target."
        )

    inferred_pr_number = infer_github_pull_request_number(ref)
    candidate_numbers = [
        value
        for value in (
            pull_request_number,
            repository_pr.number if repository_pr is not None else None,
            explicit_pr.number if explicit_pr is not None else None,
            inferred_pr_number,
        )
        if value is not None
    ]
    if candidate_numbers and any(number != candidate_numbers[0] for number in candidate_numbers):
        raise EvidenceValidationError(
            "GitHub pull request number, URL, and ref must point at the same pull request."
        )

    resolved_pr_number = candidate_numbers[0] if candidate_numbers else None
    clean_ref = (ref or "").strip() or None
    if resolved_pr_number is not None and clean_ref is None:
        clean_ref = f"refs/pull/{resolved_pr_number}/head"

    clean_reference = (reference or "").strip() or None
    if resolved_pr_number is not None and clean_reference is None:
        clean_reference = f"Pull request #{resolved_pr_number}"

    resolved_pr_url = (
        (explicit_pr.url if explicit_pr is not None else None)
        or (repository_pr.url if repository_pr is not None else None)
        or (f"https://github.com/{repository_slug}/pull/{resolved_pr_number}" if resolved_pr_number else None)
    )

    return GitHubRepositoryImportTarget(
        repository=repository_slug,
        ref=clean_ref,
        reference=clean_reference,
        pull_request_number=resolved_pr_number,
        pull_request_url=resolved_pr_url,
    )


def build_github_repository_reference(
    repository_slug: str,
    ref: str | None,
    reference: str | None,
) -> str | None:
    base = repository_slug if not ref else f"{repository_slug}@{ref}"
    scope_note = (reference or "").strip()
    combined = f"{base} :: {scope_note}" if scope_note else base
    return _truncate_text(combined, 255) or None


def infer_github_pull_request_number(ref: str | None) -> int | None:
    clean_ref = (ref or "").strip()
    if not clean_ref:
        return None
    match = _GITHUB_PULL_REF_RE.match(clean_ref)
    if match:
        return int(match.group(1))
    return None


def build_github_ssh_remote_url(repository_slug: str) -> str:
    return f"git@github.com:{repository_slug}.git"


def _normalize_ssh_private_key(ssh_private_key: str | None) -> str | None:
    clean_key = (ssh_private_key or "").strip()
    if not clean_key:
        return None
    if "BEGIN " not in clean_key or "PRIVATE KEY" not in clean_key:
        raise EvidenceValidationError(
            "SSH private key must be provided as a valid PEM or OpenSSH private key block."
        )
    return f"{clean_key}\n"


def _build_git_ssh_command(
    *,
    known_hosts_path: Path,
    private_key_path: Path | None = None,
) -> str:
    parts = [
        "ssh",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_path}",
        "-o",
        "ConnectTimeout=15",
    ]
    if private_key_path is not None:
        parts.extend(["-i", str(private_key_path), "-o", "IdentitiesOnly=yes"])
    return shlex.join(parts)


async def _run_git_command(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float = _GIT_COMMAND_TIMEOUT_SECONDS,
) -> tuple[str, str]:
    process = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise EvidenceValidationError(
            "GitHub SSH fetch timed out before the repository could be pulled.",
            status_code=504,
        ) from exc

    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise _GitCommandError(stderr_text.strip() or stdout_text.strip() or "git command failed")
    return stdout_text, stderr_text


def _candidate_git_refs(ref: str | None) -> list[str]:
    clean_ref = (ref or "").strip()
    if not clean_ref:
        return ["HEAD"]

    candidates = [
        clean_ref,
        f"refs/heads/{clean_ref}",
        f"refs/tags/{clean_ref}",
    ]
    return list(dict.fromkeys(candidates))


def _raise_github_ssh_error(detail: str, *, ref: str | None = None) -> None:
    lowered = detail.lower()
    if "permission denied (publickey)" in lowered:
        raise EvidenceValidationError(
            "GitHub SSH authentication failed. Provide a private key with read access to the repository, or use an SSH agent/deploy key.",
            status_code=401,
        )
    if "host key verification failed" in lowered:
        raise EvidenceValidationError(
            "GitHub SSH host key verification failed.",
            status_code=502,
        )
    if "repository not found" in lowered or "could not read from remote repository" in lowered:
        raise EvidenceValidationError(
            "GitHub repository not found, or the SSH credentials do not have access to it.",
            status_code=404,
        )
    if ref and (
        "couldn't find remote ref" in lowered
        or "not our ref" in lowered
        or "reference is not a tree" in lowered
        or "pathspec" in lowered
    ):
        raise EvidenceValidationError(
            "GitHub ref could not be resolved over SSH. Check the branch, tag, or commit.",
            status_code=404,
        )
    raise EvidenceValidationError(
        "GitHub SSH fetch failed. Ensure the repository, ref, and SSH credentials are valid.",
        status_code=502,
    )


def _archive_repository_checkout(checkout_dir: Path) -> bytes:
    buffer = BytesIO()
    added_files = 0
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(checkout_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative_path = path.relative_to(checkout_dir).as_posix()
            if relative_path.startswith(".git/"):
                continue
            if not _is_relevant_repository_path(relative_path) or _SECRET_PATH_RE.search(relative_path):
                continue
            try:
                if path.stat().st_size > MAX_TEXT_FILE_BYTES:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            if len(raw) > MAX_TEXT_FILE_BYTES or _decode_text(raw) is None:
                continue
            archive.writestr(relative_path, raw)
            added_files += 1
            if added_files >= MAX_REPOSITORY_FILES:
                break
    return buffer.getvalue()


async def fetch_github_repository_archive_over_ssh(
    repository: str,
    *,
    ref: str | None = None,
    ssh_private_key: str | None = None,
) -> tuple[bytes, str, str | None]:
    repository_slug = normalize_github_repository_slug(repository)
    clean_ref = (ref or "").strip() or None
    normalized_private_key = _normalize_ssh_private_key(ssh_private_key)

    with tempfile.TemporaryDirectory(prefix="threatgenix-github-ssh-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        repo_dir = temp_dir / "repo"
        repo_dir.mkdir()

        known_hosts_path = temp_dir / "known_hosts"
        known_hosts_path.write_text(f"{_GITHUB_KNOWN_HOSTS}\n", encoding="utf-8")
        known_hosts_path.chmod(0o600)

        private_key_path: Path | None = None
        if normalized_private_key is not None:
            private_key_path = temp_dir / "github_import_key"
            private_key_path.write_text(normalized_private_key, encoding="utf-8")
            private_key_path.chmod(0o600)

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_SSH_COMMAND"] = _build_git_ssh_command(
            known_hosts_path=known_hosts_path,
            private_key_path=private_key_path,
        )

        try:
            await _run_git_command(["git", "init", "--quiet"], cwd=repo_dir, env=env)
            await _run_git_command(
                ["git", "remote", "add", "origin", build_github_ssh_remote_url(repository_slug)],
                cwd=repo_dir,
                env=env,
            )
            last_error: str | None = None
            for candidate_ref in _candidate_git_refs(clean_ref):
                try:
                    await _run_git_command(
                        ["git", "fetch", "--depth", "1", "origin", candidate_ref],
                        cwd=repo_dir,
                        env=env,
                    )
                    break
                except _GitCommandError as exc:
                    last_error = exc.detail
            else:
                _raise_github_ssh_error(last_error or "git fetch failed", ref=clean_ref)

            try:
                await _run_git_command(["git", "checkout", "--quiet", "FETCH_HEAD"], cwd=repo_dir, env=env)
            except _GitCommandError as exc:
                _raise_github_ssh_error(exc.detail, ref=clean_ref)

            archive_bytes = _archive_repository_checkout(repo_dir)
        except _GitCommandError as exc:
            _raise_github_ssh_error(exc.detail, ref=clean_ref)

    if not archive_bytes:
        raise EvidenceValidationError(
            "GitHub repository checkout did not contain any readable manifest or source files."
        )
    return archive_bytes, repository_slug, clean_ref


async def fetch_github_repository_archive(
    repository: str,
    *,
    ref: str | None = None,
    transport: GitHubImportTransport = "https",
    github_token: str | None = None,
    ssh_private_key: str | None = None,
) -> tuple[bytes, str, str | None]:
    if transport == "ssh":
        return await fetch_github_repository_archive_over_ssh(
            repository,
            ref=ref,
            ssh_private_key=ssh_private_key,
        )

    repository_slug = normalize_github_repository_slug(repository)
    clean_ref = (ref or "").strip() or None
    clean_token = (github_token or "").strip() or None

    url = f"https://api.github.com/repos/{repository_slug}/zipball"
    if clean_ref:
        url = f"{url}/{quote(clean_ref, safe='')}"

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "threatgenix/1.0",
    }
    if clean_token:
        headers["Authorization"] = f"Bearer {clean_token}"

    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 200:
        if not response.content:
            raise EvidenceValidationError(
                "GitHub returned an empty repository archive.",
                status_code=502,
            )
        return response.content, repository_slug, clean_ref

    if response.status_code == 401:
        raise EvidenceValidationError(
            "GitHub authentication failed. Provide a valid token with read access to the repository.",
            status_code=401,
        )

    if response.status_code == 403:
        if response.headers.get("x-ratelimit-remaining") == "0":
            raise EvidenceValidationError(
                "GitHub rate limit exceeded while fetching the repository archive. Retry shortly or use an authenticated token.",
                status_code=403,
            )
        raise EvidenceValidationError(
            "GitHub access was denied. Provide a token with read access to the repository.",
            status_code=403,
        )

    if response.status_code == 404:
        raise EvidenceValidationError(
            "GitHub repository not found, or the provided token does not have access to it.",
            status_code=404,
        )

    raise EvidenceValidationError(
        f"GitHub repository archive fetch failed with status {response.status_code}.",
        status_code=502,
    )


async def fetch_github_pull_request_metadata(
    repository: str,
    pull_request_number: int,
    *,
    github_token: str | None = None,
) -> GitHubPullRequestMetadata:
    if pull_request_number < 1:
        raise EvidenceValidationError("GitHub pull request number must be greater than zero.")

    repository_slug = normalize_github_repository_slug(repository)
    clean_token = (github_token or "").strip() or None
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "threatgenix/1.0",
    }
    if clean_token:
        headers["Authorization"] = f"Bearer {clean_token}"

    pr_url = f"https://api.github.com/repos/{repository_slug}/pulls/{pull_request_number}"
    files_url = f"{pr_url}/files"
    changed_files: list[GitHubPullRequestChangedFile] = []
    truncated = False

    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        pr_response = await client.get(pr_url, headers=headers)
        if pr_response.status_code != 200:
            _raise_github_pr_metadata_error(pr_response.status_code, pr_response.headers)
        pr_payload = pr_response.json()

        page = 1
        while True:
            response = await client.get(
                files_url,
                headers=headers,
                params={"per_page": 100, "page": page},
            )
            if response.status_code != 200:
                _raise_github_pr_metadata_error(response.status_code, response.headers)
            file_payload = response.json()
            if not isinstance(file_payload, list) or not file_payload:
                break
            for item in file_payload:
                if len(changed_files) >= MAX_PULL_REQUEST_CHANGED_FILES:
                    truncated = True
                    break
                changed_files.append(
                    GitHubPullRequestChangedFile(
                        path=_truncate_text(str(item.get("filename") or ""), 260),
                        status=_truncate_text(str(item.get("status") or "modified"), 40),
                        previous_path=_truncate_text(str(item.get("previous_filename") or ""), 260)
                        or None,
                        additions=_coerce_int(item.get("additions")),
                        deletions=_coerce_int(item.get("deletions")),
                        changes=_coerce_int(item.get("changes")),
                    )
                )
            if truncated or len(file_payload) < 100:
                break
            page += 1

    return GitHubPullRequestMetadata(
        repository=repository_slug,
        number=pull_request_number,
        url=_truncate_text(str(pr_payload.get("html_url") or ""), 500) or None,
        title=_truncate_text(str(pr_payload.get("title") or ""), 180) or None,
        state=_truncate_text(str(pr_payload.get("state") or ""), 40) or None,
        base_ref=_truncate_text(str((pr_payload.get("base") or {}).get("ref") or ""), 120) or None,
        head_ref=_truncate_text(str((pr_payload.get("head") or {}).get("ref") or ""), 120) or None,
        head_sha=_truncate_text(str((pr_payload.get("head") or {}).get("sha") or ""), 80) or None,
        changed_files=changed_files,
        changed_file_count=_coerce_int(pr_payload.get("changed_files")) or len(changed_files),
        truncated=truncated,
        fetched_at=datetime.now(timezone.utc),
    )


def _raise_github_pr_metadata_error(status_code: int, headers: dict[str, str]) -> None:
    if status_code == 401:
        raise EvidenceValidationError(
            "GitHub authentication failed while fetching pull request metadata.",
            status_code=401,
        )
    if status_code == 403 and headers.get("x-ratelimit-remaining") == "0":
        raise EvidenceValidationError(
            "GitHub rate limit exceeded while fetching pull request metadata.",
            status_code=403,
        )
    if status_code == 403:
        raise EvidenceValidationError(
            "GitHub access was denied while fetching pull request metadata.",
            status_code=403,
        )
    if status_code == 404:
        raise EvidenceValidationError(
            "GitHub pull request metadata was not found, or the token does not have access to it.",
            status_code=404,
        )
    raise EvidenceValidationError(
        f"GitHub pull request metadata fetch failed with status {status_code}.",
        status_code=502,
    )


def compose_environment_context_summary(
    repository_evidence: dict[str, Any] | RepositoryEvidence | None,
    cloud_scan_evidence: dict[str, Any] | CloudScanEvidence | None,
    iac_evidence: dict[str, Any] | IacEvidence | None = None,
) -> str | None:
    repo = _coerce_repository(repository_evidence)
    cloud = _coerce_cloud_scan(cloud_scan_evidence)
    iac = _coerce_iac(iac_evidence)
    sections: list[str] = []

    if repo:
        sections.append("## Repository Evidence")
        sections.append(f"- Source file: {repo.filename}")
        if repo.connection and repo.connection.provider == "github":
            sync_ref = repo.connection.ref or "default branch"
            sections.append(
                f"- GitHub connection: {repo.connection.repository}@{sync_ref} "
                f"via {repo.connection.transport}; last synced {repo.connection.last_synced_at.isoformat()}"
            )
        if repo.reference:
            sections.append(f"- Repository reference: {repo.reference}")
        if repo.pull_request:
            pr = repo.pull_request
            changed_preview = ", ".join(file.path for file in pr.changed_files[:MAX_PREVIEW_ITEMS])
            sections.append(
                f"- Pull request metadata: #{pr.number}"
                + (f" {pr.title}" if pr.title else "")
                + f"; {pr.changed_file_count} changed file(s)"
                + ("; file list truncated" if pr.truncated else "")
            )
            if changed_preview:
                sections.append(f"- Pull request changed files: {changed_preview}")
        if repo.languages:
            sections.append(f"- Languages: {', '.join(repo.languages[:MAX_PREVIEW_ITEMS])}")
        if repo.frameworks:
            sections.append(f"- Frameworks: {', '.join(repo.frameworks[:MAX_PREVIEW_ITEMS])}")
        if repo.entrypoints:
            sections.append(f"- Entrypoints: {', '.join(repo.entrypoints[:MAX_PREVIEW_ITEMS])}")
        if repo.api_routes:
            sections.append(f"- API routes: {', '.join(repo.api_routes[:MAX_PREVIEW_ITEMS])}")
        if repo.webhook_endpoints:
            sections.append(f"- Callback and webhook endpoints: {', '.join(repo.webhook_endpoints[:MAX_PREVIEW_ITEMS])}")
        if repo.route_auth_map:
            preview = [
                f"{entry.method} {entry.path} -> {', '.join(entry.auth_guards)}"
                for entry in repo.route_auth_map[:MAX_PREVIEW_ITEMS]
                if entry.auth_guards
            ]
            if preview:
                sections.append(f"- Route auth guards: {'; '.join(preview[:4])}")
        if repo.unprotected_routes:
            sections.append(
                "- Routes with no detected auth guard (some may be intentionally public): "
                + ", ".join(repo.unprotected_routes[:MAX_PREVIEW_ITEMS])
            )
        if repo.sensitive_routes:
            sections.append(
                "- Routes touching sensitive data: " + "; ".join(repo.sensitive_routes[:4])
            )
        if repo.routes_with_raw_input:
            sections.append(
                "- Routes with raw request input access: " + "; ".join(repo.routes_with_raw_input[:4])
            )
        risky_sensitive_routes = [
            f"{entry.method} {entry.path} -> {', '.join(entry.sensitive_data_signals)}"
            for entry in repo.route_auth_map[:MAX_PREVIEW_ITEMS]
            if entry.sensitive_data_signals and not entry.auth_guards
        ]
        if risky_sensitive_routes:
            sections.append(
                "- Sensitive-data routes with no detected auth guard: "
                + "; ".join(risky_sensitive_routes[:4])
            )
        route_outbound_preview = [
            f"{entry.method} {entry.path} -> {', '.join(entry.outbound_call_signals)}"
            for entry in repo.route_auth_map[:MAX_PREVIEW_ITEMS]
            if entry.outbound_call_signals
        ]
        if route_outbound_preview:
            sections.append("- Route outbound-call posture: " + "; ".join(route_outbound_preview[:4]))
        if repo.risky_routes:
            sections.append("- Correlated route risks: " + "; ".join(repo.risky_routes[:4]))
        if repo.code_evidence_summary.surface_count:
            summary = repo.code_evidence_summary
            sections.append(
                "- Code evidence summary: "
                f"{summary.surface_count} surfaces, "
                f"{summary.control_signal_count} control signals, "
                f"{summary.risk_signal_count} risk signals"
            )
        if repo.code_surfaces:
            surface_preview = [
                f"{surface.name} ({surface.source_file}"
                + (f":{surface.line_number}" if surface.line_number else "")
                + ")"
                for surface in repo.code_surfaces[:4]
            ]
            sections.append("- Code surfaces: " + "; ".join(surface_preview))
        if repo.code_control_signals:
            control_preview = [
                f"{signal.control_type.replace('_', ' ')} on {signal.surface_id}"
                for signal in repo.code_control_signals[:4]
            ]
            sections.append("- Code control signals: " + "; ".join(control_preview))
        if repo.code_risk_signals:
            risk_preview = [
                f"{signal.severity} {signal.risk_type.replace('_', ' ')} on {signal.surface_id}: {signal.evidence}"
                for signal in repo.code_risk_signals[:4]
            ]
            sections.append("- Code risk signals: " + "; ".join(risk_preview))
        if repo.dfd_seed_suggestions:
            seed_preview = [
                f"{suggestion.label} ({suggestion.node_type})"
                for suggestion in repo.dfd_seed_suggestions[:MAX_PREVIEW_ITEMS]
            ]
            sections.append("- DFD seed suggestions: " + "; ".join(seed_preview))
        if repo.auth_surfaces:
            sections.append(f"- Auth surfaces: {', '.join(repo.auth_surfaces[:MAX_PREVIEW_ITEMS])}")
        if repo.auth_mechanisms:
            sections.append(f"- Auth mechanisms: {', '.join(repo.auth_mechanisms[:MAX_PREVIEW_ITEMS])}")
        if repo.data_stores:
            sections.append(f"- Data stores: {', '.join(repo.data_stores[:MAX_PREVIEW_ITEMS])}")
        if repo.queues:
            sections.append(f"- Queues and async systems: {', '.join(repo.queues[:MAX_PREVIEW_ITEMS])}")
        if repo.external_integrations:
            sections.append(f"- External integrations: {', '.join(repo.external_integrations[:MAX_PREVIEW_ITEMS])}")
        if repo.outbound_calls:
            sections.append(f"- Outbound calls and publishers: {', '.join(repo.outbound_calls[:MAX_PREVIEW_ITEMS])}")
        if repo.deployment_clues:
            sections.append(f"- Deployment clues: {', '.join(repo.deployment_clues[:MAX_PREVIEW_ITEMS])}")
        if repo.infrastructure_resources:
            sections.append(f"- Infrastructure resources: {', '.join(repo.infrastructure_resources[:MAX_PREVIEW_ITEMS])}")
        if repo.security_sensitive_paths:
            sections.append(
                f"- Sensitive paths: {', '.join(repo.security_sensitive_paths[:MAX_PREVIEW_ITEMS])}"
            )
        if repo.warnings:
            sections.append(f"- Parser warnings: {' '.join(repo.warnings[:3])}")

    if cloud:
        sections.append("## Cloud Posture Evidence")
        sections.append(f"- Source file: {cloud.filename}")
        sections.append(f"- Provider format: {cloud.provider}")
        sections.append(f"- High-signal findings parsed: {cloud.finding_count}")
        if cloud.exposed_services:
            sections.append(f"- Internet exposure: {', '.join(cloud.exposed_services[:MAX_PREVIEW_ITEMS])}")
        if cloud.identity_risks:
            sections.append(f"- IAM or trust risks: {', '.join(cloud.identity_risks[:MAX_PREVIEW_ITEMS])}")
        if cloud.encryption_gaps:
            sections.append(f"- Encryption or KMS gaps: {', '.join(cloud.encryption_gaps[:MAX_PREVIEW_ITEMS])}")
        if cloud.logging_gaps:
            sections.append(f"- Logging gaps: {', '.join(cloud.logging_gaps[:MAX_PREVIEW_ITEMS])}")
        for finding in cloud.high_signal_findings[:5]:
            label = f"{finding.severity} {finding.category}"
            detail = _truncate_text(finding.detail, 180)
            target = " / ".join(part for part in [finding.service, finding.resource] if part)
            if target:
                sections.append(f"- Finding: {label} on {target}: {detail}")
            else:
                sections.append(f"- Finding: {label}: {detail}")
        if cloud.warnings:
            sections.append(f"- Parser warnings: {' '.join(cloud.warnings[:3])}")

    if iac:
        sections.append("## IaC Evidence")
        sections.append(f"- Source file: {iac.filename}")
        if iac.reference:
            sections.append(f"- Reference: {iac.reference}")
        sections.append(f"- Infrastructure resources parsed: {iac.resource_count}")
        if iac.resource_types:
            sections.append(f"- Resource types: {', '.join(iac.resource_types[:MAX_PREVIEW_ITEMS])}")
        if iac.resource_names:
            sections.append(f"- Resource names: {', '.join(iac.resource_names[:MAX_PREVIEW_ITEMS])}")
        if iac.public_exposure:
            sections.append(f"- Public exposure signals: {', '.join(iac.public_exposure[:MAX_PREVIEW_ITEMS])}")
        if iac.iam_bindings:
            sections.append(f"- IAM and trust bindings: {', '.join(iac.iam_bindings[:MAX_PREVIEW_ITEMS])}")
        if iac.network_paths:
            sections.append(f"- Network entry points: {', '.join(iac.network_paths[:MAX_PREVIEW_ITEMS])}")
        if iac.secret_refs:
            sections.append(f"- Secret and key references: {', '.join(iac.secret_refs[:MAX_PREVIEW_ITEMS])}")
        if iac.warnings:
            sections.append(f"- Parser warnings: {' '.join(iac.warnings[:3])}")

    if not sections:
        return None

    summary = "\n".join(sections)
    return _truncate_text(summary, ENVIRONMENT_CONTEXT_CHAR_BUDGET)


def parse_repository_evidence(
    content: bytes,
    filename: str,
    *,
    reference: str | None = None,
) -> RepositoryEvidence:
    if not content:
        raise EvidenceValidationError("Repository evidence file is empty.")
    if len(content) > REPOSITORY_EVIDENCE_MAX_BYTES:
        raise EvidenceValidationError(
            "Repository evidence file is too large. Keep uploads under 25 MB.",
            status_code=413,
        )

    source_type, files, warnings = _load_repository_text_files(content, filename)
    if not files:
        raise EvidenceValidationError(
            "Could not find any readable manifest or source files in the repository evidence upload."
        )

    languages = _collect_languages(files)
    frameworks = _collect_frameworks(files)
    entrypoints = _collect_entrypoints(files)
    api_routes = _collect_api_routes(files)
    webhook_endpoints = _collect_webhook_endpoints(api_routes, files)
    route_auth_map = _collect_route_auth_map(files)
    unprotected_routes = _collect_unprotected_routes(route_auth_map)
    sensitive_routes = _collect_sensitive_routes(route_auth_map)
    routes_with_raw_input = _collect_routes_with_raw_input(route_auth_map)
    risky_routes = _collect_risky_routes(route_auth_map)
    code_surfaces = _build_code_surfaces(route_auth_map)
    code_control_signals = _build_code_control_signals(code_surfaces)
    code_risk_signals = _build_code_risk_signals(code_surfaces)
    code_evidence_summary = _build_code_evidence_summary(
        code_surfaces,
        code_control_signals,
        code_risk_signals,
    )
    auth_surfaces = _collect_matching_paths(files, _AUTH_PATH_RE)
    auth_mechanisms = _collect_auth_mechanisms(files)
    sensitive_paths = _collect_matching_paths(files, _SENSITIVE_PATH_RE)
    data_stores = _collect_keyword_facts(files, _DATA_STORE_HINTS)
    queues = _collect_keyword_facts(files, _QUEUE_HINTS)
    integrations = _collect_keyword_facts(files, _INTEGRATION_HINTS)
    outbound_calls = _collect_outbound_calls(files)
    deployment_clues = _collect_deployment_clues(files)
    infrastructure_resources = _collect_infrastructure_resources(files)
    (
        dfd_seed_suggestions,
        dfd_seed_flow_suggestions,
        dfd_seed_boundary_suggestions,
    ) = build_repository_dfd_seed_suggestions(
        entrypoints=entrypoints,
        api_routes=api_routes,
        route_auth_map=route_auth_map,
        data_stores=data_stores,
        queues=queues,
        external_integrations=integrations,
        outbound_calls=outbound_calls,
        infrastructure_resources=infrastructure_resources,
    )

    return RepositoryEvidence(
        source_type=source_type,
        filename=filename,
        reference=_truncate_text(reference or "", 255) or None,
        file_count=len(files),
        languages=languages,
        frameworks=frameworks,
        entrypoints=entrypoints,
        api_routes=api_routes,
        webhook_endpoints=webhook_endpoints,
        route_auth_map=route_auth_map,
        unprotected_routes=unprotected_routes,
        sensitive_routes=sensitive_routes,
        routes_with_raw_input=routes_with_raw_input,
        risky_routes=risky_routes,
        auth_surfaces=auth_surfaces,
        auth_mechanisms=auth_mechanisms,
        data_stores=data_stores,
        queues=queues,
        external_integrations=integrations,
        outbound_calls=outbound_calls,
        deployment_clues=deployment_clues,
        infrastructure_resources=infrastructure_resources,
        security_sensitive_paths=sensitive_paths,
        code_surfaces=code_surfaces,
        code_control_signals=code_control_signals,
        code_risk_signals=code_risk_signals,
        finding_code_links=[],
        code_evidence_summary=code_evidence_summary,
        dfd_seed_suggestions=dfd_seed_suggestions,
        dfd_seed_flow_suggestions=dfd_seed_flow_suggestions,
        dfd_seed_boundary_suggestions=dfd_seed_boundary_suggestions,
        warnings=warnings,
        parsed_at=datetime.now(timezone.utc),
    )


def build_repository_dfd_seed_suggestions(
    *,
    entrypoints: list[str],
    api_routes: list[str],
    route_auth_map: list[RouteAuthEntry],
    data_stores: list[str],
    queues: list[str],
    external_integrations: list[str],
    outbound_calls: list[str],
    infrastructure_resources: list[str],
) -> tuple[
    list[RepositoryDfdSeedSuggestion],
    list[RepositoryDfdSeedFlowSuggestion],
    list[RepositoryDfdSeedBoundarySuggestion],
]:
    suggestions: list[RepositoryDfdSeedSuggestion] = []
    flows: list[RepositoryDfdSeedFlowSuggestion] = []
    boundaries: list[RepositoryDfdSeedBoundarySuggestion] = []
    seen: set[str] = set()
    labels_by_seed_id: dict[str, str] = {}

    def add(
        node_type: str,
        label: str,
        rationale: str,
        source_refs: list[str],
        confidence: float,
    ) -> None:
        if len(suggestions) >= MAX_DFD_SEED_SUGGESTIONS:
            return
        clean_label = _truncate_text(label.strip(), 120)
        dedupe_key = f"{node_type}:{clean_label.lower()}"
        if not clean_label or dedupe_key in seen:
            return
        seen.add(dedupe_key)
        seed_id = f"repo-seed-{_stable_slug(dedupe_key)}"
        suggestions.append(
            RepositoryDfdSeedSuggestion(
                id=seed_id,
                node_type=node_type,  # type: ignore[arg-type]
                label=clean_label,
                rationale=_truncate_text(rationale, 220),
                source_refs=[_truncate_text(ref, 180) for ref in source_refs[:4] if ref],
                confidence=confidence,
            )
        )
        labels_by_seed_id[seed_id] = clean_label

    def seed_id_for(node_type: str, label: str) -> str:
        return f"repo-seed-{_stable_slug(f'{node_type}:{label.strip().lower()}')}"

    def add_flow(
        source_seed_id: str,
        target_seed_id: str,
        label: str,
        rationale: str,
        source_refs: list[str],
        confidence: float,
        *,
        directionality: str = "request",
        transfer_mode: str = "synchronous",
        lifecycle_stage: str = "processing",
    ) -> None:
        if source_seed_id == target_seed_id:
            return
        if source_seed_id not in labels_by_seed_id or target_seed_id not in labels_by_seed_id:
            return
        dedupe_key = f"{source_seed_id}:{target_seed_id}:{label.strip().lower()}"
        if any(flow.id == f"repo-flow-{_stable_slug(dedupe_key)}" for flow in flows):
            return
        flows.append(
            RepositoryDfdSeedFlowSuggestion(
                id=f"repo-flow-{_stable_slug(dedupe_key)}",
                source_seed_id=source_seed_id,
                target_seed_id=target_seed_id,
                label=_truncate_text(label.strip(), 120),
                rationale=_truncate_text(rationale, 220),
                source_refs=[_truncate_text(ref, 180) for ref in source_refs[:4] if ref],
                confidence=confidence,
                directionality=directionality,  # type: ignore[arg-type]
                transfer_mode=transfer_mode,  # type: ignore[arg-type]
                lifecycle_stage=lifecycle_stage,  # type: ignore[arg-type]
            )
        )

    def add_boundary(
        name: str,
        boundary_type: str,
        seed_ids: list[str],
        rationale: str,
        source_refs: list[str],
        confidence: float,
    ) -> None:
        if len(boundaries) >= MAX_DFD_SEED_BOUNDARY_SUGGESTIONS:
            return
        clean_name = _truncate_text(name.strip(), 120)
        member_seed_ids = [
            seed_id
            for seed_id in dict.fromkeys(seed_ids)
            if seed_id in labels_by_seed_id
        ]
        if not clean_name or not member_seed_ids:
            return
        dedupe_key = clean_name.lower()
        if any(boundary.name.lower() == dedupe_key for boundary in boundaries):
            return
        boundaries.append(
            RepositoryDfdSeedBoundarySuggestion(
                id=f"repo-boundary-{_stable_slug(dedupe_key)}",
                name=clean_name,
                boundary_type=boundary_type,  # type: ignore[arg-type]
                seed_ids=member_seed_ids,
                rationale=_truncate_text(rationale, 220),
                source_refs=[_truncate_text(ref, 180) for ref in source_refs[:4] if ref],
                confidence=confidence,
            )
        )

    route_refs = [
        f"{entry.method} {entry.path} ({entry.source_file}"
        + (f":{entry.line_number}" if entry.line_number else "")
        + ")"
        for entry in route_auth_map[:4]
    ]
    if entrypoints or api_routes:
        add(
            "process",
            "Application service",
            "Repository entrypoints and route handlers indicate an application process that should appear in the DFD.",
            entrypoints[:4] or route_refs,
            0.78,
        )
    if api_routes:
        add(
            "process",
            "API layer",
            "Repository route definitions indicate externally reachable API surface that should be modeled.",
            route_refs or api_routes[:4],
            0.82,
        )
    for store in data_stores:
        add(
            "data_store",
            store,
            "Repository dependency and infrastructure hints indicate a persisted data store.",
            [store],
            0.72,
        )
    for queue in queues:
        add(
            "queue",
            queue,
            "Repository dependency and publisher hints indicate asynchronous message flow.",
            [queue],
            0.7,
        )
    for integration in _dedupe(external_integrations + outbound_calls):
        add(
            "external_entity",
            integration,
            "Repository integration and outbound-call hints indicate a third-party or external system.",
            [integration],
            0.68,
        )
    for resource in infrastructure_resources:
        add(
            "infrastructure",
            resource,
            "Repository infrastructure manifests indicate deployable infrastructure that may shape trust boundaries.",
            [resource],
            0.66,
        )

    api_seed_id = seed_id_for("process", "API layer")
    app_seed_id = seed_id_for("process", "Application service")
    route_refs_with_sensitive_data = [
        f"{entry.method} {entry.path} ({entry.source_file}"
        + (f":{entry.line_number}" if entry.line_number else "")
        + ")"
        for entry in route_auth_map
        if entry.sensitive_data_signals
    ]
    route_refs_with_outbound_calls = [
        f"{entry.method} {entry.path} ({entry.source_file}"
        + (f":{entry.line_number}" if entry.line_number else "")
        + ")"
        for entry in route_auth_map
        if entry.outbound_call_signals
    ]
    if api_seed_id in labels_by_seed_id and app_seed_id in labels_by_seed_id:
        add_flow(
            api_seed_id,
            app_seed_id,
            "dispatches application work",
            "Repository routes and application entrypoints indicate request handling through the application service.",
            route_refs or entrypoints[:4],
            0.66,
        )
    for store in data_stores:
        add_flow(
            api_seed_id,
            seed_id_for("data_store", store),
            "reads/writes persisted data",
            "Repository data-store hints and route evidence indicate persisted application state.",
            route_refs_with_sensitive_data or [store],
            0.68,
            lifecycle_stage="storage",
        )
    for queue in queues:
        add_flow(
            api_seed_id,
            seed_id_for("queue", queue),
            "publishes async work",
            "Repository queue clients indicate asynchronous work or notification flow.",
            [ref for ref in outbound_calls if queue.lower() in ref.lower()] or [queue],
            0.66,
            directionality="event",
            transfer_mode="asynchronous",
            lifecycle_stage="notification",
        )
    for integration in _dedupe(external_integrations + outbound_calls):
        add_flow(
            api_seed_id,
            seed_id_for("external_entity", integration),
            "calls external service",
            "Repository integration and outbound-call hints indicate an egress dependency.",
            route_refs_with_outbound_calls or [integration],
            0.64,
            lifecycle_stage="egress",
        )
    for resource in infrastructure_resources:
        add_flow(
            app_seed_id if app_seed_id in labels_by_seed_id else api_seed_id,
            seed_id_for("infrastructure", resource),
            "runs on infrastructure",
            "Repository infrastructure manifests indicate the runtime depends on this infrastructure resource.",
            [resource],
            0.6,
        )

    add_boundary(
        "Public API Boundary",
        "network",
        [api_seed_id],
        "Repository route definitions indicate a public entry boundary before application processing.",
        route_refs or api_routes[:4],
        0.68,
    )
    add_boundary(
        "Application Runtime Boundary",
        "cloud",
        [app_seed_id]
        + [seed_id_for("infrastructure", resource) for resource in infrastructure_resources],
        "Repository entrypoints and infrastructure manifests indicate the application runtime boundary.",
        entrypoints[:2] + infrastructure_resources[:2],
        0.64,
    )
    add_boundary(
        "Data Tier Boundary",
        "regulatory",
        [seed_id_for("data_store", store) for store in data_stores],
        "Repository data-store hints indicate persistence components that should be reviewed as a data boundary.",
        data_stores[:4],
        0.66,
    )
    add_boundary(
        "Async Messaging Boundary",
        "cloud",
        [seed_id_for("queue", queue) for queue in queues],
        "Repository queue hints indicate asynchronous infrastructure that should be modeled as a separate boundary.",
        queues[:4],
        0.62,
    )
    add_boundary(
        "Third-Party Boundary",
        "organizational",
        [
            seed_id_for("external_entity", integration)
            for integration in _dedupe(external_integrations + outbound_calls)
        ],
        "Repository integration and outbound-call hints indicate externally owned systems.",
        _dedupe(external_integrations + outbound_calls)[:4],
        0.62,
    )
    return suggestions, flows, boundaries


def parse_cloud_scan_evidence(content: bytes, filename: str) -> CloudScanEvidence:
    if not content:
        raise EvidenceValidationError("Cloud scan file is empty.")
    if len(content) > CLOUD_SCAN_EVIDENCE_MAX_BYTES:
        raise EvidenceValidationError(
            "Cloud scan file is too large. Keep uploads under 50 MB.",
            status_code=413,
        )

    provider, raw_findings, warnings = _load_cloud_findings(content, filename)
    high_signal_findings = _normalize_cloud_findings(raw_findings)
    return CloudScanEvidence(
        provider=provider,
        filename=filename,
        finding_count=len(high_signal_findings),
        high_signal_findings=high_signal_findings[:20],
        exposed_services=_collect_cloud_summary(high_signal_findings, {"public_storage", "internet_exposure"}),
        identity_risks=_collect_cloud_summary(high_signal_findings, {"broad_iam", "cross_account_trust", "mfa_gap"}),
        encryption_gaps=_collect_cloud_summary(high_signal_findings, {"encryption_gap"}),
        logging_gaps=_collect_cloud_summary(high_signal_findings, {"logging_gap"}),
        warnings=warnings,
        parsed_at=datetime.now(timezone.utc),
    )


def parse_iac_evidence(
    content: bytes,
    filename: str,
    *,
    reference: str | None = None,
) -> IacEvidence:
    if not content:
        raise EvidenceValidationError("IaC evidence file is empty.")
    if len(content) > IAC_EVIDENCE_MAX_BYTES:
        raise EvidenceValidationError(
            "IaC evidence file is too large. Keep uploads under 25 MB.",
            status_code=413,
        )

    source_type, files, warnings = _load_iac_text_files(content, filename)
    if not files:
        raise EvidenceValidationError(
            "Could not find any readable Terraform, CloudFormation, or Kubernetes files in the IaC upload."
        )

    resource_types: Counter[str] = Counter()
    resource_names: list[str] = []
    public_exposure: set[str] = set()
    iam_bindings: set[str] = set()
    network_paths: set[str] = set()
    secret_refs: set[str] = set()

    for path, text in files:
        suffix = PurePosixPath(path).suffix.lower()
        if suffix == ".tf":
            for resource_type, resource_name in _extract_terraform_resources(text):
                resource_types[resource_type] += 1
                resource_names.append(f"{resource_type}.{resource_name}")
            public_exposure.update(_extract_public_exposure_signals(text, path))
            iam_bindings.update(_extract_iam_signals(text, path))
            network_paths.update(_extract_network_signals(text, path))
            secret_refs.update(_extract_secret_signals(text, path))
            continue

        yaml_docs = _parse_yaml_documents(text) if suffix in {".yaml", ".yml"} else []
        json_doc = _parse_json_document(text) if suffix == ".json" else None

        if json_doc is not None:
            _apply_structured_iac_document(
                json_doc,
                path,
                resource_types,
                resource_names,
                public_exposure,
                iam_bindings,
                network_paths,
                secret_refs,
            )

        for document in yaml_docs:
            _apply_structured_iac_document(
                document,
                path,
                resource_types,
                resource_names,
                public_exposure,
                iam_bindings,
                network_paths,
                secret_refs,
            )

        if not yaml_docs and json_doc is None:
            public_exposure.update(_extract_public_exposure_signals(text, path))
            iam_bindings.update(_extract_iam_signals(text, path))
            network_paths.update(_extract_network_signals(text, path))
            secret_refs.update(_extract_secret_signals(text, path))

    return IacEvidence(
        source_type=source_type,
        filename=filename,
        reference=_truncate_text(reference or "", 255) or None,
        resource_count=sum(resource_types.values()),
        resource_types=sorted(resource_types.keys())[:40],
        resource_names=sorted(dict.fromkeys(resource_names))[:40],
        public_exposure=sorted(public_exposure)[:20],
        iam_bindings=sorted(iam_bindings)[:20],
        network_paths=sorted(network_paths)[:20],
        secret_refs=sorted(secret_refs)[:20],
        warnings=warnings,
        parsed_at=datetime.now(timezone.utc),
    )


def _coerce_repository(value: dict[str, Any] | RepositoryEvidence | None) -> RepositoryEvidence | None:
    if value is None:
        return None
    if isinstance(value, RepositoryEvidence):
        return value
    return RepositoryEvidence.model_validate(value)


def _coerce_cloud_scan(value: dict[str, Any] | CloudScanEvidence | None) -> CloudScanEvidence | None:
    if value is None:
        return None
    if isinstance(value, CloudScanEvidence):
        return value
    return CloudScanEvidence.model_validate(value)


def _coerce_iac(value: dict[str, Any] | IacEvidence | None) -> IacEvidence | None:
    if value is None:
        return None
    if isinstance(value, IacEvidence):
        return value
    return IacEvidence.model_validate(value)


def _load_repository_text_files(
    content: bytes,
    filename: str,
) -> tuple[str, list[tuple[str, str]], list[str]]:
    lowered = filename.lower()
    warnings: list[str] = []
    if lowered.endswith(".zip"):
        try:
            return "archive", _read_zip_repository_files(content), warnings
        except zipfile.BadZipFile as exc:
            raise EvidenceValidationError("Repository archive could not be read.") from exc
    if lowered.endswith(".tar") or lowered.endswith(".tar.gz") or lowered.endswith(".tgz"):
        try:
            return "archive", _read_tar_repository_files(content), warnings
        except tarfile.TarError as exc:
            raise EvidenceValidationError("Repository archive could not be read.") from exc
    if lowered.endswith((".json", ".toml", ".txt", ".md", ".py", ".js", ".ts", ".yml", ".yaml", ".xml")):
        text = _decode_text(content)
        if text is None:
            raise EvidenceValidationError("Uploaded repository evidence is not readable text.")
        source_type = "manifest_bundle" if _looks_like_manifest(filename) else "single_file"
        return source_type, [(PurePosixPath(filename).name, text[:MAX_TEXT_FILE_BYTES])], warnings
    raise EvidenceValidationError(
        "Unsupported repository evidence format. Upload a zip/tar archive or a manifest file bundle."
    )


def _load_iac_text_files(
    content: bytes,
    filename: str,
) -> tuple[str, list[tuple[str, str]], list[str]]:
    lowered = filename.lower()
    warnings: list[str] = []
    if lowered.endswith(".zip"):
        try:
            files = _read_zip_repository_files(content)
            filtered = [(path, text) for path, text in files if PurePosixPath(path).suffix.lower() in _IAC_TEXT_EXTENSIONS]
            return "archive", filtered, warnings
        except zipfile.BadZipFile as exc:
            raise EvidenceValidationError("IaC archive could not be read.") from exc
    if lowered.endswith(".tar") or lowered.endswith(".tar.gz") or lowered.endswith(".tgz"):
        try:
            files = _read_tar_repository_files(content)
            filtered = [(path, text) for path, text in files if PurePosixPath(path).suffix.lower() in _IAC_TEXT_EXTENSIONS]
            return "archive", filtered, warnings
        except tarfile.TarError as exc:
            raise EvidenceValidationError("IaC archive could not be read.") from exc
    if lowered.endswith(tuple(_IAC_TEXT_EXTENSIONS)):
        text = _decode_text(content)
        if text is None:
            raise EvidenceValidationError("Uploaded IaC evidence is not readable text.")
        source_type = "manifest_bundle" if PurePosixPath(filename).name.lower() in {"template.yaml", "template.yml"} else "single_file"
        return source_type, [(PurePosixPath(filename).name, text[:MAX_TEXT_FILE_BYTES])], warnings
    raise EvidenceValidationError(
        "Unsupported IaC evidence format. Upload Terraform, CloudFormation, Kubernetes YAML/JSON, or a zip/tar archive."
    )


def _extract_terraform_resources(text: str) -> list[tuple[str, str]]:
    return [(resource_type, resource_name) for resource_type, resource_name in _TERRAFORM_RESOURCE_RE.findall(text)]


def _parse_json_document(text: str) -> Any | None:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, (dict, list)) else None


def _parse_yaml_documents(text: str) -> list[Any]:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []
    return [document for document in documents if isinstance(document, (dict, list))]


def _apply_structured_iac_document(
    document: Any,
    path: str,
    resource_types: Counter[str],
    resource_names: list[str],
    public_exposure: set[str],
    iam_bindings: set[str],
    network_paths: set[str],
    secret_refs: set[str],
) -> None:
    if isinstance(document, dict) and "Resources" in document and isinstance(document["Resources"], dict):
        for resource_name, resource in document["Resources"].items():
            if isinstance(resource, dict):
                resource_type = str(resource.get("Type", "CloudFormation::Unknown"))
                resource_types[resource_type] += 1
                resource_names.append(f"{resource_type}:{resource_name}")
                serialized = json.dumps(resource)
                public_exposure.update(_extract_public_exposure_signals(serialized, f"{path}:{resource_name}"))
                iam_bindings.update(_extract_iam_signals(serialized, f"{path}:{resource_name}"))
                network_paths.update(_extract_network_signals(serialized, f"{path}:{resource_name}"))
                secret_refs.update(_extract_secret_signals(serialized, f"{path}:{resource_name}"))
        return

    if isinstance(document, dict) and document.get("kind"):
        kind = str(document.get("kind"))
        metadata = document.get("metadata") or {}
        name = str(metadata.get("name") or "unnamed")
        resource_types[kind] += 1
        resource_names.append(f"{kind}:{name}")
        serialized = json.dumps(document)
        public_exposure.update(_extract_public_exposure_signals(serialized, f"{path}:{name}"))
        iam_bindings.update(_extract_iam_signals(serialized, f"{path}:{name}"))
        network_paths.update(_extract_network_signals(serialized, f"{path}:{name}"))
        secret_refs.update(_extract_secret_signals(serialized, f"{path}:{name}"))
        return

    if isinstance(document, list):
        for item in document:
            _apply_structured_iac_document(
                item,
                path,
                resource_types,
                resource_names,
                public_exposure,
                iam_bindings,
                network_paths,
                secret_refs,
            )


def _extract_public_exposure_signals(text: str, path: str) -> set[str]:
    signals: set[str] = set()
    lowered = text.lower()
    if "0.0.0.0/0" in text or "::/0" in text:
        signals.add(f"{path}: public ingress or egress rule")
    if "loadbalancer" in lowered or "internet-facing" in lowered or "publicly_accessible" in lowered:
        signals.add(f"{path}: public load balancer or public service")
    if "aws_internet_gateway" in lowered or "map_public_ip_on_launch" in lowered:
        signals.add(f"{path}: internet-routable subnet")
    return signals


def _extract_iam_signals(text: str, path: str) -> set[str]:
    signals: set[str] = set()
    lowered = text.lower()
    if any(token in lowered for token in ("iam_role", "iam_policy", "assumerole", "rolearn", "clusterrolebinding", "serviceaccount")):
        signals.add(f"{path}: IAM role, policy, or trust binding")
    return signals


def _extract_network_signals(text: str, path: str) -> set[str]:
    signals: set[str] = set()
    lowered = text.lower()
    if any(token in lowered for token in ("ingress", "route_table", "listener", "gateway", "subnet", "service", "networkpolicy")):
        signals.add(f"{path}: network entry or routing component")
    return signals


def _extract_secret_signals(text: str, path: str) -> set[str]:
    signals: set[str] = set()
    lowered = text.lower()
    if any(token in lowered for token in ("secret", "secretkeyref", "kms", "vault", "secretsmanager", "parameter_store")):
        signals.add(f"{path}: secret or key reference")
    return signals


def _read_zip_repository_files(content: bytes) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    with zipfile.ZipFile(BytesIO(content)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            safe_name = _validate_archive_name(info.filename)
            if safe_name is None or not _is_relevant_repository_path(safe_name):
                continue
            if len(files) >= MAX_REPOSITORY_FILES:
                break
            with archive.open(info) as handle:
                raw = handle.read(MAX_TEXT_FILE_BYTES + 1)
            if len(raw) > MAX_TEXT_FILE_BYTES or _SECRET_PATH_RE.search(safe_name):
                continue
            text = _decode_text(raw)
            if text is None:
                continue
            files.append((safe_name, text))
    return files


def _read_tar_repository_files(content: bytes) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    with tarfile.open(fileobj=BytesIO(content), mode="r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            safe_name = _validate_archive_name(member.name)
            if safe_name is None or not _is_relevant_repository_path(safe_name):
                continue
            if len(files) >= MAX_REPOSITORY_FILES:
                break
            if member.size > MAX_TEXT_FILE_BYTES or _SECRET_PATH_RE.search(safe_name):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            raw = handle.read(MAX_TEXT_FILE_BYTES + 1)
            if len(raw) > MAX_TEXT_FILE_BYTES:
                continue
            text = _decode_text(raw)
            if text is None:
                continue
            files.append((safe_name, text))
    return files


def _validate_archive_name(name: str) -> str | None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise EvidenceValidationError("Archive contains an invalid file path.")
    cleaned = str(path)
    return cleaned.lstrip("./")


def _is_relevant_repository_path(path: str) -> bool:
    lowered = path.lower()
    if _SKIP_REPO_PATH_RE.search(lowered):
        return False
    filename = PurePosixPath(path).name.lower()
    if filename in _REPO_INTERESTING_FILENAMES:
        return True
    if _ENTRYPOINT_PATH_RE.search(lowered) or _SENSITIVE_PATH_RE.search(lowered):
        return True
    if PurePosixPath(path).suffix.lower() in _REPO_TEXT_EXTENSIONS and (
        path.count("/") <= 6 or "api/" in lowered or "routes/" in lowered or "controllers/" in lowered
    ):
        return True
    return False


def _looks_like_manifest(filename: str) -> bool:
    return PurePosixPath(filename).name.lower() in _REPO_INTERESTING_FILENAMES


def _decode_text(raw: bytes) -> str | None:
    if b"\x00" in raw:
        return None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def _collect_languages(files: list[tuple[str, str]]) -> list[str]:
    counts: Counter[str] = Counter()
    for path, _ in files:
        lowered = path.lower()
        suffix = PurePosixPath(path).suffix.lower()
        if suffix in {".py"} or lowered.endswith("requirements.txt") or lowered.endswith("pyproject.toml"):
            counts["Python"] += 1
        elif suffix in {".js", ".jsx"}:
            counts["JavaScript"] += 1
        elif suffix in {".ts", ".tsx"}:
            counts["TypeScript"] += 1
        elif suffix == ".go" or lowered.endswith("go.mod"):
            counts["Go"] += 1
        elif suffix in {".java"} or lowered.endswith("pom.xml") or lowered.endswith("build.gradle"):
            counts["Java"] += 1
        elif suffix in {".kt", ".kts"}:
            counts["Kotlin"] += 1
        elif suffix == ".rs" or lowered.endswith("cargo.toml"):
            counts["Rust"] += 1
        elif suffix == ".rb" or lowered.endswith("gemfile"):
            counts["Ruby"] += 1
        elif suffix == ".php" or lowered.endswith("composer.json"):
            counts["PHP"] += 1
        elif suffix in {".tf"}:
            counts["Terraform"] += 1
    return [name for name, _ in counts.most_common(MAX_PREVIEW_ITEMS)]


def _collect_frameworks(files: list[tuple[str, str]]) -> list[str]:
    hits: list[str] = []
    for path, text in files:
        filename = PurePosixPath(path).name.lower()
        if filename == "package.json":
            try:
                pkg = json.loads(text)
            except json.JSONDecodeError:
                continue
            deps = {
                **(pkg.get("dependencies") or {}),
                **(pkg.get("devDependencies") or {}),
            }
            hits.extend(_lookup_frameworks_from_keys(deps.keys()))
            hits.extend(_lookup_facts_from_keys(deps.keys(), _DATA_STORE_HINTS))
            hits.extend(_lookup_facts_from_keys(deps.keys(), _QUEUE_HINTS))
            hits.extend(_lookup_facts_from_keys(deps.keys(), _INTEGRATION_HINTS))
        elif filename == "pyproject.toml":
            try:
                data = tomllib.loads(text)
            except Exception:
                continue
            deps = _flatten_toml_dependencies(data)
            hits.extend(_lookup_frameworks_from_keys(deps))
        elif filename == "requirements.txt":
            deps = [line.split("==")[0].strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
            hits.extend(_lookup_frameworks_from_keys(deps))
        elif filename == "go.mod":
            deps = re.findall(r"^\s*([A-Za-z0-9./_-]+)\s+v[0-9]", text, flags=re.MULTILINE)
            hits.extend(_lookup_frameworks_from_keys(deps))
        elif filename in {"pom.xml"}:
            hits.extend(_lookup_frameworks_from_keys(re.findall(r"<artifactId>([^<]+)</artifactId>", text)))
        elif filename in {"build.gradle", "build.gradle.kts"}:
            hits.extend(_lookup_frameworks_from_keys(re.findall(r"['\"]([^'\"]+)['\"]", text)))
        elif filename == "cargo.toml":
            hits.extend(_lookup_frameworks_from_keys(re.findall(r"^([A-Za-z0-9_-]+)\s*=", text, flags=re.MULTILINE)))
    return _dedupe(hits)


def _flatten_toml_dependencies(data: dict[str, Any]) -> list[str]:
    deps: list[str] = []
    project = data.get("project") or {}
    for entry in project.get("dependencies", []) or []:
        deps.append(str(entry))
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    deps.extend(str(key) for key in poetry.keys())
    return deps


def _lookup_frameworks_from_keys(keys: Any) -> list[str]:
    hits: list[str] = []
    for key in keys:
        lowered = str(key).lower()
        for token, label in _FRAMEWORK_HINTS.items():
            if token in lowered:
                hits.append(label)
    return hits


def _lookup_facts_from_keys(keys: Any, mapping: dict[str, str]) -> list[str]:
    hits: list[str] = []
    for key in keys:
        lowered = str(key).lower()
        for token, label in mapping.items():
            if token in lowered:
                hits.append(label)
    return hits


def _collect_keyword_facts(files: list[tuple[str, str]], mapping: dict[str, str]) -> list[str]:
    hits: list[str] = []
    for _, text in files:
        lowered = text.lower()
        for token, label in mapping.items():
            if token in lowered:
                hits.append(label)
    return _dedupe(hits)


def _collect_entrypoints(files: list[tuple[str, str]]) -> list[str]:
    hits = [path for path, _ in files if _ENTRYPOINT_PATH_RE.search(path.lower())]
    return _dedupe(hits)


def _collect_matching_paths(files: list[tuple[str, str]], pattern: re.Pattern[str]) -> list[str]:
    hits = [path for path, text in files if pattern.search(path) or pattern.search(text[:5_000])]
    return _dedupe(hits)


def _collect_deployment_clues(files: list[tuple[str, str]]) -> list[str]:
    clues: list[str] = []
    for path, text in files:
        filename = PurePosixPath(path).name.lower()
        lowered = text.lower()
        if filename == "dockerfile":
            clues.append("Dockerfile present")
        if filename in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            clues.append("Docker Compose present")
        if filename in {"serverless.yml", "serverless.yaml"}:
            clues.append("Serverless deployment config")
        if filename == "vercel.json":
            clues.append("Vercel deployment config")
        if PurePosixPath(path).suffix.lower() == ".tf":
            if "aws_" in lowered:
                clues.append("Terraform for AWS")
            if "google_" in lowered:
                clues.append("Terraform for GCP")
            if "azurerm_" in lowered:
                clues.append("Terraform for Azure")
        if PurePosixPath(path).suffix.lower() in {".yml", ".yaml"}:
            if re.search(r"\b(kind:\s*(deployment|service|ingress|job|cronjob|statefulset))\b", lowered):
                clues.append("Kubernetes manifests")
        if "github/workflows" in path.lower():
                clues.append("CI/CD workflows")
    return _dedupe(clues)


def _collect_api_routes(files: list[tuple[str, str]]) -> list[str]:
    routes = [f"{route.method} {route.path}" for route in _collect_route_definitions(files)]
    for path, text in files:
        if PurePosixPath(path).suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
            next_route = _route_from_next_api_path(path)
            if next_route:
                methods = _EXPORTED_HANDLER_RE.findall(text) or ["ANY"]
                for method in methods:
                    routes.append(f"{method.upper()} {next_route}")
    return _dedupe(routes)


def _collect_route_auth_map(files: list[tuple[str, str]]) -> list[RouteAuthEntry]:
    entries: list[RouteAuthEntry] = []
    for route in _collect_route_definitions(files):
        entries.append(
            RouteAuthEntry(
                method=route.method,
                path=route.path,
                auth_guards=_dedupe(route.auth_guards),
                sensitive_data_signals=_dedupe(route.sensitive_data_signals),
                validation_signals=_dedupe(route.validation_signals),
                outbound_call_signals=_dedupe(route.outbound_call_signals),
                risk_flags=_dedupe(route.risk_flags),
                source_file=route.source_file,
                line_number=route.line_number,
            )
        )
    return entries[:MAX_PREVIEW_ITEMS]


def _collect_unprotected_routes(route_auth_map: list[RouteAuthEntry]) -> list[str]:
    hits = [
        f"{entry.method} {entry.path}"
        for entry in route_auth_map
        if not entry.auth_guards
    ]
    return _dedupe(hits)


def _collect_sensitive_routes(route_auth_map: list[RouteAuthEntry]) -> list[str]:
    hits = [
        f"{entry.method} {entry.path} -> {', '.join(entry.sensitive_data_signals)}"
        for entry in route_auth_map
        if entry.sensitive_data_signals
    ]
    return _dedupe(hits)


def _collect_routes_with_raw_input(route_auth_map: list[RouteAuthEntry]) -> list[str]:
    hits = [
        f"{entry.method} {entry.path}"
        for entry in route_auth_map
        if "Raw JSON/body access" in entry.validation_signals
    ]
    return _dedupe(hits)


def _collect_risky_routes(route_auth_map: list[RouteAuthEntry]) -> list[str]:
    hits = [
        f"{entry.method} {entry.path} -> {', '.join(entry.risk_flags)}"
        for entry in route_auth_map
        if entry.risk_flags
    ]
    return _dedupe(hits)


def _stable_code_id(*parts: object) -> str:
    raw = ":".join(str(part or "") for part in parts)
    slug = re.sub(r"[^a-z0-9]+", "-", raw.casefold()).strip("-")
    return slug[:160] or "code-signal"


def _code_surface_kind(entry: RouteAuthEntry) -> str:
    if re.search(r"(webhook|callback|notify|event)", entry.path, re.IGNORECASE):
        return "webhook"
    return "route"


def _build_code_surfaces(route_auth_map: list[RouteAuthEntry]) -> list[CodeSurface]:
    surfaces: list[CodeSurface] = []
    for entry in route_auth_map:
        surface_id = _stable_code_id("surface", entry.method, entry.path, entry.source_file)
        tags: list[str] = []
        if entry.auth_guards:
            tags.append("auth_guarded")
        if entry.sensitive_data_signals:
            tags.append("sensitive_data")
        if entry.validation_signals:
            tags.append("validated_input")
        if entry.outbound_call_signals:
            tags.append("outbound_call")
        if entry.risk_flags:
            tags.append("risk_signal")
        surfaces.append(
            CodeSurface(
                id=surface_id,
                kind=_code_surface_kind(entry),  # type: ignore[arg-type]
                name=f"{entry.method} {entry.path}",
                method=entry.method,
                path=entry.path,
                source_file=entry.source_file,
                line_number=entry.line_number,
                auth_guards=entry.auth_guards,
                sensitive_data_signals=entry.sensitive_data_signals,
                validation_signals=entry.validation_signals,
                outbound_call_signals=entry.outbound_call_signals,
                risk_flags=entry.risk_flags,
                tags=tags,
            )
        )
    return surfaces


def _build_code_control_signals(surfaces: list[CodeSurface]) -> list[CodeControlSignal]:
    signals: list[CodeControlSignal] = []
    for surface in surfaces:
        if surface.auth_guards:
            signals.append(
                CodeControlSignal(
                    id=_stable_code_id("control", surface.id, "authentication"),
                    surface_id=surface.id,
                    control_type="authentication",
                    strength="strong",
                    evidence=", ".join(surface.auth_guards),
                )
            )
            if any(
                re.search(r"(admin|role|permission|scope|authorize|policy)", guard, re.IGNORECASE)
                for guard in surface.auth_guards
            ):
                signals.append(
                    CodeControlSignal(
                        id=_stable_code_id("control", surface.id, "authorization"),
                        surface_id=surface.id,
                        control_type="authorization",
                        strength="strong",
                        evidence=", ".join(surface.auth_guards),
                    )
                )
        validation_evidence = [
            item for item in surface.validation_signals if item != "Raw JSON/body access"
        ]
        if validation_evidence:
            signals.append(
                CodeControlSignal(
                    id=_stable_code_id("control", surface.id, "validation"),
                    surface_id=surface.id,
                    control_type="validation",
                    strength="strong",
                    evidence=", ".join(validation_evidence),
                )
            )
        if any(
            re.search(r"(signature|hmac|signed|webhook signing)", signal, re.IGNORECASE)
            for signal in surface.outbound_call_signals
        ):
            signals.append(
                CodeControlSignal(
                    id=_stable_code_id("control", surface.id, "signature-verification"),
                    surface_id=surface.id,
                    control_type="signature_verification",
                    strength="partial",
                    evidence=", ".join(surface.outbound_call_signals),
                )
            )
        if any(
            re.search(r"(secret|vault|kms|secretsmanager|parameter)", signal, re.IGNORECASE)
            for signal in [*surface.outbound_call_signals, *surface.sensitive_data_signals]
        ):
            signals.append(
                CodeControlSignal(
                    id=_stable_code_id("control", surface.id, "secret-retrieval"),
                    surface_id=surface.id,
                    control_type="secret_retrieval",
                    strength="partial",
                    evidence=", ".join(
                        [*surface.outbound_call_signals, *surface.sensitive_data_signals]
                    ),
                )
            )
    return signals


def _risk_type_from_flag(flag: str) -> str:
    lowered = flag.casefold()
    if "no auth guard" in lowered:
        return "missing_authentication"
    if "raw input" in lowered:
        return "missing_validation"
    if "unsigned outbound" in lowered:
        return "unsigned_outbound_call"
    return "sensitive_data_exposure"


def _risk_severity_for_surface(surface: CodeSurface, risk_type: str) -> str:
    if risk_type == "missing_authentication" and surface.sensitive_data_signals:
        return "High"
    if risk_type == "missing_validation" and surface.sensitive_data_signals:
        return "High"
    if risk_type == "unsigned_outbound_call":
        return "Medium"
    return "Medium" if surface.sensitive_data_signals else "Low"


def _build_code_risk_signals(surfaces: list[CodeSurface]) -> list[CodeRiskSignal]:
    signals: list[CodeRiskSignal] = []
    for surface in surfaces:
        if not surface.auth_guards and surface.sensitive_data_signals:
            signals.append(
                CodeRiskSignal(
                    id=_stable_code_id("risk", surface.id, "missing-authentication"),
                    surface_id=surface.id,
                    risk_type="missing_authentication",
                    severity="High",
                    evidence="No auth guard was detected on a route that handles "
                    + ", ".join(surface.sensitive_data_signals),
                )
            )
        if "Raw JSON/body access" in surface.validation_signals and surface.sensitive_data_signals:
            signals.append(
                CodeRiskSignal(
                    id=_stable_code_id("risk", surface.id, "missing-validation"),
                    surface_id=surface.id,
                    risk_type="missing_validation",
                    severity="High",
                    evidence="Raw request input is read on a sensitive-data route.",
                )
            )
        if "HTTP call without auth/signing evidence" in surface.outbound_call_signals:
            signals.append(
                CodeRiskSignal(
                    id=_stable_code_id("risk", surface.id, "unsigned-outbound-call"),
                    surface_id=surface.id,
                    risk_type="unsigned_outbound_call",
                    severity="Medium",
                    evidence="Outbound HTTP call has no detected auth or signing evidence.",
                )
            )
        for risk_flag in [risk_flag for risk_flag in surface.risk_flags if risk_flag]:
            risk_type = _risk_type_from_flag(risk_flag)
            signals.append(
                CodeRiskSignal(
                    id=_stable_code_id("risk", surface.id, risk_type, risk_flag),
                    surface_id=surface.id,
                    risk_type=risk_type,  # type: ignore[arg-type]
                    severity=_risk_severity_for_surface(surface, risk_type),  # type: ignore[arg-type]
                    evidence=risk_flag,
                )
            )
    deduped: list[CodeRiskSignal] = []
    seen: set[str] = set()
    for signal in signals:
        if signal.id in seen:
            continue
        seen.add(signal.id)
        deduped.append(signal)
    return deduped


def _build_code_evidence_summary(
    surfaces: list[CodeSurface],
    control_signals: list[CodeControlSignal],
    risk_signals: list[CodeRiskSignal],
) -> CodeEvidenceSummary:
    high_signal_risk_surface_ids = {
        signal.surface_id
        for signal in risk_signals
        if signal.risk_type in {"missing_authentication", "missing_validation"}
    }
    return CodeEvidenceSummary(
        surface_count=len(surfaces),
        route_count=sum(1 for surface in surfaces if surface.kind in {"route", "webhook"}),
        control_signal_count=len(control_signals),
        risk_signal_count=len(risk_signals),
        linked_finding_count=0,
        externally_reachable_surface_count=sum(
            1 for surface in surfaces if surface.kind in {"route", "webhook"}
        ),
        unprotected_sensitive_surface_count=len(high_signal_risk_surface_ids),
        verified_control_count=sum(
            1 for signal in control_signals if signal.strength in {"strong", "partial"}
        ),
        missing_control_count=sum(
            1
            for signal in risk_signals
            if signal.risk_type in {"missing_authentication", "missing_validation"}
        ),
    )


def _collect_route_definitions(files: list[tuple[str, str]]) -> list[_RouteDefinition]:
    routes: list[_RouteDefinition] = []
    for path, text in files:
        suffix = PurePosixPath(path).suffix.lower()
        if suffix == ".py":
            routes.extend(_collect_python_route_definitions(path, text))
        elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
            routes.extend(_collect_express_route_definitions(path, text))
    deduped: list[_RouteDefinition] = []
    seen: set[tuple[str, str, str]] = set()
    for route in routes:
        key = (route.method, route.path, route.source_file)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(route)
        if len(deduped) >= 32:
            break
    return deduped


def _collect_python_route_definitions(path: str, text: str) -> list[_RouteDefinition]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        routes: list[_RouteDefinition] = []
        prefixes = _FASTAPI_PREFIX_RE.findall(text) or [""]
        matches = _PYTHON_ROUTE_RE.findall(text)
        for method, route in matches:
            for prefix in prefixes[:1]:
                routes.append(
                    _RouteDefinition(
                        method=method.upper(),
                        path=_join_route(prefix, route),
                        source_file=path,
                    )
                )
        return routes

    router_configs = _collect_python_router_configs(tree)
    routes: list[_RouteDefinition] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route_decorators: list[_RouteDefinition] = []
        function_auth_guards: list[str] = []
        function_segment = _get_python_source_segment(text, node)
        sensitive_data_signals = _collect_sensitive_data_signals_from_text(function_segment)
        validation_signals = _collect_python_validation_signals(node, function_segment)
        outbound_call_signals = _collect_outbound_call_signals_from_text(function_segment)
        for decorator in node.decorator_list:
            route_decorators.extend(_route_definitions_from_python_decorator(path, decorator, router_configs))
            if not _is_python_route_decorator(decorator):
                function_auth_guards.extend(_extract_python_guard_names(decorator))
        for route in route_decorators:
            route.auth_guards = _dedupe(route.auth_guards + function_auth_guards)
            route.sensitive_data_signals = sensitive_data_signals.copy()
            route.validation_signals = validation_signals.copy()
            route.outbound_call_signals = outbound_call_signals.copy()
            route.risk_flags = _derive_route_risk_flags(route)
            routes.append(route)
    return routes


def _collect_python_router_configs(tree: ast.AST) -> dict[str, dict[str, Any]]:
    configs: dict[str, dict[str, Any]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        func_name = _python_call_name(node.value.func)
        if func_name != "APIRouter":
            continue
        prefix = ""
        guards: list[str] = []
        for keyword in node.value.keywords:
            if keyword.arg == "prefix":
                prefix = _literal_string(keyword.value) or ""
            elif keyword.arg == "dependencies":
                guards.extend(_extract_python_guard_names(keyword.value))
        configs[node.targets[0].id] = {
            "prefix": prefix,
            "auth_guards": _dedupe(guards),
        }
    return configs


def _route_definitions_from_python_decorator(
    path: str,
    decorator: ast.AST,
    router_configs: dict[str, dict[str, Any]],
) -> list[_RouteDefinition]:
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return []

    method_name = decorator.func.attr.lower()
    base_name = _python_call_name(decorator.func.value)
    route = _literal_string(decorator.args[0]) if decorator.args else None
    methods: list[str] = []
    route_guards: list[str] = []

    if method_name in {m.lower() for m in _HTTP_METHODS}:
        methods = [method_name.upper()]
    elif method_name == "route":
        methods = _extract_python_route_methods(decorator)
    else:
        return []

    if route is None:
        for keyword in decorator.keywords:
            if keyword.arg in {"path", "rule"}:
                route = _literal_string(keyword.value)
            elif keyword.arg == "dependencies":
                route_guards.extend(_extract_python_guard_names(keyword.value))
    else:
        for keyword in decorator.keywords:
            if keyword.arg == "dependencies":
                route_guards.extend(_extract_python_guard_names(keyword.value))

    if not route:
        return []

    router_config = router_configs.get(base_name or "", {})
    prefix = router_config.get("prefix", "")
    combined_guards = _dedupe(route_guards + router_config.get("auth_guards", []))
    return [
        _RouteDefinition(
            method=method,
            path=_join_route(prefix, route),
            source_file=path,
            line_number=getattr(decorator, "lineno", None),
            auth_guards=combined_guards.copy(),
        )
        for method in methods
    ]


def _extract_python_route_methods(decorator: ast.Call) -> list[str]:
    for keyword in decorator.keywords:
        if keyword.arg != "methods" or not isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
            continue
        methods = [
            (_literal_string(element) or "").upper()
            for element in keyword.value.elts
            if _literal_string(element)
        ]
        return methods or ["ANY"]
    return ["ANY"]


def _is_python_route_decorator(decorator: ast.AST) -> bool:
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return False
    return decorator.func.attr.lower() in {m.lower() for m in _HTTP_METHODS} | {"route"}


def _extract_python_guard_names(node: ast.AST) -> list[str]:
    guards: list[str] = []
    if isinstance(node, ast.Call):
        call_name = _python_call_name(node.func)
        if call_name in {"Depends", "Security"}:
            for arg in node.args:
                guards.extend(_extract_python_guard_names(arg))
            for keyword in node.keywords:
                guards.extend(_extract_python_guard_names(keyword.value))
        else:
            if _looks_like_auth_guard(call_name):
                guards.append(call_name)
            for arg in node.args:
                guards.extend(_extract_python_guard_names(arg))
    elif isinstance(node, ast.Name):
        if _looks_like_auth_guard(node.id):
            guards.append(node.id)
    elif isinstance(node, ast.Attribute):
        attr_name = _python_call_name(node)
        if _looks_like_auth_guard(attr_name):
            guards.append(attr_name)
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for element in node.elts:
            guards.extend(_extract_python_guard_names(element))
    return _dedupe(guards)


def _collect_express_route_definitions(path: str, text: str) -> list[_RouteDefinition]:
    router_level_guards = _collect_express_router_level_guards(text)
    routes: list[_RouteDefinition] = []
    for match in _EXPRESS_ROUTE_WITH_ARGS_RE.finditer(text):
        method, route, remainder = match.groups()
        route_path = _join_route("", route)
        guards = _extract_express_guard_names(remainder)
        handler_blob = _extract_express_handler_blob(text, remainder)
        sensitive_data_signals = _collect_sensitive_data_signals_from_text(handler_blob)
        validation_signals = _collect_express_validation_signals(remainder, handler_blob)
        outbound_call_signals = _collect_outbound_call_signals_from_text(handler_blob)
        for prefix, scoped_guards in router_level_guards:
            if prefix is None or route_path == prefix or route_path.startswith(prefix.rstrip("/") + "/"):
                guards.extend(scoped_guards)
        route = _RouteDefinition(
            method=method.upper(),
            path=route_path,
            source_file=path,
            line_number=text[: match.start()].count("\n") + 1,
            auth_guards=_dedupe(guards),
            sensitive_data_signals=sensitive_data_signals,
            validation_signals=validation_signals,
            outbound_call_signals=outbound_call_signals,
        )
        route.risk_flags = _derive_route_risk_flags(route)
        routes.append(
            route
        )
    if routes:
        return routes
    for method, route in _EXPRESS_ROUTE_RE.findall(text):
        route_path = _join_route("", route)
        guards: list[str] = []
        for prefix, scoped_guards in router_level_guards:
            if prefix is None or route_path == prefix or route_path.startswith(prefix.rstrip("/") + "/"):
                guards.extend(scoped_guards)
        routes.append(
            _RouteDefinition(
                method=method.upper(),
                path=route_path,
                source_file=path,
                auth_guards=_dedupe(guards),
                sensitive_data_signals=[],
                validation_signals=[],
                outbound_call_signals=[],
                risk_flags=[],
            )
        )
    return routes


def _collect_express_router_level_guards(text: str) -> list[tuple[str | None, list[str]]]:
    guards: list[tuple[str | None, list[str]]] = []
    for match in _EXPRESS_USE_RE.finditer(text):
        argument_blob = match.group(1).strip()
        prefix: str | None = None
        prefix_match = re.match(r"^[\"']([^\"']+)[\"']\s*,\s*(.+)$", argument_blob, re.DOTALL)
        if prefix_match:
            prefix = _join_route("", prefix_match.group(1))
            argument_blob = prefix_match.group(2)
        extracted = _extract_express_guard_names(argument_blob)
        if extracted:
            guards.append((prefix, extracted))
    return guards


def _extract_express_guard_names(argument_blob: str) -> list[str]:
    tokens = re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\b", argument_blob)
    guards: list[str] = []
    for token in tokens:
        if token in _EXPRESS_IGNORED_TOKENS:
            continue
        if _looks_like_auth_guard(token):
            guards.append(token)
    return _dedupe(guards)


def _extract_express_handler_blob(text: str, argument_blob: str) -> str:
    if "=>" in argument_blob or "function" in argument_blob:
        return argument_blob

    tokens = re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\b", argument_blob)
    candidates = [
        token for token in tokens
        if token not in _EXPRESS_IGNORED_TOKENS and not _looks_like_auth_guard(token)
    ]
    for name in reversed(candidates):
        for marker in (
            f"async function {name}",
            f"function {name}",
            f"const {name} =",
            f"let {name} =",
            f"var {name} =",
        ):
            start = text.find(marker)
            if start != -1:
                return text[start : start + 1200]
        function_pattern = re.compile(
            rf"(?:async\s+)?function\s+{re.escape(name)}\s*\([^)]*\)\s*\{{[\s\S]{{0,1200}}?\}}",
            re.IGNORECASE,
        )
        arrow_pattern = re.compile(
            rf"(?:const|let|var)\s+{re.escape(name)}\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{{[\s\S]{{0,1200}}?\}}",
            re.IGNORECASE,
        )
        for pattern in (function_pattern, arrow_pattern):
            match = pattern.search(text)
            if match:
                return match.group(0)
    return argument_blob


def _looks_like_auth_guard(name: str | None) -> bool:
    if not name:
        return False
    return bool(_AUTH_GUARD_NAME_RE.search(name))


def _collect_sensitive_data_signals_from_text(text: str) -> list[str]:
    if not text:
        return []
    hits = [
        label
        for label, pattern in _SENSITIVE_DATA_SIGNAL_PATTERNS
        if pattern.search(text)
    ]
    return _dedupe(hits)


def _collect_python_validation_signals(node: ast.AST, text: str) -> list[str]:
    hits = _collect_validation_signals_from_text(text)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        typed_params = [
            arg.arg
            for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
            if arg.annotation is not None and arg.arg not in {"self", "cls", "request", "req", "res"}
        ]
        if typed_params:
            hits.append("Typed request parameters")
    return _dedupe(hits)


def _collect_express_validation_signals(argument_blob: str, handler_blob: str) -> list[str]:
    hits = _collect_validation_signals_from_text(handler_blob)
    if any(token.lower().startswith("validate") or "validator" in token.lower() for token in re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\b", argument_blob)):
        hits.append("Validator middleware")
    return _dedupe(hits)


def _collect_validation_signals_from_text(text: str) -> list[str]:
    if not text:
        return []
    hits = [
        label
        for label, pattern in _VALIDATION_PATTERNS
        if pattern.search(text)
    ]
    hits.extend(
        label
        for label, pattern in _RAW_INPUT_PATTERNS
        if pattern.search(text)
    )
    return _dedupe(hits)


def _collect_outbound_call_signals_from_text(text: str) -> list[str]:
    if not text:
        return []
    hits: list[str] = []
    lowered = text.lower()
    if _STRIPE_CALL_RE.search(text):
        hits.append("Stripe SDK-authenticated call")
    for client_name in _BOTO3_CLIENT_RE.findall(text):
        if client_name.lower() in {"sqs", "sns", "s3", "dynamodb"}:
            hits.append(f"AWS SDK-authenticated {client_name.upper()} call")
        else:
            hits.append("AWS SDK-authenticated service call")
    if _HTTP_CLIENT_CALL_RE.search(text):
        auth_hits = [
            label
            for label, pattern in _OUTBOUND_AUTH_PATTERNS
            if pattern.search(text)
        ]
        if auth_hits:
            hits.append("HTTP call with auth/signing evidence")
            hits.extend(auth_hits)
        else:
            hits.append("HTTP call without auth/signing evidence")
    if "webhook" in lowered and any(pattern.search(text) for _, pattern in _OUTBOUND_AUTH_PATTERNS):
        hits.append("Webhook signing evidence")
    return _dedupe(hits)


def _derive_route_risk_flags(route: _RouteDefinition) -> list[str]:
    flags: list[str] = []
    if not route.auth_guards and route.sensitive_data_signals:
        flags.append("No auth guard on sensitive-data route")
    if "Raw JSON/body access" in route.validation_signals and route.sensitive_data_signals:
        flags.append("Raw input on sensitive-data route")
    if not route.auth_guards and "HTTP call without auth/signing evidence" in route.outbound_call_signals:
        flags.append("No auth guard on route with unsigned outbound call")
    if "Raw JSON/body access" in route.validation_signals and "HTTP call without auth/signing evidence" in route.outbound_call_signals:
        flags.append("Raw input reaches unsigned outbound call")
    return _dedupe(flags)


def _get_python_source_segment(text: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(text, node)
    if segment:
        return segment
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", start)
    if start is None or end is None:
        return ""
    lines = text.splitlines()
    return "\n".join(lines[start - 1 : end])


def _python_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _python_call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _collect_webhook_endpoints(
    api_routes: list[str],
    files: list[tuple[str, str]],
) -> list[str]:
    hits = [route for route in api_routes if re.search(r"(callback|webhook|notify|event)", route, re.IGNORECASE)]
    for path, _ in files:
        lowered = path.lower()
        if re.search(r"(callback|webhook)", lowered):
            route = _route_from_next_api_path(path)
            if route:
                hits.append(route)
    return _dedupe(hits)


def _collect_auth_mechanisms(files: list[tuple[str, str]]) -> list[str]:
    text_blob = "\n".join([path for path, _ in files] + [text[:4000] for _, text in files])
    hits: list[str] = []
    for label, pattern in _AUTH_MECHANISM_PATTERNS:
        if pattern.search(text_blob):
            hits.append(label)
    return _dedupe(hits)


def _collect_outbound_calls(files: list[tuple[str, str]]) -> list[str]:
    hits: list[str] = []
    for _, text in files:
        lowered = text.lower()
        if _STRIPE_CALL_RE.search(text):
            hits.append("Stripe API calls")
        for client_name in _BOTO3_CLIENT_RE.findall(text):
            label = _QUEUE_HINTS.get(client_name.lower())
            if label:
                hits.append(f"{label} publisher/client")
            elif client_name.lower() == "s3":
                hits.append("Amazon S3 client")
            else:
                hits.append(f"AWS {client_name.upper()} client")
        for client_name, method in _HTTP_CLIENT_CALL_RE.findall(text):
            hits.append(f"{client_name.lower()} {method.lower()} outbound HTTP calls")
        if "auth0" in lowered and ("http" in lowered or "callback" in lowered):
            hits.append("Auth0 identity provider callbacks")
    return _dedupe(hits)


def _collect_infrastructure_resources(files: list[tuple[str, str]]) -> list[str]:
    hits: list[str] = []
    for path, text in files:
        lowered = text.lower()
        if PurePosixPath(path).suffix.lower() == ".tf":
            for token, label in _INFRA_RESOURCE_HINTS.items():
                if token in lowered:
                    hits.append(label)
        if PurePosixPath(path).name.lower() in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            if "postgres" in lowered:
                hits.append("PostgreSQL container")
            if "redis" in lowered:
                hits.append("Redis container")
    return _dedupe(hits)


def _join_route(prefix: str, route: str) -> str:
    combined = f"{prefix.rstrip('/')}/{route.lstrip('/')}" if prefix else route
    normalized = "/" + combined.strip("/")
    return normalized if normalized != "/" else "/"


def _route_from_next_api_path(path: str) -> str | None:
    match = _NEXT_APP_ROUTE_RE.search(path)
    if not match:
        return None
    route_path = match.group(3)
    route_path = re.sub(r"/(route\.[jt]sx?|index\.[jt]sx?)$", "", route_path)
    route_path = re.sub(r"\.[jt]sx?$", "", route_path)
    route_path = route_path.strip("/")
    return f"/api/{route_path}" if route_path else "/api"


def _load_cloud_findings(
    content: bytes,
    filename: str,
) -> tuple[str, list[dict[str, Any]], list[str]]:
    lowered = filename.lower()
    try:
        if lowered.endswith(".zip"):
            return _load_cloud_findings_from_zip(content)
        if lowered.endswith(".js"):
            data = _parse_scoutsuite_js(content)
            return "scoutsuite", _collect_scoutsuite_candidates(data), []
        if lowered.endswith(".json"):
            data = json.loads(content.decode("utf-8"))
            provider = _detect_cloud_scan_provider(data, filename)
            if provider == "scoutsuite":
                return provider, _collect_scoutsuite_candidates(data), []
            return provider, _collect_prowler_candidates(data), []
    except json.JSONDecodeError as exc:
        raise EvidenceValidationError("Cloud scan JSON could not be parsed.") from exc
    except zipfile.BadZipFile as exc:
        raise EvidenceValidationError("Cloud scan archive could not be read.") from exc
    raise EvidenceValidationError(
        "Unsupported cloud scan format. Upload Prowler JSON, ScoutSuite results.js, or a zip of ScoutSuite output."
    )


def _load_cloud_findings_from_zip(content: bytes) -> tuple[str, list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    with zipfile.ZipFile(BytesIO(content)) as archive:
        js_candidates = [info for info in archive.infolist() if info.filename.lower().endswith(".js") and "scoutsuite" in info.filename.lower()]
        json_candidates = [info for info in archive.infolist() if info.filename.lower().endswith(".json")]
        if js_candidates:
            with archive.open(js_candidates[0]) as handle:
                return "scoutsuite", _collect_scoutsuite_candidates(_parse_scoutsuite_js(handle.read())), warnings
        for info in json_candidates:
            with archive.open(info) as handle:
                raw = handle.read()
            try:
                data = json.loads(raw.decode("utf-8"))
            except Exception:
                continue
            provider = _detect_cloud_scan_provider(data, info.filename)
            if provider == "prowler":
                return provider, _collect_prowler_candidates(data), warnings
        raise EvidenceValidationError("Could not find a supported Prowler JSON or ScoutSuite results file in the archive.")


def _parse_scoutsuite_js(content: bytes) -> dict[str, Any]:
    text = content.decode("utf-8", errors="ignore").strip()
    match = re.search(r"=\s*(\{.*\})\s*;?\s*$", text, re.DOTALL)
    if not match:
        raise EvidenceValidationError("ScoutSuite results.js could not be parsed.")
    return json.loads(match.group(1))


def _detect_cloud_scan_provider(data: Any, filename: str) -> str:
    if isinstance(data, dict) and any(key.lower().startswith("scoutsuite") for key in data.keys()):
        return "scoutsuite"
    if isinstance(data, dict) and "services" in data and "metadata" in data:
        return "scoutsuite"
    if isinstance(data, list) and data:
        sample = data[0]
        if isinstance(sample, dict) and (
            "StatusExtended" in sample
            or "CheckID" in sample
            or "finding_info" in sample
            or "severity" in sample
        ):
            return "prowler"
    if isinstance(data, dict) and ("findings" in data or "ocsf_version" in data or "SchemaVersion" in data):
        return "prowler"
    if "scoutsuite" in filename.lower():
        return "scoutsuite"
    return "unknown"


def _collect_prowler_candidates(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
        entries = data["findings"]
    elif isinstance(data, list):
        entries = data
    else:
        entries = [data]
    findings: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        status = str(
            entry.get("Status")
            or entry.get("status")
            or entry.get("compliance_status")
            or entry.get("status_code")
            or ""
        ).lower()
        if status and not any(word in status for word in ("fail", "failed", "warning", "alarm", "critical")):
            continue
        detail = (
            entry.get("StatusExtended")
            or entry.get("description")
            or entry.get("finding_info", {}).get("title")
            or entry.get("title")
            or ""
        )
        findings.append(
            {
                "source_finding_id": _cloud_source_finding_id(entry),
                "service": entry.get("ServiceName") or entry.get("service_name") or entry.get("service") or "",
                "resource": entry.get("ResourceArn") or entry.get("resource_id") or entry.get("resource") or "",
                "severity": _normalize_severity(entry.get("Severity") or entry.get("severity") or entry.get("severity", {}).get("label")),
                "detail": str(detail),
            }
        )
    return findings


def _collect_scoutsuite_candidates(data: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def walk(value: Any, path: list[str]) -> None:
        if isinstance(value, dict):
            text_blob = json.dumps(value, sort_keys=True)[:2_000]
            category = _categorize_cloud_text(text_blob)
            if category != "other":
                findings.append(
                    {
                        "source_finding_id": "scoutsuite:" + ":".join(path[:6]),
                        "service": path[0] if path else "",
                        "resource": "/".join(path[1:4]),
                        "severity": _infer_scoutsuite_severity(text_blob),
                        "detail": text_blob,
                    }
                )
            for key, child in value.items():
                walk(child, [*path, str(key)])
        elif isinstance(value, list):
            for index, child in enumerate(value[:25]):
                walk(child, [*path, str(index)])

    walk(data, [])
    return findings


def _cloud_source_finding_id(entry: dict[str, Any]) -> str | None:
    candidates = (
        entry.get("FindingUniqueId"),
        entry.get("finding_uid"),
        entry.get("finding_id"),
        entry.get("id"),
        entry.get("uid"),
        entry.get("CheckID"),
        entry.get("check_id"),
        entry.get("metadata", {}).get("uid")
        if isinstance(entry.get("metadata"), dict)
        else None,
        entry.get("finding_info", {}).get("uid")
        if isinstance(entry.get("finding_info"), dict)
        else None,
    )
    for candidate in candidates:
        if candidate is None:
            continue
        value = str(candidate).strip()
        if value:
            return _truncate_text(value, 180)
    return None


def _normalize_cloud_findings(raw_findings: list[dict[str, Any]]) -> list[CloudFinding]:
    findings: list[CloudFinding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in raw_findings:
        detail = _truncate_text(str(item.get("detail") or ""), 220)
        category = _categorize_cloud_text(
            " ".join(
                [
                    str(item.get("service") or ""),
                    str(item.get("resource") or ""),
                    detail,
                ]
            )
        )
        if category == "other":
            continue
        severity = _normalize_severity(item.get("severity"))
        service = _truncate_text(str(item.get("service") or ""), 80)
        resource = _truncate_text(str(item.get("resource") or ""), 120)
        source_finding_id = _truncate_text(str(item.get("source_finding_id") or ""), 180) or None
        key = (source_finding_id or "", category, service, resource)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            CloudFinding(
                category=category,
                severity=severity,
                service=service,
                resource=resource,
                detail=detail,
                source_finding_id=source_finding_id,
            )
        )
    findings.sort(key=lambda finding: (_severity_rank(finding.severity), finding.category, finding.service), reverse=False)
    findings.sort(key=lambda finding: _severity_rank(finding.severity), reverse=True)
    return findings


def _collect_cloud_summary(findings: list[CloudFinding], categories: set[str]) -> list[str]:
    hits: list[str] = []
    for finding in findings:
        if finding.category in categories:
            label = " / ".join(part for part in [finding.service, finding.resource] if part)
            hits.append(label or finding.detail)
    return _dedupe(hits)


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "critical" in text:
        return "Critical"
    if "high" in text:
        return "High"
    if "medium" in text or "moderate" in text:
        return "Medium"
    if "low" in text:
        return "Low"
    return "Medium"


def _severity_rank(value: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(value, 0)


def _categorize_cloud_text(text: str) -> str:
    for category, pattern in _CLOUD_FINDING_CATEGORY_PATTERNS:
        if pattern.search(text):
            return category
    return "other"


def _infer_scoutsuite_severity(text: str) -> str:
    lowered = text.lower()
    if "critical" in lowered:
        return "Critical"
    if "high" in lowered:
        return "High"
    if "medium" in lowered:
        return "Medium"
    return "Medium"


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        cleaned = _truncate_text(item.strip(), 140)
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
        if len(deduped) >= MAX_PREVIEW_ITEMS:
            break
    return deduped


def _stable_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or "suggestion"


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."
