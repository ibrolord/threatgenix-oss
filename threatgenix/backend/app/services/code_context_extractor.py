"""Extract source-referenced code context without executing customer code."""

from __future__ import annotations

import ast
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from app.schemas.tool_harness import (
    HarnessEnvelope,
    HarnessEvent,
    HarnessEvidenceItem,
    HarnessRequest,
    HarnessResult,
)
from app.services.application_review_bundles import (
    ReviewBundleValidationError,
    canonical_json,
    safe_manifest_path,
)

CODE_CONTEXT_EXTRACTOR_VERSION = "python-fastapi-0.1.0"
FASTAPI_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "api_route", "websocket"}
AUTH_TERMS = {
    "auth",
    "authenticate",
    "authenticated",
    "current_user",
    "get_current_user",
    "require_user",
    "require_auth",
    "jwt",
    "oauth",
    "session",
}
AUTHZ_TERMS = {
    "authorize",
    "authorized",
    "authorization",
    "permission",
    "permissions",
    "role",
    "roles",
    "rbac",
    "is_admin",
    "tenant_id",
    "organization_id",
    "owner_id",
    "can_",
}
SENSITIVE_TERMS = {
    "ssn",
    "sin",
    "pii",
    "email",
    "phone",
    "address",
    "dob",
    "date_of_birth",
    "user",
    "customer",
    "account",
    "export",
    "payment",
    "card",
    "token",
}
DATA_ACCESS_TERMS = {
    "select",
    "insert",
    "update",
    "delete",
    "query",
    "execute",
    "session",
    "db",
    "sqlalchemy",
    "repository",
    "collection",
    "find",
}
EXTERNAL_CALL_TERMS = {"requests", "httpx", "aiohttp", "boto3", "stripe", "sendgrid", "twilio"}


@dataclass(frozen=True)
class CodeSourceFile:
    """Customer source supplied by a bundle reader, CLI, or GitHub adapter."""

    path: str
    content: str
    sha256: str | None = None
    file_kind: str = "source"


@dataclass(frozen=True)
class CodeSurface:
    """One source-referenced surface extracted from customer code."""

    surface_id: str
    kind: str
    path: str
    start_line: int
    end_line: int
    framework: str
    handler: str | None = None
    method: str | None = None
    route_path: str | None = None
    auth_controls: list[str] = field(default_factory=list)
    authorization_checks: list[str] = field(default_factory=list)
    data_touched: list[str] = field(default_factory=list)
    sensitive_signals: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    exposure_hints: list[str] = field(default_factory=list)
    uncertainty: list[str] = field(default_factory=list)
    confidence: float = 0.5

    @property
    def title(self) -> str:
        if self.method and self.route_path:
            return f"{self.method.upper()} {self.route_path}"
        if self.handler:
            return f"{self.kind} {self.handler}"
        return f"{self.kind} {self.path}"

    def source_ref(self) -> dict[str, Any]:
        return {
            "type": "path",
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }

    def to_context_payload(self) -> dict[str, Any]:
        return {
            "id": self.surface_id,
            "title": self.title,
            "kind": self.kind,
            "framework": self.framework,
            "path": self.path,
            "handler": self.handler,
            "method": self.method,
            "route_path": self.route_path,
            "source_refs": [self.source_ref()],
            "auth_controls": self.auth_controls,
            "authorization_checks": self.authorization_checks,
            "data_touched": self.data_touched,
            "sensitive_signals": self.sensitive_signals,
            "external_calls": self.external_calls,
            "exposure_hints": self.exposure_hints,
            "uncertainty": self.uncertainty,
            "confidence": self.confidence,
            "facets": {
                "category": "code_context",
                "framework": self.framework,
                "kind": self.kind,
                "path": self.path,
                "method": self.method,
                "route_path": self.route_path,
                "has_auth": bool(self.auth_controls),
                "has_authz": bool(self.authorization_checks),
                "has_sensitive_signals": bool(self.sensitive_signals),
                "uncertainty_count": len(self.uncertainty),
            },
        }


@dataclass(frozen=True)
class CodeContextExtractionResult:
    surfaces: list[CodeSurface]
    warnings: list[str]
    skipped_paths: list[str]
    extractor_version: str = CODE_CONTEXT_EXTRACTOR_VERSION

    def to_context_payloads(self) -> list[dict[str, Any]]:
        return [surface.to_context_payload() for surface in self.surfaces]


def extract_code_context(
    files: list[CodeSourceFile],
    *,
    manifest_paths: set[str] | None = None,
) -> CodeContextExtractionResult:
    """Extract Python/FastAPI context from supplied source text.

    This function deliberately parses text only. It never imports customer modules
    and never executes customer code.
    """

    allowed_paths = _safe_manifest_paths(manifest_paths or set())
    warnings: list[str] = []
    skipped_paths: list[str] = []
    surfaces: list[CodeSurface] = []

    for source_file in sorted(files, key=lambda item: item.path):
        try:
            safe_path = safe_manifest_path(source_file.path)
        except ReviewBundleValidationError as exc:
            skipped_paths.append(source_file.path)
            warnings.append(f"Skipped unsafe source path {source_file.path!r}: {exc}")
            continue
        if allowed_paths and safe_path not in allowed_paths:
            skipped_paths.append(safe_path)
            warnings.append(f"Skipped source path not present in review bundle manifest: {safe_path}")
            continue
        if source_file.file_kind not in {"source", "config", "other"} and not safe_path.endswith(".py"):
            continue
        if not safe_path.endswith(".py"):
            continue
        surfaces.extend(_extract_python_file(safe_path, source_file.content, warnings))

    return CodeContextExtractionResult(
        surfaces=surfaces,
        warnings=warnings,
        skipped_paths=skipped_paths,
    )


def build_code_context_harness_envelope(
    *,
    tenant_key: str,
    review_id: UUID,
    bundle_id: UUID,
    files: list[CodeSourceFile],
    manifest_paths: set[str],
    idempotency_key: str,
) -> HarnessEnvelope:
    started_at = time.monotonic()
    result = extract_code_context(files, manifest_paths=manifest_paths)
    payloads = result.to_context_payloads()
    evidence_hash = hashlib.sha256(canonical_json(payloads).encode("utf-8")).hexdigest()
    duration_ms = int((time.monotonic() - started_at) * 1000)
    return HarnessEnvelope(
        request=HarnessRequest(
            tool_name="code_context_extractor",
            tool_version=CODE_CONTEXT_EXTRACTOR_VERSION,
            tenant_key=tenant_key,
            review_id=review_id,
            bundle_id=bundle_id,
            idempotency_key=idempotency_key,
            inputs={"paths": sorted(manifest_paths), "stack": "python_fastapi"},
            policy={
                "network": "none",
                "timeout_seconds": 120,
                "allowed_targets": [f"tgx-review-bundle://{bundle_id}"],
            },
        ),
        result=HarnessResult(
            status="completed",
            evidence_items=[
                HarnessEvidenceItem(
                    item_type="code_context",
                    title="Python/FastAPI code context",
                    source_refs=sorted({surface.path for surface in result.surfaces}),
                    content_hash=evidence_hash,
                    metadata={
                        "extractor_version": result.extractor_version,
                        "stack": "python_fastapi",
                        "surface_count": len(result.surfaces),
                        "surfaces": payloads,
                        "skipped_paths": result.skipped_paths,
                    },
                )
            ],
            warnings=result.warnings,
            normalized_findings=[],
        ),
        events=[
            HarnessEvent(event_type="started", message="started code context extraction", elapsed_ms=0),
            HarnessEvent(
                event_type="completed",
                message="completed code context extraction",
                elapsed_ms=duration_ms,
            ),
        ],
        duration_ms=duration_ms,
    )


def _extract_python_file(path: str, content: str, warnings: list[str]) -> list[CodeSurface]:
    try:
        module = ast.parse(content, filename=path)
    except SyntaxError as exc:
        warnings.append(f"Could not parse {path}: syntax error on line {exc.lineno or 1}")
        return [
            _file_surface(
                path=path,
                content=content,
                uncertainty=[f"syntax_error:{exc.lineno or 1}"],
                confidence=0.1,
            )
        ]

    imports = _import_names(module)
    text_lower = content.casefold()
    routes = _route_surfaces(path, module, imports, text_lower)
    if routes:
        return routes
    if "fastapi" in imports or "apirouter" in text_lower or "fastapi" in text_lower:
        return [
            _file_surface(
                path=path,
                content=content,
                uncertainty=["fastapi_import_present_but_no_route_decorator_found"],
                confidence=0.35,
            )
        ]
    return [
        _file_surface(
            path=path,
            content=content,
            framework="unsupported",
            uncertainty=["unsupported_or_no_fastapi_surface_found"],
            confidence=0.2,
        )
    ]


def _route_surfaces(
    path: str,
    module: ast.Module,
    imports: set[str],
    file_text_lower: str,
) -> list[CodeSurface]:
    surfaces: list[CodeSurface] = []
    for node in ast.walk(module):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        route_decorators = [_route_from_decorator(decorator) for decorator in node.decorator_list]
        route_decorators = [route for route in route_decorators if route is not None]
        if not route_decorators:
            continue
        source_text = _node_text(node)
        source_lower = source_text.casefold()
        auth_controls = _matched_terms(source_lower, AUTH_TERMS)
        authorization_checks = _matched_terms(source_lower, AUTHZ_TERMS)
        data_touched = _matched_terms(source_lower, DATA_ACCESS_TERMS | SENSITIVE_TERMS)
        sensitive_signals = _matched_terms(
            " ".join([source_lower, file_text_lower, " ".join(route.path for route in route_decorators)]),
            SENSITIVE_TERMS,
        )
        external_calls = _matched_terms(source_lower, EXTERNAL_CALL_TERMS)
        exposure_hints = _exposure_hints(route_decorators, node, source_lower)
        uncertainty = _route_uncertainty(route_decorators, auth_controls, authorization_checks, sensitive_signals, source_lower)
        confidence = _route_confidence(imports, auth_controls, authorization_checks, uncertainty)
        start_line = min(
            [node.lineno, *[decorator.lineno for decorator in node.decorator_list if hasattr(decorator, "lineno")]]
        )
        for route in route_decorators:
            surfaces.append(
                CodeSurface(
                    surface_id=_surface_id(path, node.name, route.method, route.path, start_line),
                    kind="route",
                    path=path,
                    start_line=start_line,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    framework="fastapi",
                    handler=node.name,
                    method=route.method,
                    route_path=route.path,
                    auth_controls=auth_controls,
                    authorization_checks=authorization_checks,
                    data_touched=data_touched,
                    sensitive_signals=sensitive_signals,
                    external_calls=external_calls,
                    exposure_hints=exposure_hints,
                    uncertainty=uncertainty,
                    confidence=confidence,
                )
            )
    return sorted(surfaces, key=lambda surface: (surface.path, surface.start_line, surface.method or "", surface.route_path or ""))


@dataclass(frozen=True)
class _RouteDecorator:
    method: str
    path: str


def _route_from_decorator(decorator: ast.expr) -> _RouteDecorator | None:
    call = decorator if isinstance(decorator, ast.Call) else None
    func = call.func if call is not None else decorator
    method = _attribute_name(func)
    if method not in FASTAPI_ROUTE_METHODS:
        return None
    if call is None:
        return _RouteDecorator(method=method, path="<dynamic>")
    route_path = _literal_first_arg(call)
    if route_path is None:
        route_path = _keyword_literal(call, "path") or "<dynamic>"
    if method == "api_route":
        method = _api_route_method(call)
    return _RouteDecorator(method=method, path=route_path)


def _attribute_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr.casefold()
    if isinstance(node, ast.Name):
        return node.id.casefold()
    return None


def _literal_first_arg(call: ast.Call) -> str | None:
    if not call.args:
        return None
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _keyword_literal(call: ast.Call, keyword_name: str) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == keyword_name and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value
    return None


def _api_route_method(call: ast.Call) -> str:
    for keyword in call.keywords:
        if keyword.arg == "methods" and isinstance(keyword.value, ast.List):
            for item in keyword.value.elts:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    return item.value.casefold()
    return "api_route"


def _import_names(module: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.casefold())
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.casefold())
            for alias in node.names:
                names.add(alias.name.casefold())
    return names


def _node_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _matched_terms(text: str, terms: set[str]) -> list[str]:
    matched = []
    for term in sorted(terms):
        pattern = rf"(?<![a-zA-Z0-9_]){re.escape(term.casefold())}(?![a-zA-Z0-9_])"
        if re.search(pattern, text):
            matched.append(term)
    return matched


def _exposure_hints(routes: list[_RouteDecorator], node: ast.AST, source_lower: str) -> list[str]:
    hints: set[str] = set()
    for route in routes:
        if route.path.startswith("/"):
            hints.add("http_route")
        if "webhook" in route.path.casefold():
            hints.add("webhook")
        if route.method in {"post", "put", "patch", "delete"}:
            hints.add("state_changing_method")
    if "uploadfile" in source_lower or "file(" in source_lower:
        hints.add("file_upload")
    if isinstance(node, ast.AsyncFunctionDef):
        hints.add("async_handler")
    return sorted(hints)


def _route_uncertainty(
    routes: list[_RouteDecorator],
    auth_controls: list[str],
    authorization_checks: list[str],
    sensitive_signals: list[str],
    source_lower: str,
) -> list[str]:
    uncertainty: list[str] = []
    if not auth_controls:
        uncertainty.append("auth_control_not_identified")
    if sensitive_signals and auth_controls and not authorization_checks:
        uncertainty.append("sensitive_route_auth_present_but_authz_not_identified")
    if sensitive_signals and not {"tenant_id", "organization_id", "owner_id"} & set(authorization_checks):
        uncertainty.append("tenant_or_owner_scope_not_identified")
    for route in routes:
        if route.path == "<dynamic>":
            uncertainty.append("dynamic_route_path")
        if "webhook" in route.path.casefold() and not any(term in source_lower for term in ("signature", "hmac", "verify")):
            uncertainty.append("webhook_signature_verification_not_identified")
    return sorted(set(uncertainty))


def _route_confidence(
    imports: set[str],
    auth_controls: list[str],
    authorization_checks: list[str],
    uncertainty: list[str],
) -> float:
    score = 0.55
    if "fastapi" in imports or "fastapi.routing" in imports or "apirouter" in imports:
        score += 0.15
    if auth_controls:
        score += 0.1
    if authorization_checks:
        score += 0.1
    score -= min(0.25, 0.05 * len(uncertainty))
    return round(max(0.05, min(0.95, score)), 2)


def _file_surface(
    *,
    path: str,
    content: str,
    uncertainty: list[str],
    confidence: float,
    framework: str = "fastapi",
) -> CodeSurface:
    line_count = max(1, content.count("\n") + 1)
    return CodeSurface(
        surface_id=_surface_id(path, "file", None, None, 1),
        kind="file",
        path=path,
        start_line=1,
        end_line=line_count,
        framework=framework,
        sensitive_signals=_matched_terms(content.casefold(), SENSITIVE_TERMS),
        external_calls=_matched_terms(content.casefold(), EXTERNAL_CALL_TERMS),
        uncertainty=uncertainty,
        confidence=confidence,
    )


def _surface_id(
    path: str,
    handler: str,
    method: str | None,
    route_path: str | None,
    start_line: int,
) -> str:
    payload = {
        "path": path,
        "handler": handler,
        "method": method,
        "route_path": route_path,
        "start_line": start_line,
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:24]
    return f"code-surface:{digest}"


def _safe_manifest_paths(paths: set[str]) -> set[str]:
    safe_paths: set[str] = set()
    for path in paths:
        safe_paths.add(safe_manifest_path(path))
    return safe_paths
