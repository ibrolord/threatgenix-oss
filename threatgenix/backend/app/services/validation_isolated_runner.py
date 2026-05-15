"""Remote isolated runner contract for networked validation tools.

This module keeps hosted SaaS network scanners out of the Cloud Run process
worker. It builds auditable Kubernetes job specs with per-job egress policy and
optionally submits them with kubectl when the GKE runner backend is configured.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import re
import secrets
import shutil
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode, urlparse, urlunparse
from uuid import UUID

import httpx

from app.services.target_safety import LiveTargetSafetyError, validate_live_url_target
from app.services.validation_env import validation_env_flag, validation_env_value
from app.services.validation_execution_policy import (
    NETWORK_ADVISORY_DB,
    NETWORK_TARGET_ONLY,
    TARGET_LOCKFILE,
    TARGET_REPOSITORY_PATH,
    ValidationExecutionPolicy,
)
from app.services.validation_sandbox import (
    validation_isolated_runner_backend,
    validation_isolated_runner_image_pinned,
    validation_isolated_runner_ready_for,
    validation_isolated_runner_tool_image,
    validate_validation_target_access,
)
from app.services.validation_tools import (
    NUCLEI_TOOL_NAME,
    OSV_SCANNER_TOOL_NAME,
    ValidationToolAdapter,
    ValidationToolResult,
    ValidationToolUnavailable,
    redact_validation_command,
    sanitize_validation_target_for_storage,
)

ISOLATED_NAMESPACE_ENV = "THREATGENIX_VALIDATION_ISOLATED_NAMESPACE"
ISOLATED_SERVICE_ACCOUNT_ENV = "THREATGENIX_VALIDATION_ISOLATED_SERVICE_ACCOUNT"
ISOLATED_EGRESS_PROXY_URL_ENV = "THREATGENIX_VALIDATION_ISOLATED_EGRESS_PROXY_URL"
ISOLATED_EGRESS_PROXY_NAMESPACE_ENV = "THREATGENIX_VALIDATION_EGRESS_PROXY_NAMESPACE"
ISOLATED_EGRESS_PROXY_APP_LABEL_ENV = "THREATGENIX_VALIDATION_EGRESS_PROXY_APP_LABEL"
ISOLATED_KUBECTL_ENV = "THREATGENIX_VALIDATION_KUBECTL"
ISOLATED_K8S_API_SERVER_ENV = "THREATGENIX_VALIDATION_K8S_API_SERVER"
ISOLATED_K8S_CA_CERT_B64_ENV = "THREATGENIX_VALIDATION_K8S_CA_CERT_B64"
ISOLATED_K8S_BEARER_TOKEN_ENV = "THREATGENIX_VALIDATION_K8S_BEARER_TOKEN"
ISOLATED_JOB_TTL_SECONDS_ENV = "THREATGENIX_VALIDATION_ISOLATED_JOB_TTL_SECONDS"
ISOLATED_LOCKFILE_CONFIGMAP_MAX_BYTES_ENV = (
    "THREATGENIX_VALIDATION_ISOLATED_LOCKFILE_CONFIGMAP_MAX_BYTES"
)
ISOLATED_OSV_ADVISORY_HOSTS_ENV = "THREATGENIX_VALIDATION_OSV_ADVISORY_HOSTS"
ISOLATED_NUCLEI_ALLOW_IPV6_ENV = "THREATGENIX_VALIDATION_NUCLEI_ALLOW_IPV6"
ISOLATED_NODE_LOCAL_DNS_CIDRS_ENV = "THREATGENIX_VALIDATION_NODE_LOCAL_DNS_CIDRS"

_DEFAULT_NAMESPACE = "threatgenix-validation"
_DEFAULT_SERVICE_ACCOUNT = "threatgenix-scanner"
_DEFAULT_PROXY_APP_LABEL = "threatgenix-egress-proxy"
_DEFAULT_OSV_HOSTS = ("api.osv.dev",)
_DEFAULT_NODE_LOCAL_DNS_CIDRS = ("169.254.20.10/32",)
_SCANNER_WORKDIR = "/workspace"
_SCANNER_TARGET_DIR = "/workspace/target"
_SCANNER_RESULT_DIR = "/workspace/results"
_SCANNER_PROXY_DIR = "/etc/threatgenix/proxy"
_SCANNER_PROXY_TOKEN_FILE = f"{_SCANNER_PROXY_DIR}/token"
_K8S_LABEL_MAX = 63


class IsolatedRunnerConfigurationError(ValidationToolUnavailable):
    """Raised when remote isolated execution is requested but not configured."""


@dataclass(frozen=True)
class IsolatedNetworkGrant:
    mode: str
    allowed_hosts: tuple[str, ...]
    allowed_cidrs: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    proxy_url: str

    def as_policy_json(self) -> str:
        return json.dumps(
            {
                "mode": self.mode,
                "allowed_hosts": list(self.allowed_hosts),
                "allowed_cidrs": list(self.allowed_cidrs),
                "allowed_ports": list(self.allowed_ports),
                "proxy_url": self.proxy_url,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class IsolatedValidationJobSpec:
    scan_job_id: UUID
    threat_model_id: UUID | None
    owner_id: UUID | None
    tool_name: str
    target: str
    target_type: str
    command: tuple[str, ...]
    image: str
    namespace: str
    service_account_name: str
    active_deadline_seconds: int
    max_output_bytes: int
    network_grant: IsolatedNetworkGrant
    resource_limits: dict[str, str]
    proxy_token: str
    target_configmap_data: dict[str, str] = field(default_factory=dict)

    @property
    def job_name(self) -> str:
        return _k8s_name(f"tg-scan-{self.scan_job_id}")

    @property
    def labels(self) -> dict[str, str]:
        labels = {
            "app.kubernetes.io/name": "threatgenix-validation",
            "app.kubernetes.io/component": "scanner",
            "threatgenix.io/tool": _label_value(self.tool_name),
            "threatgenix.io/scan-job-id": _label_value(str(self.scan_job_id)),
        }
        if self.threat_model_id is not None:
            labels["threatgenix.io/threat-model-id"] = _label_value(
                str(self.threat_model_id)
            )
        if self.owner_id is not None:
            labels["threatgenix.io/tenant-id"] = _label_value(str(self.owner_id))
        return labels


Resolver = Callable[[str, int], list[str]]


def isolated_runner_can_handle(
    tool_name: str,
    policy: ValidationExecutionPolicy,
) -> bool:
    return validation_isolated_runner_ready_for(tool_name, policy.network_mode)


def build_isolated_validation_job_spec(
    *,
    scan_job_id: UUID,
    threat_model_id: UUID | None,
    owner_id: UUID | None,
    tool: ValidationToolAdapter,
    target: str,
    target_type: str,
    policy: ValidationExecutionPolicy,
    command: list[str],
    auth_headers: list[str] | None = None,
    resolver: Resolver | None = None,
) -> IsolatedValidationJobSpec:
    if tool.name not in {NUCLEI_TOOL_NAME, OSV_SCANNER_TOOL_NAME}:
        raise IsolatedRunnerConfigurationError(
            f"{tool.name} is not supported by the isolated network runner."
        )
    if policy.network_mode not in {NETWORK_ADVISORY_DB, NETWORK_TARGET_ONLY}:
        raise IsolatedRunnerConfigurationError(
            f"{tool.name} does not require isolated network execution."
        )
    if validation_isolated_runner_backend() is None:
        raise IsolatedRunnerConfigurationError(
            "THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND must be gke or kubernetes."
        )
    _required_env(ISOLATED_EGRESS_PROXY_URL_ENV)
    _required_env("THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF")
    image = validation_isolated_runner_tool_image(tool.name)
    if image is None:
        raise IsolatedRunnerConfigurationError(
            f"{tool.name} isolated runner image must be configured."
        )
    if not validation_isolated_runner_image_pinned(image):
        raise IsolatedRunnerConfigurationError(
            f"{tool.name} isolated runner image must be pinned by digest."
        )

    proxy_url = _required_env(ISOLATED_EGRESS_PROXY_URL_ENV)
    if tool.name == NUCLEI_TOOL_NAME:
        if auth_headers:
            raise IsolatedRunnerConfigurationError(
                "Authenticated Nuclei scans require a credential broker before isolated execution."
            )
        if "-disable-redirects" not in command and "-dr" not in command:
            raise IsolatedRunnerConfigurationError(
                "Nuclei isolated scans must disable redirects to avoid target-scope escape."
            )
        network_grant = build_nuclei_target_network_grant(
            target,
            proxy_url=proxy_url,
            resolver=resolver,
        )
        mapped_command = tuple(command)
        target_configmap_data: dict[str, str] = {}
    elif tool.name == OSV_SCANNER_TOOL_NAME:
        network_grant = build_osv_advisory_network_grant(proxy_url=proxy_url)
        mapped_command, target_configmap_data = _osv_command_and_input(
            command, target, target_type
        )
    else:
        raise IsolatedRunnerConfigurationError(
            f"{tool.name} is not supported by the isolated network runner."
        )

    return IsolatedValidationJobSpec(
        scan_job_id=scan_job_id,
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        tool_name=tool.name,
        target=target,
        target_type=target_type,
        command=mapped_command,
        image=image,
        namespace=(
            validation_env_value(ISOLATED_NAMESPACE_ENV, _DEFAULT_NAMESPACE) or ""
        ).strip()
        or _DEFAULT_NAMESPACE,
        service_account_name=(
            validation_env_value(
                ISOLATED_SERVICE_ACCOUNT_ENV,
                _DEFAULT_SERVICE_ACCOUNT,
            )
            or ""
        ).strip()
        or _DEFAULT_SERVICE_ACCOUNT,
        active_deadline_seconds=max(1, int(policy.max_runtime_seconds)),
        max_output_bytes=max(1, int(policy.max_output_bytes)),
        network_grant=network_grant,
        resource_limits=_resource_limits(tool.name),
        proxy_token=secrets.token_urlsafe(32),
        target_configmap_data=target_configmap_data,
    )


def build_nuclei_target_network_grant(
    target: str,
    *,
    proxy_url: str,
    resolver: Resolver | None = None,
) -> IsolatedNetworkGrant:
    parsed = urlparse(target.strip())
    if parsed.username or parsed.password:
        raise LiveTargetSafetyError(
            "Live scan target URLs must not include credentials."
        )
    validate_live_url_target(target, resolve_dns=False)
    host = (parsed.hostname or "").casefold()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = _resolve_public_addresses(host, port, resolver=resolver)
    allow_ipv6 = _env_flag(ISOLATED_NUCLEI_ALLOW_IPV6_ENV)
    cidrs: list[str] = []
    for address in addresses:
        parsed_ip = ipaddress.ip_address(address)
        if parsed_ip.version == 6 and not allow_ipv6:
            raise LiveTargetSafetyError(
                "Live scan target resolved to IPv6; enable isolated IPv6 controls before allowing it."
            )
        suffix = "/32" if parsed_ip.version == 4 else "/128"
        cidrs.append(f"{parsed_ip}{suffix}")
    return IsolatedNetworkGrant(
        mode=NETWORK_TARGET_ONLY,
        allowed_hosts=(host,),
        allowed_cidrs=tuple(sorted(set(cidrs))),
        allowed_ports=(port,),
        proxy_url=proxy_url,
    )


def build_osv_advisory_network_grant(*, proxy_url: str) -> IsolatedNetworkGrant:
    hosts = (
        tuple(
            host.casefold()
            for host in _split_csv(
                validation_env_value(ISOLATED_OSV_ADVISORY_HOSTS_ENV, "") or ""
            )
        )
        or _DEFAULT_OSV_HOSTS
    )
    return IsolatedNetworkGrant(
        mode=NETWORK_ADVISORY_DB,
        allowed_hosts=hosts,
        allowed_cidrs=(),
        allowed_ports=(443,),
        proxy_url=proxy_url,
    )


def build_kubernetes_manifest_objects(
    spec: IsolatedValidationJobSpec,
) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = [
        _proxy_token_secret(spec),
        _egress_policy_configmap(spec),
        _network_policy(spec),
    ]
    target_configmap = _target_input_configmap(spec)
    if target_configmap is not None:
        objects.append(target_configmap)
    objects.append(
        _job(
            spec,
            target_configmap_name=target_configmap["metadata"]["name"]
            if target_configmap
            else None,
        )
    )
    return objects


def render_kubernetes_manifest_json(spec: IsolatedValidationJobSpec) -> str:
    return json.dumps(
        {
            "apiVersion": "v1",
            "kind": "List",
            "items": build_kubernetes_manifest_objects(spec),
        },
        sort_keys=True,
    )


async def run_isolated_validation_tool(
    *,
    scan_job_id: UUID,
    threat_model_id: UUID | None,
    owner_id: UUID | None,
    tool: ValidationToolAdapter,
    target: str,
    target_type: str,
    policy: ValidationExecutionPolicy,
    auth_headers: list[str] | None = None,
    template_tags: str | None = None,
    target_authorization_checked: bool = False,
) -> ValidationToolResult:
    if tool.name == NUCLEI_TOOL_NAME and not target_authorization_checked:
        raise IsolatedRunnerConfigurationError(
            "Nuclei isolated execution requires tenant-scoped target authorization."
        )
    command = tool.build_command(
        target,
        auth_headers=auth_headers,
        template_tags=template_tags,
        target_type=target_type,
    )
    spec = build_isolated_validation_job_spec(
        scan_job_id=scan_job_id,
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        tool=tool,
        target=target,
        target_type=target_type,
        policy=policy,
        command=command,
        auth_headers=auth_headers,
    )
    backend = validation_isolated_runner_backend()
    if backend not in {"gke", "kubernetes"}:
        raise IsolatedRunnerConfigurationError(
            "THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND must be gke or kubernetes."
        )
    if (
        backend == "gke"
        and (validation_env_value(ISOLATED_K8S_API_SERVER_ENV, "") or "").strip()
    ):
        return await KubernetesApiIsolatedRunnerClient().run(spec, tool)
    return await KubectlIsolatedRunnerClient().run(spec, tool)


class KubectlIsolatedRunnerClient:
    """Submit an isolated scanner job with kubectl and return parsed scanner output."""

    async def run(
        self,
        spec: IsolatedValidationJobSpec,
        tool: ValidationToolAdapter,
    ) -> ValidationToolResult:
        kubectl = _kubectl_path()
        manifest = render_kubernetes_manifest_json(spec)
        await _cleanup_kubernetes_objects(kubectl, spec)
        started_command = [
            kubectl,
            "apply",
            "-f",
            "-",
        ]
        apply_result = await _run_command(started_command, input_text=manifest)
        if apply_result.returncode != 0:
            raise ValidationToolUnavailable(
                f"failed to submit isolated validation job: {apply_result.stderr.strip()}"
            )
        try:
            wait_result = await _kubectl_wait_for_job_finished(kubectl, spec)
            exit_code = await _kubectl_pod_exit_code(kubectl, spec)
            if exit_code is None:
                raise ValidationToolUnavailable(
                    "isolated validation job did not expose a terminated scanner exit code"
                )
            wait_stderr = wait_result.stderr.strip()
            if exit_code in getattr(tool, "success_returncodes", frozenset({0})):
                wait_stderr = ""
            logs_result = await _run_command(
                [
                    kubectl,
                    "logs",
                    f"job/{spec.job_name}",
                    "--namespace",
                    spec.namespace,
                    "--container",
                    "scanner",
                    "--tail=-1",
                    "--limit-bytes",
                    str(spec.max_output_bytes + 1),
                ],
                timeout_seconds=60,
            )
            if logs_result.returncode != 0:
                raise ValidationToolUnavailable(
                    f"failed to read isolated validation logs: {logs_result.stderr.strip()}"
                )
            raw_output = logs_result.stdout.encode("utf-8")
            output_limit_exceeded = len(raw_output) > spec.max_output_bytes
            if output_limit_exceeded:
                raw_output = raw_output[: spec.max_output_bytes]
            return ValidationToolResult(
                tool_name=tool.name,
                target=spec.target,
                findings=[]
                if output_limit_exceeded
                else tool.parse_output(spec.target, raw_output),
                returncode=_normalized_tool_returncode(
                    tool,
                    exit_code=exit_code,
                    wait_returncode=wait_result.returncode,
                ),
                stderr=wait_stderr or logs_result.stderr.strip(),
                command=redact_validation_command(
                    list(spec.command),
                    target=spec.target,
                    resolved_target=spec.target,
                    target_type=spec.target_type,
                ),
                resolved_target=sanitize_validation_target_for_storage(
                    spec.target,
                    spec.target_type,
                ),
                stdout_bytes=len(raw_output),
                output_limit_exceeded=output_limit_exceeded,
                sandboxed=True,
                sandbox_mode="isolated-kubernetes",
                container_image=spec.image,
                network_policy=spec.network_grant.mode,
                resource_limits=spec.resource_limits,
            )
        finally:
            await _cleanup_kubernetes_objects(kubectl, spec)


class KubernetesApiIsolatedRunnerClient:
    """Submit isolated scanner jobs with the Kubernetes API from Cloud Run."""

    async def run(
        self,
        spec: IsolatedValidationJobSpec,
        tool: ValidationToolAdapter,
    ) -> ValidationToolResult:
        manifest_objects = build_kubernetes_manifest_objects(spec)
        await self._cleanup(spec)
        async with _KubernetesApiSession() as session:
            try:
                for obj in manifest_objects:
                    result = await session.create(obj, namespace=spec.namespace)
                    if result.status_code >= 300:
                        raise ValidationToolUnavailable(
                            "failed to submit isolated validation job: "
                            f"{result.status_code} {result.text[:500]}"
                        )
                wait_deadline = time.monotonic() + spec.active_deadline_seconds + 60
                wait_condition: str | None = None
                wait_stderr = ""
                while True:
                    status = await session.get_job_status(spec)
                    condition = _kubernetes_job_condition(status)
                    if condition in {"Complete", "Failed"}:
                        wait_condition = condition
                        break
                    if time.monotonic() >= wait_deadline:
                        wait_stderr = (
                            f"isolated validation job timed out after "
                            f"{spec.active_deadline_seconds}s"
                        )
                        break
                    await asyncio.sleep(2)

                pod = await session.get_first_job_pod(spec)
                exit_code = _pod_scanner_exit_code(pod)
                if exit_code is None:
                    raise ValidationToolUnavailable(
                        "isolated validation job did not expose a terminated scanner exit code"
                    )
                if wait_condition == "Failed" and exit_code not in getattr(
                    tool, "success_returncodes", frozenset({0})
                ):
                    wait_stderr = "isolated validation job failed"
                raw_output = await session.get_pod_logs(
                    pod,
                    namespace=spec.namespace,
                    container="scanner",
                    limit_bytes=spec.max_output_bytes + 1,
                )
                output_limit_exceeded = len(raw_output) > spec.max_output_bytes
                if output_limit_exceeded:
                    raw_output = raw_output[: spec.max_output_bytes]
                return ValidationToolResult(
                    tool_name=tool.name,
                    target=spec.target,
                    findings=[]
                    if output_limit_exceeded
                    else tool.parse_output(spec.target, raw_output),
                    returncode=_normalized_tool_returncode(
                        tool,
                        exit_code=exit_code,
                        wait_returncode=0 if not wait_stderr else 1,
                    ),
                    stderr=wait_stderr,
                    command=redact_validation_command(
                        list(spec.command),
                        target=spec.target,
                        resolved_target=spec.target,
                        target_type=spec.target_type,
                    ),
                    resolved_target=sanitize_validation_target_for_storage(
                        spec.target,
                        spec.target_type,
                    ),
                    stdout_bytes=len(raw_output),
                    output_limit_exceeded=output_limit_exceeded,
                    sandboxed=True,
                    sandbox_mode="isolated-kubernetes",
                    container_image=spec.image,
                    network_policy=spec.network_grant.mode,
                    resource_limits=spec.resource_limits,
                )
            finally:
                await self._cleanup(spec, session=session)

    async def _cleanup(
        self,
        spec: IsolatedValidationJobSpec,
        *,
        session: "_KubernetesApiSession | None" = None,
    ) -> None:
        if session is not None:
            await _cleanup_kubernetes_objects_api(session, spec)
            return
        async with _KubernetesApiSession() as cleanup_session:
            await _cleanup_kubernetes_objects_api(cleanup_session, spec)


class _KubernetesApiSession:
    """Small Kubernetes API client for Cloud Run service-account execution."""

    def __init__(self) -> None:
        self.api_server = (
            (validation_env_value(ISOLATED_K8S_API_SERVER_ENV, "") or "")
            .strip()
            .rstrip("/")
        )
        if not self.api_server:
            raise IsolatedRunnerConfigurationError(
                f"{ISOLATED_K8S_API_SERVER_ENV} must be configured for the GKE runner."
            )
        self._client: httpx.AsyncClient | None = None
        self._ca_file: str | None = None

    async def __aenter__(self) -> "_KubernetesApiSession":
        token = await _kubernetes_bearer_token()
        verify = self._verification_arg()
        try:
            self._client = httpx.AsyncClient(
                base_url=self.api_server,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(30.0, connect=10.0),
                verify=verify,
            )
        except Exception:
            if self._ca_file:
                Path(self._ca_file).unlink(missing_ok=True)
            raise
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
        if self._ca_file:
            try:
                Path(self._ca_file).unlink(missing_ok=True)
            except OSError:
                pass

    async def create(
        self,
        obj: dict[str, Any],
        *,
        namespace: str,
    ) -> httpx.Response:
        return await self._request(
            "POST",
            _kubernetes_collection_path(obj, namespace=namespace),
            json=obj,
        )

    async def delete_resource(
        self,
        *,
        api_version: str,
        kind: str,
        name: str,
        namespace: str,
    ) -> httpx.Response:
        return await self._request(
            "DELETE",
            _kubernetes_object_path(
                api_version=api_version,
                kind=kind,
                name=name,
                namespace=namespace,
            ),
            json={
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Background",
            },
        )

    async def get_job_status(self, spec: IsolatedValidationJobSpec) -> dict[str, Any]:
        response = await self._request(
            "GET",
            _kubernetes_object_path(
                api_version="batch/v1",
                kind="Job",
                name=spec.job_name,
                namespace=spec.namespace,
            ),
        )
        if response.status_code >= 300:
            raise ValidationToolUnavailable(
                f"failed to read isolated validation job: {response.status_code} {response.text[:500]}"
            )
        data = response.json()
        return data if isinstance(data, dict) else {}

    async def get_first_job_pod(
        self, spec: IsolatedValidationJobSpec
    ) -> dict[str, Any]:
        query = urlencode({"labelSelector": f"job-name={spec.job_name}"})
        response = await self._request(
            "GET",
            f"/api/v1/namespaces/{quote(spec.namespace, safe='')}/pods?{query}",
        )
        if response.status_code >= 300:
            raise ValidationToolUnavailable(
                f"failed to read isolated validation pod: {response.status_code} {response.text[:500]}"
            )
        data = response.json()
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list) or not items:
            raise ValidationToolUnavailable(
                "isolated validation job did not create a pod"
            )
        pod = items[0]
        return pod if isinstance(pod, dict) else {}

    async def get_pod_logs(
        self,
        pod: dict[str, Any],
        *,
        namespace: str,
        container: str,
        limit_bytes: int,
    ) -> bytes:
        pod_name = str((pod.get("metadata") or {}).get("name") or "")
        if not pod_name:
            raise ValidationToolUnavailable("isolated validation pod name was missing")
        response = await self._request(
            "GET",
            _kubernetes_pod_logs_path(
                namespace=namespace,
                pod_name=pod_name,
                container=container,
                limit_bytes=limit_bytes,
            ),
        )
        if response.status_code >= 300:
            raise ValidationToolUnavailable(
                f"failed to read isolated validation logs: {response.status_code} {response.text[:500]}"
            )
        return response.content

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        if self._client is None:
            raise IsolatedRunnerConfigurationError(
                "Kubernetes API session is not open."
            )
        return await self._client.request(method, path, **kwargs)

    def _verification_arg(self) -> bool | ssl.SSLContext | str:
        raw = (validation_env_value(ISOLATED_K8S_CA_CERT_B64_ENV, "") or "").strip()
        if not raw:
            return True
        try:
            certificate = base64.b64decode(raw)
        except (binascii.Error, ValueError) as exc:
            raise IsolatedRunnerConfigurationError(
                f"{ISOLATED_K8S_CA_CERT_B64_ENV} must be base64 encoded."
            ) from exc
        ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
        try:
            ca_file.write(certificate)
            ca_file.flush()
        finally:
            ca_file.close()
        self._ca_file = ca_file.name
        return ca_file.name


async def _cleanup_kubernetes_objects_api(
    session: _KubernetesApiSession,
    spec: IsolatedValidationJobSpec,
) -> None:
    resources = [
        ("batch/v1", "Job", spec.job_name),
        ("networking.k8s.io/v1", "NetworkPolicy", f"{spec.job_name}-egress-np"),
        ("v1", "Secret", f"{spec.job_name}-proxy"),
        ("v1", "ConfigMap", f"{spec.job_name}-egress-cm"),
    ]
    if spec.target_configmap_data:
        resources.append(("v1", "ConfigMap", f"{spec.job_name}-target"))
    for api_version, kind, name in resources:
        response = await session.delete_resource(
            api_version=api_version,
            kind=kind,
            name=name,
            namespace=spec.namespace,
        )
        if response.status_code not in {200, 202, 404}:
            raise ValidationToolUnavailable(
                f"failed to clean up isolated validation resource {kind}/{name}: "
                f"{response.status_code} {response.text[:500]}"
            )


async def _kubernetes_bearer_token() -> str:
    configured = (validation_env_value(ISOLATED_K8S_BEARER_TOKEN_ENV, "") or "").strip()
    if configured:
        return configured
    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
        response = await client.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"},
        )
    if response.status_code >= 300:
        raise IsolatedRunnerConfigurationError(
            "failed to fetch Cloud Run service-account token for GKE runner."
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise IsolatedRunnerConfigurationError(
            "Cloud Run metadata token response was not valid JSON."
        ) from exc
    token = str(payload.get("access_token") or "")
    if not token:
        raise IsolatedRunnerConfigurationError(
            "Cloud Run metadata token response did not include access_token."
        )
    return token


def _kubernetes_collection_path(obj: dict[str, Any], *, namespace: str) -> str:
    api_version = str(obj.get("apiVersion") or "")
    kind = str(obj.get("kind") or "")
    resource = _kubernetes_resource_name(api_version, kind)
    namespace_part = quote(namespace, safe="")
    if api_version == "v1":
        return f"/api/v1/namespaces/{namespace_part}/{resource}"
    group, version = api_version.split("/", 1)
    return f"/apis/{quote(group, safe='')}/{quote(version, safe='')}/namespaces/{namespace_part}/{resource}"


def _kubernetes_object_path(
    *,
    api_version: str,
    kind: str,
    name: str,
    namespace: str,
) -> str:
    collection = _kubernetes_collection_path(
        {"apiVersion": api_version, "kind": kind},
        namespace=namespace,
    )
    return f"{collection}/{quote(name, safe='')}"


def _kubernetes_pod_logs_path(
    *,
    namespace: str,
    pod_name: str,
    container: str,
    limit_bytes: int,
) -> str:
    query = urlencode(
        {
            "container": container,
            "limitBytes": str(limit_bytes),
        }
    )
    return (
        f"/api/v1/namespaces/{quote(namespace, safe='')}/pods/"
        f"{quote(pod_name, safe='')}/log?{query}"
    )


def _kubernetes_resource_name(api_version: str, kind: str) -> str:
    resources = {
        ("v1", "ConfigMap"): "configmaps",
        ("v1", "Secret"): "secrets",
        ("v1", "Pod"): "pods",
        ("batch/v1", "Job"): "jobs",
        ("networking.k8s.io/v1", "NetworkPolicy"): "networkpolicies",
    }
    try:
        return resources[(api_version, kind)]
    except KeyError as exc:
        raise IsolatedRunnerConfigurationError(
            f"Unsupported Kubernetes object {api_version}/{kind}."
        ) from exc


def _kubernetes_job_condition(job: dict[str, Any]) -> str | None:
    status = job.get("status")
    if not isinstance(status, dict):
        return None
    for condition in status.get("conditions") or []:
        if not isinstance(condition, dict):
            continue
        if condition.get("status") == "True" and condition.get("type") in {
            "Complete",
            "Failed",
        }:
            return str(condition.get("type"))
    if status.get("succeeded"):
        return "Complete"
    if status.get("failed"):
        return "Failed"
    return None


def _pod_scanner_exit_code(pod: dict[str, Any]) -> int | None:
    status = pod.get("status")
    if not isinstance(status, dict):
        return None
    for container_status in status.get("containerStatuses") or []:
        if (
            not isinstance(container_status, dict)
            or container_status.get("name") != "scanner"
        ):
            continue
        state = container_status.get("state")
        if not isinstance(state, dict):
            return None
        terminated = state.get("terminated")
        if not isinstance(terminated, dict):
            return None
        exit_code = terminated.get("exitCode")
        if isinstance(exit_code, int):
            return exit_code
    return None


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: str
    stderr: str


async def _run_command(
    command: list[str],
    *,
    input_text: str | None = None,
    timeout_seconds: int = 120,
) -> _CommandResult:
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE if input_text is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(
                input_text.encode("utf-8") if input_text is not None else None
            ),
            timeout=timeout_seconds,
        )
    except TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        stdout, stderr = await proc.communicate()
        return _CommandResult(
            returncode=-1,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=(
                stderr.decode("utf-8", errors="replace").strip()
                or f"command timed out after {timeout_seconds}s"
            ),
        )
    return _CommandResult(
        returncode=proc.returncode or 0,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
    )


async def _kubectl_wait_for_job_finished(
    kubectl: str,
    spec: IsolatedValidationJobSpec,
) -> _CommandResult:
    deadline = time.monotonic() + spec.active_deadline_seconds + 60
    while True:
        result = await _run_command(
            [
                kubectl,
                "get",
                "job",
                spec.job_name,
                "--namespace",
                spec.namespace,
                "-o=json",
            ],
            timeout_seconds=30,
        )
        if result.returncode != 0:
            return result
        try:
            job = json.loads(result.stdout)
        except json.JSONDecodeError:
            return _CommandResult(
                returncode=1,
                stdout=result.stdout,
                stderr="failed to parse isolated validation job status",
            )
        condition = _kubernetes_job_condition(job if isinstance(job, dict) else {})
        if condition == "Complete":
            return _CommandResult(returncode=0, stdout=result.stdout, stderr="")
        if condition == "Failed":
            return _CommandResult(
                returncode=1,
                stdout=result.stdout,
                stderr="isolated validation job failed",
            )
        if time.monotonic() >= deadline:
            return _CommandResult(
                returncode=1,
                stdout=result.stdout,
                stderr=(
                    f"isolated validation job timed out after "
                    f"{spec.active_deadline_seconds}s"
                ),
            )
        await asyncio.sleep(2)


async def _kubectl_pod_exit_code(
    kubectl: str,
    spec: IsolatedValidationJobSpec,
) -> int | None:
    result = await _run_command(
        [
            kubectl,
            "get",
            "pod",
            "--namespace",
            spec.namespace,
            "-l",
            f"job-name={spec.job_name}",
            '-o=jsonpath={.items[0].status.containerStatuses[?(@.name=="scanner")].state.terminated.exitCode}',
        ],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        return None
    raw = result.stdout.strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


async def _cleanup_kubernetes_objects(
    kubectl: str,
    spec: IsolatedValidationJobSpec,
) -> None:
    resource_names = [
        f"job/{spec.job_name}",
        f"networkpolicy/{spec.job_name}-egress-np",
        f"secret/{spec.job_name}-proxy",
        f"configmap/{spec.job_name}-egress-cm",
    ]
    if spec.target_configmap_data:
        resource_names.append(f"configmap/{spec.job_name}-target")
    await _run_command(
        [
            kubectl,
            "delete",
            "--namespace",
            spec.namespace,
            "--ignore-not-found=true",
            *resource_names,
        ],
        timeout_seconds=60,
    )


def _normalized_tool_returncode(
    tool: ValidationToolAdapter,
    *,
    exit_code: int | None,
    wait_returncode: int,
) -> int:
    if exit_code is None:
        return 0 if wait_returncode == 0 else 1
    success_returncodes = getattr(tool, "success_returncodes", frozenset({0}))
    return 0 if exit_code in success_returncodes else exit_code


def _osv_command_and_input(
    command: list[str],
    target: str,
    target_type: str,
) -> tuple[tuple[str, ...], dict[str, str]]:
    if target_type == TARGET_REPOSITORY_PATH:
        raise IsolatedRunnerConfigurationError(
            "OSV repository_path scans require object-store target bundle delivery before hosted isolated execution."
        )
    if target_type != TARGET_LOCKFILE:
        raise IsolatedRunnerConfigurationError(
            "OSV isolated execution currently supports lockfile targets."
        )
    resolved = validate_validation_target_access(target, target_type)
    lockfile = Path(resolved)
    content = lockfile.read_bytes()
    max_bytes = _int_env(ISOLATED_LOCKFILE_CONFIGMAP_MAX_BYTES_ENV, default=750000)
    if len(content) > max_bytes:
        raise IsolatedRunnerConfigurationError(
            "OSV lockfile is too large for ConfigMap input; use object-store target bundle delivery."
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IsolatedRunnerConfigurationError(
            "OSV lockfile must be UTF-8 text."
        ) from exc
    container_target = f"{_SCANNER_TARGET_DIR}/{_safe_configmap_key(lockfile.name)}"
    mapped = tuple(
        container_target if arg == target or arg == resolved else arg for arg in command
    )
    return mapped, {_safe_configmap_key(lockfile.name): text}


def _resolve_public_addresses(
    host: str,
    port: int,
    *,
    resolver: Resolver | None,
) -> list[str]:
    if resolver is not None:
        addresses = resolver(host, port)
    else:
        try:
            resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise LiveTargetSafetyError(
                "Live scan target host must resolve to public routable DNS."
            ) from exc
        addresses = [item[4][0] for item in resolved if item[4]]
    if not addresses:
        raise LiveTargetSafetyError(
            "Live scan target host must resolve to public routable DNS."
        )
    allowed: list[str] = []
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        ):
            raise LiveTargetSafetyError(
                "Live scan target DNS resolves to a private, loopback, link-local, or metadata IP."
            )
        allowed.append(str(parsed))
    return sorted(set(allowed))


def _egress_policy_configmap(spec: IsolatedValidationJobSpec) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": _metadata(f"{spec.job_name}-egress-cm", spec),
        "data": {
            "policy.json": _egress_policy_json(spec),
        },
    }


def _proxy_token_secret(spec: IsolatedValidationJobSpec) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": _metadata(f"{spec.job_name}-proxy", spec),
        "type": "Opaque",
        "stringData": {
            "token": spec.proxy_token,
        },
    }


def _egress_policy_json(spec: IsolatedValidationJobSpec) -> str:
    proxy_token_sha256 = hashlib.sha256(spec.proxy_token.encode("utf-8")).hexdigest()
    return json.dumps(
        {
            "mode": spec.network_grant.mode,
            "allowed_hosts": list(spec.network_grant.allowed_hosts),
            "allowed_cidrs": list(spec.network_grant.allowed_cidrs),
            "allowed_ports": list(spec.network_grant.allowed_ports),
            "proxy_url": spec.network_grant.proxy_url,
            "proxy_token_sha256": proxy_token_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _target_input_configmap(spec: IsolatedValidationJobSpec) -> dict[str, Any] | None:
    if not spec.target_configmap_data:
        return None
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": _metadata(f"{spec.job_name}-target", spec),
        "data": spec.target_configmap_data,
    }


def _network_policy(spec: IsolatedValidationJobSpec) -> dict[str, Any]:
    proxy_url = urlparse(spec.network_grant.proxy_url)
    proxy_port = proxy_url.port or (443 if proxy_url.scheme == "https" else 8080)
    proxy_namespace = (
        validation_env_value(ISOLATED_EGRESS_PROXY_NAMESPACE_ENV, spec.namespace) or ""
    ).strip()
    proxy_app_label = (
        validation_env_value(
            ISOLATED_EGRESS_PROXY_APP_LABEL_ENV, _DEFAULT_PROXY_APP_LABEL
        )
        or ""
    ).strip()
    proxy_peer: dict[str, Any] = {
        "podSelector": {"matchLabels": {"app": proxy_app_label}}
    }
    if proxy_namespace and proxy_namespace != spec.namespace:
        proxy_peer["namespaceSelector"] = {
            "matchLabels": {"kubernetes.io/metadata.name": proxy_namespace}
        }
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": _metadata(f"{spec.job_name}-egress-np", spec),
        "spec": {
            "podSelector": {"matchLabels": spec.labels},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "kubernetes.io/metadata.name": "kube-system"
                                }
                            }
                        }
                    ],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                        {"protocol": "TCP", "port": 53},
                    ],
                },
                {
                    "to": [
                        {"ipBlock": {"cidr": cidr}} for cidr in _node_local_dns_cidrs()
                    ],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                        {"protocol": "TCP", "port": 53},
                    ],
                },
                {
                    "to": [proxy_peer],
                    "ports": [{"protocol": "TCP", "port": proxy_port}],
                },
            ],
        },
    }


def _job(
    spec: IsolatedValidationJobSpec,
    *,
    target_configmap_name: str | None,
) -> dict[str, Any]:
    volumes: list[dict[str, Any]] = [
        {"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}},
        {"name": "results", "emptyDir": {"sizeLimit": "64Mi"}},
        {
            "name": "egress-policy",
            "configMap": {"name": f"{spec.job_name}-egress-cm"},
        },
        {
            "name": "proxy-token",
            "secret": {
                "secretName": f"{spec.job_name}-proxy",
                "defaultMode": 0o440,
            },
        },
    ]
    volume_mounts: list[dict[str, Any]] = [
        {"name": "tmp", "mountPath": "/tmp"},
        {"name": "results", "mountPath": _SCANNER_RESULT_DIR},
        {
            "name": "egress-policy",
            "mountPath": "/etc/threatgenix/egress",
            "readOnly": True,
        },
        {
            "name": "proxy-token",
            "mountPath": _SCANNER_PROXY_DIR,
            "readOnly": True,
        },
    ]
    if target_configmap_name is not None:
        volumes.append({"name": "target", "configMap": {"name": target_configmap_name}})
        volume_mounts.append(
            {"name": "target", "mountPath": _SCANNER_TARGET_DIR, "readOnly": True}
        )
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": _metadata(spec.job_name, spec),
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": spec.active_deadline_seconds,
            "ttlSecondsAfterFinished": _int_env(
                ISOLATED_JOB_TTL_SECONDS_ENV, default=300
            ),
            "template": {
                "metadata": {
                    "labels": spec.labels,
                    "annotations": {
                        "threatgenix.io/network-mode": spec.network_grant.mode,
                        "threatgenix.io/allowed-hosts": ",".join(
                            spec.network_grant.allowed_hosts
                        ),
                        "threatgenix.io/allowed-cidrs": ",".join(
                            spec.network_grant.allowed_cidrs
                        ),
                    },
                },
                "spec": {
                    "restartPolicy": "Never",
                    "serviceAccountName": spec.service_account_name,
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65532,
                        "runAsGroup": 65532,
                        "fsGroup": 65532,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "scanner",
                            "image": spec.image,
                            "imagePullPolicy": "IfNotPresent",
                            "workingDir": _SCANNER_WORKDIR,
                            "env": _scanner_env(spec),
                            "volumeMounts": volume_mounts,
                            "resources": {
                                "requests": spec.resource_limits,
                                "limits": spec.resource_limits,
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                    "volumes": volumes,
                },
            },
        },
    }


def _scanner_env(spec: IsolatedValidationJobSpec) -> list[dict[str, str]]:
    proxy_base_url = _proxy_base_url(spec)
    return [
        {"name": "TG_TOOL_NAME", "value": spec.tool_name},
        {"name": "TG_TARGET", "value": spec.target},
        {"name": "TG_TARGET_TYPE", "value": spec.target_type},
        {"name": "TG_COMMAND_JSON", "value": json.dumps(list(spec.command))},
        {"name": "TG_MAX_OUTPUT_BYTES", "value": str(spec.max_output_bytes)},
        {
            "name": "TG_EGRESS_POLICY_PATH",
            "value": "/etc/threatgenix/egress/policy.json",
        },
        {"name": "HOME", "value": "/tmp"},
        {"name": "TG_PROXY_BASE_URL", "value": proxy_base_url},
        {"name": "TG_PROXY_USERNAME", "value": spec.job_name},
        {"name": "TG_PROXY_TOKEN_FILE", "value": _SCANNER_PROXY_TOKEN_FILE},
        {
            "name": "NO_PROXY",
            "value": "localhost,127.0.0.1,::1",
        },
        {
            "name": "no_proxy",
            "value": "localhost,127.0.0.1,::1",
        },
    ]


def _proxy_base_url(spec: IsolatedValidationJobSpec) -> str:
    """Return a proxy URL without job credentials for the pod spec."""
    parsed = urlparse(spec.network_grant.proxy_url)
    if not parsed.scheme or not parsed.netloc:
        raise IsolatedRunnerConfigurationError(
            f"{ISOLATED_EGRESS_PROXY_URL_ENV} must be an absolute proxy URL."
        )
    if parsed.username or parsed.password:
        raise IsolatedRunnerConfigurationError(
            f"{ISOLATED_EGRESS_PROXY_URL_ENV} must not include credentials."
        )
    host = parsed.hostname or ""
    if not host:
        raise IsolatedRunnerConfigurationError(
            f"{ISOLATED_EGRESS_PROXY_URL_ENV} must include a proxy hostname."
        )
    netloc = host
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(
        (
            parsed.scheme,
            netloc,
            parsed.path or "",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def _metadata(name: str, spec: IsolatedValidationJobSpec) -> dict[str, Any]:
    return {
        "name": _k8s_name(name),
        "namespace": spec.namespace,
        "labels": spec.labels,
        "annotations": {
            "threatgenix.io/scan-job-id": str(spec.scan_job_id),
            "threatgenix.io/tool": spec.tool_name,
        },
    }


def _resource_limits(tool_name: str) -> dict[str, str]:
    normalized = tool_name.upper().replace("-", "_")
    return {
        "cpu": validation_env_value(
            f"THREATGENIX_VALIDATION_ISOLATED_{normalized}_CPU", "1"
        )
        or "1",
        "memory": validation_env_value(
            f"THREATGENIX_VALIDATION_ISOLATED_{normalized}_MEMORY",
            "1Gi",
        )
        or "1Gi",
        "ephemeral-storage": validation_env_value(
            f"THREATGENIX_VALIDATION_ISOLATED_{normalized}_EPHEMERAL_STORAGE",
            "2Gi",
        )
        or "2Gi",
    }


def _required_env(name: str) -> str:
    value = (validation_env_value(name, "") or "").strip()
    if not value:
        raise IsolatedRunnerConfigurationError(f"{name} must be configured.")
    return value


def _int_env(name: str, *, default: int) -> int:
    raw = (validation_env_value(name, str(default)) or str(default)).strip()
    try:
        return int(raw)
    except ValueError as exc:
        raise IsolatedRunnerConfigurationError(f"{name} must be an integer.") from exc


def _kubectl_path() -> str:
    configured = (validation_env_value(ISOLATED_KUBECTL_ENV, "") or "").strip()
    if configured:
        return configured
    resolved = shutil.which("kubectl")
    if not resolved:
        raise IsolatedRunnerConfigurationError(
            "kubectl is required for the kubernetes isolated runner backend."
        )
    return resolved


def _k8s_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]+", "-", value.casefold()).strip("-")
    if not normalized:
        normalized = "tg-scan"
    return normalized[:_K8S_LABEL_MAX].rstrip("-")


def _label_value(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-_.")
    return (normalized or "unknown")[:_K8S_LABEL_MAX]


def _safe_configmap_key(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-_.")
    return normalized or "target.lock"


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _node_local_dns_cidrs() -> tuple[str, ...]:
    configured = tuple(
        _split_csv(validation_env_value(ISOLATED_NODE_LOCAL_DNS_CIDRS_ENV, "") or "")
    )
    return configured or _DEFAULT_NODE_LOCAL_DNS_CIDRS


def _env_flag(name: str) -> bool:
    return validation_env_flag(name)
