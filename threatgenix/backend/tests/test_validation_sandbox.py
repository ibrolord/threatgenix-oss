from __future__ import annotations

import pytest

from app.services.validation_sandbox import (
    ContainerValidationSandboxRunner,
    VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV,
    ValidationSandboxError,
    ValidationSandboxRunner,
    ValidationSandboxTargetError,
    create_validation_sandbox_runner,
    validate_validation_target_reference,
)

PYTHON_EXECUTABLE = "python3"


def test_managed_target_reference_allows_missing_worker_path_under_root(tmp_path):
    missing_repo = tmp_path / "tenant-a" / "repo"

    resolved = validate_validation_target_reference(
        str(missing_repo),
        "repository_path",
        allowed_roots=[str(tmp_path)],
    )

    assert resolved == str(missing_repo.resolve(strict=False))


def test_managed_target_reference_rejects_relative_path(tmp_path):
    with pytest.raises(ValidationSandboxTargetError, match="absolute path"):
        validate_validation_target_reference(
            "tenant-a/repo",
            "repository_path",
            allowed_roots=[str(tmp_path)],
        )


def test_managed_target_reference_rejects_path_outside_root(tmp_path):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside" / "repo"

    with pytest.raises(ValidationSandboxTargetError, match="outside configured allowed roots"):
        validate_validation_target_reference(
            str(outside),
            "repository_path",
            allowed_roots=[str(allowed)],
        )


@pytest.mark.asyncio
async def test_sandbox_rejects_path_target_without_allowlist(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    runner = ValidationSandboxRunner(allowed_roots=[])

    with pytest.raises(ValidationSandboxTargetError, match="allow"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')", str(target)],
            tool_name="semgrep",
            executable=PYTHON_EXECUTABLE,
            target=str(target),
            target_type="repository_path",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_sandbox_rejects_path_outside_allowlist(tmp_path):
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    runner = ValidationSandboxRunner(allowed_roots=[str(allowed)])

    with pytest.raises(ValidationSandboxTargetError, match="outside"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')", str(denied)],
            tool_name="semgrep",
            executable=PYTHON_EXECUTABLE,
            target=str(denied),
            target_type="repository_path",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_sandbox_resolves_symlinks_before_allowlist_check(tmp_path):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    link = allowed / "link"
    allowed.mkdir()
    outside.mkdir()
    link.symlink_to(outside, target_is_directory=True)
    runner = ValidationSandboxRunner(allowed_roots=[str(allowed)])

    with pytest.raises(ValidationSandboxTargetError, match="outside"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')", str(link)],
            tool_name="semgrep",
            executable=PYTHON_EXECUTABLE,
            target=str(link),
            target_type="repository_path",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_sandbox_rejects_nested_symlink_escape_inside_allowed_repo(tmp_path):
    allowed = tmp_path / "allowed"
    repo = allowed / "repo"
    outside = tmp_path / "outside"
    allowed.mkdir()
    repo.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("do not scan\n")
    (repo / "external").symlink_to(outside, target_is_directory=True)
    runner = ValidationSandboxRunner(allowed_roots=[str(allowed)])

    with pytest.raises(ValidationSandboxTargetError, match="symlink outside"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')", str(repo)],
            tool_name="semgrep",
            executable=PYTHON_EXECUTABLE,
            target=str(repo),
            target_type="repository_path",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_sandbox_returns_structured_result_for_allowed_path(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    runner = ValidationSandboxRunner(allowed_roots=[str(tmp_path)])

    result = await runner.run(
        [PYTHON_EXECUTABLE, "-c", "print('ok')", str(target)],
        tool_name="semgrep",
        executable=PYTHON_EXECUTABLE,
        target=str(target),
        target_type="repository_path",
        timeout_seconds=5,
        max_output_bytes=1024,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == b"ok"
    assert result.resolved_target == str(target.resolve())
    assert result.command[0].endswith(f"/{PYTHON_EXECUTABLE}")


@pytest.mark.asyncio
async def test_sandbox_uses_fixed_process_path_not_parent_path(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    monkeypatch.setenv("PATH", f"{target}:/tmp/fake-bin")
    runner = ValidationSandboxRunner(allowed_roots=[str(tmp_path)])

    result = await runner.run(
        [
            PYTHON_EXECUTABLE,
            "-c",
            "import os; print(os.environ['PATH'])",
            str(target),
        ],
        tool_name="semgrep",
        executable=PYTHON_EXECUTABLE,
        target=str(target),
        target_type="repository_path",
        timeout_seconds=5,
        max_output_bytes=1024,
    )

    path_value = result.stdout.decode("utf-8").strip()
    assert str(target) not in path_value
    assert "/tmp/fake-bin" not in path_value
    assert "/usr/bin" in path_value


@pytest.mark.asyncio
async def test_sandbox_requires_lockfile_target_to_be_file(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    runner = ValidationSandboxRunner(allowed_roots=[str(tmp_path)])

    with pytest.raises(ValidationSandboxTargetError, match="must be a file"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')", str(target)],
            tool_name="osv-scanner",
            executable=PYTHON_EXECUTABLE,
            target=str(target),
            target_type="lockfile",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_sandbox_requires_repository_target_to_be_directory(tmp_path):
    target = tmp_path / "requirements.txt"
    target.write_text("pyjwt==1.7.1\n")
    runner = ValidationSandboxRunner(allowed_roots=[str(tmp_path)])

    with pytest.raises(ValidationSandboxTargetError, match="must be a directory"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')", str(target)],
            tool_name="semgrep",
            executable=PYTHON_EXECUTABLE,
            target=str(target),
            target_type="repository_path",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_sandbox_kills_process_on_timeout():
    runner = ValidationSandboxRunner(allowed_roots=[])

    result = await runner.run(
        [PYTHON_EXECUTABLE, "-c", "import time; time.sleep(5)"],
        tool_name="semgrep",
        executable=PYTHON_EXECUTABLE,
        target="not-a-path",
        target_type="container_image",
        timeout_seconds=1,
        max_output_bytes=1024,
    )

    assert result.timed_out is True
    assert result.returncode == -1


@pytest.mark.asyncio
async def test_sandbox_rejects_oversized_output():
    runner = ValidationSandboxRunner(allowed_roots=[])

    result = await runner.run(
        [PYTHON_EXECUTABLE, "-c", "print('x' * 2048)"],
        tool_name="semgrep",
        executable=PYTHON_EXECUTABLE,
        target="not-a-path",
        target_type="container_image",
        timeout_seconds=5,
        max_output_bytes=128,
    )

    assert result.output_limit_exceeded is True
    assert result.returncode == -1


@pytest.mark.asyncio
async def test_sandbox_rejects_unexpected_executable():
    runner = ValidationSandboxRunner(allowed_roots=[])

    with pytest.raises(ValidationSandboxError, match="not allowed"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')"],
            tool_name="semgrep",
            executable="semgrep",
            target="not-a-path",
            target_type="container_image",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_sandbox_rejects_absolute_executable_path_even_when_basename_matches(tmp_path):
    fake = tmp_path / "semgrep"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    runner = ValidationSandboxRunner(allowed_roots=[])

    with pytest.raises(ValidationSandboxError, match="approved basename|not allowed"):
        await runner.run(
            [str(fake)],
            tool_name="semgrep",
            executable="semgrep",
            target="not-a-path",
            target_type="container_image",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_process_sandbox_rejects_unenforced_network_policy(monkeypatch):
    monkeypatch.delenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, raising=False)
    runner = ValidationSandboxRunner(allowed_roots=[], network_mode="advisory_db")

    with pytest.raises(ValidationSandboxError, match="isolated network runner"):
        await runner.run(
            ["osv-scanner", "scan", "."],
            tool_name="osv-scanner",
            executable="osv-scanner",
            target="not-a-path",
            target_type="container_image",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.asyncio
async def test_process_sandbox_allows_advisory_db_network_with_local_opt_in(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("THREATGENIX_APP_ENV", raising=False)
    monkeypatch.setenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, "true")
    runner = ValidationSandboxRunner(allowed_roots=[], network_mode="advisory_db")

    result = await runner.run(
        [PYTHON_EXECUTABLE, "-c", "print('ok')"],
        tool_name="osv-scanner",
        executable=PYTHON_EXECUTABLE,
        target="not-a-path",
        target_type="container_image",
        timeout_seconds=5,
        max_output_bytes=1024,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == b"ok"
    assert result.network_policy == "host_process"


@pytest.mark.asyncio
async def test_process_sandbox_rejects_advisory_db_network_for_self_hosted_production_opt_in(
    monkeypatch,
):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("THREATGENIX_APP_ENV", raising=False)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, "true")
    runner = ValidationSandboxRunner(allowed_roots=[], network_mode="advisory_db")

    with pytest.raises(ValidationSandboxError, match="isolated network runner"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')"],
            tool_name="osv-scanner",
            executable=PYTHON_EXECUTABLE,
            target="not-a-path",
            target_type="container_image",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


@pytest.mark.parametrize(
    ("env_name", "env_value"),
    [
        ("APP_ENV", "production"),
        ("APP_ENV", "staging"),
        ("THREATGENIX_APP_ENV", "production"),
        ("THREATGENIX_APP_ENV", "staging"),
    ],
)
@pytest.mark.asyncio
async def test_process_sandbox_rejects_advisory_db_opt_in_in_production_like_env(
    monkeypatch,
    env_name,
    env_value,
):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("THREATGENIX_APP_ENV", raising=False)
    monkeypatch.delenv("THREATGENIX_VALIDATION_RUNTIME_MODE", raising=False)
    monkeypatch.setenv(env_name, env_value)
    monkeypatch.setenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, "true")
    runner = ValidationSandboxRunner(allowed_roots=[], network_mode="advisory_db")

    with pytest.raises(ValidationSandboxError, match="isolated network runner"):
        await runner.run(
            [PYTHON_EXECUTABLE, "-c", "print('ok')"],
            tool_name="osv-scanner",
            executable=PYTHON_EXECUTABLE,
            target="not-a-path",
            target_type="container_image",
            timeout_seconds=5,
            max_output_bytes=1024,
        )


def test_container_sandbox_builds_readonly_mounts_and_limits(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    runner = ContainerValidationSandboxRunner(
        allowed_roots=[str(tmp_path)],
        runtime_path="/usr/local/bin/docker",
        network_mode="none",
    )

    command, network, limits = runner.build_container_command(
        [
            "semgrep",
            "scan",
            "--config",
            str(rules),
            str(repo),
            "--output",
            str(artifacts / "report.json"),
        ],
        image="semgrep/semgrep:latest",
        target=str(repo),
        resolved_target=str(repo.resolve()),
        target_type="repository_path",
        artifacts_dir=str(artifacts),
    )

    assert command[:2] == ["/usr/local/bin/docker", "run"]
    assert "--rm" in command
    assert "--read-only" in command
    assert "--cap-drop" in command
    assert "ALL" in command
    assert "--security-opt" in command
    assert "no-new-privileges" in command
    assert network == "none"
    assert limits == {"cpus": "1", "memory": "1g", "pids": "256"}
    assert any("target=/workspace/target,readonly" in item for item in command)
    assert any("target=/artifacts" in item and ",readonly" not in item for item in command)
    assert "/workspace/target" in command
    assert "/artifacts/report.json" in command
    assert "semgrep/semgrep:latest" in command


def test_container_sandbox_rejects_target_network_without_configured_network(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    runner = ContainerValidationSandboxRunner(
        allowed_roots=[str(tmp_path)],
        runtime_path="/usr/local/bin/docker",
        network_mode="target_only",
    )

    with pytest.raises(ValidationSandboxError, match="explicitly configured container network"):
        runner.build_container_command(
            ["nuclei", "-u", "https://api.example.com"],
            image="projectdiscovery/nuclei:latest",
            target="https://api.example.com",
            resolved_target="https://api.example.com",
            target_type="url",
            artifacts_dir=str(artifacts),
        )


def test_sandbox_factory_uses_container_mode(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "container")
    monkeypatch.setattr(
        "app.services.validation_sandbox.shutil.which",
        lambda executable, path=None: "/usr/local/bin/docker" if executable == "docker" else None,
    )

    runner = create_validation_sandbox_runner(network_mode="none")

    assert isinstance(runner, ContainerValidationSandboxRunner)
