from __future__ import annotations

import uuid

from app.models.dfd import DFDNode
from app.models.scan import ScanFinding
from app.services.scan_mapper import _finding_matches_target
from app.services.validation_binding import (
    binding_target_for_scan_finding,
    infer_validation_targets_for_findings,
)
from app.services.validation_tools import (
    CheckovValidationAdapter,
    SemgrepValidationAdapter,
)


def test_infers_source_path_binding_from_node_properties():
    node = DFDNode(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        node_type="process",
        name="Authentication Service",
        properties={"source_paths": ["app/auth.py"]},
    )
    evidence = SemgrepValidationAdapter().parse_json_document(
        "/repo",
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "app/auth.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                        "metadata": {"technology": ["jwt"], "category": "security"},
                    },
                }
            ]
        },
    )[0]

    inferred = infer_validation_targets_for_findings(
        [node],
        [evidence],
        target_type="repository_path",
    )

    assert inferred == {str(node.id): "path:app/auth.py"}


def test_typed_path_binding_matches_semantic_mapper_target():
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id="python.jwt.decode-without-verify",
        template_name="JWT verification disabled",
        severity="high",
        matched_at="app/auth.py:42",
        cve_ids=[],
        tags=["jwt", "semgrep"],
        raw_output={},
    )

    assert _finding_matches_target(finding, "path:app/auth.py") is True
    assert _finding_matches_target(finding, "path:app/payments.py") is False


def test_typed_path_binding_rejects_near_miss_path_suffix():
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id="python.jwt.decode-without-verify",
        template_name="JWT verification disabled",
        severity="high",
        matched_at="app/auth.py.bak:42",
        cve_ids=[],
        tags=["jwt", "semgrep"],
        raw_output={"path": "app/auth.py.bak"},
    )

    assert _finding_matches_target(finding, "path:app/auth.py") is False


def test_infers_iac_resource_binding_from_node_properties():
    node = DFDNode(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        node_type="data_store",
        name="Statement Export Bucket",
        properties={"iac_resources": ["aws_s3_bucket_public_access_block.statement_exports"]},
    )
    evidence = CheckovValidationAdapter().parse_json_document(
        "/repo/infra",
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_55",
                        "check_name": "Ensure S3 bucket has public access block enabled",
                        "file_path": "/infra/main.tf",
                        "file_line_range": [5, 11],
                        "resource": "aws_s3_bucket_public_access_block.statement_exports",
                        "severity": "HIGH",
                    }
                ]
            }
        },
    )[0]

    inferred = infer_validation_targets_for_findings(
        [node],
        [evidence],
        target_type="iac_directory",
    )

    assert inferred == {
        str(node.id): "resource:aws_s3_bucket_public_access_block.statement_exports"
    }


def test_iac_resource_binding_rejects_ambiguous_prefix_resource():
    node = DFDNode(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        node_type="data_store",
        name="Statement Export Bucket",
        properties={"iac_resources": ["aws_s3_bucket.statement_exports"]},
    )
    evidence = CheckovValidationAdapter().parse_json_document(
        "/repo/infra",
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 bucket allows public read",
                        "file_path": "/infra/main.tf",
                        "file_line_range": [5, 11],
                        "resource": "aws_s3_bucket.statement_exports_logs",
                        "severity": "HIGH",
                    }
                ]
            }
        },
    )[0]

    inferred = infer_validation_targets_for_findings(
        [node],
        [evidence],
        target_type="iac_directory",
    )

    assert inferred == {}


def test_typed_resource_binding_rejects_ambiguous_prefix_resource():
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id="CKV_AWS_20",
        template_name="S3 bucket allows public read",
        severity="high",
        matched_at="/infra/main.tf",
        cve_ids=[],
        tags=["checkov"],
        raw_output={"resource": "aws_s3_bucket.statement_exports_logs"},
    )

    assert _finding_matches_target(finding, "resource:aws_s3_bucket.statement_exports") is False


def test_existing_scan_finding_binding_uses_source_path():
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id="python.jwt.decode-without-verify",
        template_name="JWT verification disabled",
        severity="high",
        matched_at="app/auth.py:42",
        cve_ids=[],
        tags=["jwt", "semgrep"],
        raw_output={"path": "app/auth.py", "extra": {"message": "JWT verification disabled"}},
    )

    assert binding_target_for_scan_finding(finding, target_type="repository_path") == "path:app/auth.py"


def test_existing_scan_finding_binding_uses_iac_resource_before_path():
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id="CKV_AWS_55",
        template_name="S3 public access block missing",
        severity="high",
        matched_at="/infra/main.tf",
        cve_ids=[],
        tags=["checkov"],
        raw_output={
            "resource": "aws_s3_bucket_public_access_block.statement_exports",
            "file_path": "/infra/main.tf",
        },
    )

    assert binding_target_for_scan_finding(finding, target_type="iac_directory") == (
        "resource:aws_s3_bucket_public_access_block.statement_exports"
    )
