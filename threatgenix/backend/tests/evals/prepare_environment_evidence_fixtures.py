from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path


NORTHSTAR_ARCHITECTURE_TEXT = """Northstar Bank Mobile API Gateway

Architecture summary:
- Mobile API Gateway receives public client traffic.
- FastAPI backend handles auth callback, payments, and notifications.
- PostgreSQL stores customer and payment metadata.
- Stripe receives outbound payment requests and returns webhook callbacks.
- Amazon SQS buffers async notification jobs.

Trust boundaries:
- Public Internet
- AWS VPC
- Database Subnet

Key flows:
- Mobile client -> API Gateway -> FastAPI backend
- FastAPI backend -> PostgreSQL
- FastAPI backend -> Stripe API
- Stripe webhook -> FastAPI callback surface
- FastAPI backend -> Amazon SQS -> notification workers
"""


def _write_file(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _write_simple_pdf(path: Path, text: str) -> None:
    lines = [line.rstrip() for line in text.splitlines()]
    content_lines = ["BT", "/F1 12 Tf", "72 740 Td"]
    first = True
    for line in lines:
        escaped = _escape_pdf_text(line or " ")
        if first:
            content_lines.append(f"({escaped}) Tj")
            first = False
        else:
            content_lines.append(f"T* ({escaped}) Tj")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("utf-8")

    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n",
        f"4 0 obj << /Length {len(stream)} >> stream\n".encode("utf-8") + stream + b"\nendstream endobj\n",
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("utf-8"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("utf-8"))
    pdf.extend(
        f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "utf-8"
        )
    )
    path.write_bytes(bytes(pdf))


def _build_repo_tree(root: Path) -> None:
    _write_file(
        root / "app/main.py",
        """from fastapi import FastAPI
from app.api import payments
from app.auth import callback

app = FastAPI(title="Northstar Bank Mobile API")
app.include_router(payments.router)
app.include_router(callback.router)
""",
    )
    _write_file(
        root / "app/api/payments.py",
        """import stripe
from fastapi import APIRouter

router = APIRouter(prefix="/api/payments")

@router.post("/charge")
async def create_charge(amount: int):
    return stripe.Charge.create(amount=amount, currency="cad")
""",
    )
    _write_file(
        root / "app/auth/callback.py",
        """from fastapi import APIRouter

router = APIRouter(prefix="/auth")

@router.get("/callback")
async def oidc_callback(code: str):
    return {"ok": True}
""",
    )
    _write_file(
        root / "app/services/notifications.py",
        """import boto3

sqs = boto3.client("sqs", region_name="ca-central-1")

def publish_notification(queue_url: str, message: str):
    sqs.send_message(QueueUrl=queue_url, MessageBody=message)
""",
    )
    _write_file(
        root / "requirements.txt",
        "\n".join(
            [
                "fastapi==0.115.0",
                "sqlalchemy==2.0.35",
                "psycopg2-binary==2.9.9",
                "stripe==10.12.0",
                "python-jose[cryptography]==3.3.0",
                "boto3==1.35.0",
                "auth0-python==4.7.2",
                "",
            ]
        ),
    )
    _write_file(
        root / "Dockerfile",
        """FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
""",
    )
    _write_file(
        root / "docker-compose.yml",
        """services:
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: northstar_mobile
""",
    )
    _write_file(
        root / "infra/api-gateway.tf",
        """resource "aws_api_gateway_rest_api" "mobile" {
  name = "northstar-mobile-api"
}
""",
    )


def _zip_tree(source_dir: Path, output_path: Path) -> None:
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=path.relative_to(source_dir.parent))


def _write_manifest_bundle(repo_root: Path, output_path: Path) -> None:
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path in ["requirements.txt", "Dockerfile"]:
            archive.write(repo_root / relative_path, arcname=relative_path)


def _write_prowler_json(path: Path) -> None:
    findings = [
        {
            "status_code": "FAIL",
            "severity": "CRITICAL",
            "finding_info": {"title": "Security group allows 0.0.0.0/0 ingress on port 443"},
            "resources": [{"type": "AwsEc2SecurityGroup", "uid": "sg-0abc123", "name": "mobile-api-sg"}],
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "unmapped": {"check_type": "ec2"},
        },
        {
            "status_code": "FAIL",
            "severity": "HIGH",
            "finding_info": {"title": "IAM role has AdministratorAccess policy attached"},
            "resources": [{"type": "AwsIamRole", "uid": "arn:aws:iam::role/deploy-role", "name": "deploy-role"}],
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "unmapped": {"check_type": "iam"},
        },
        {
            "status_code": "FAIL",
            "severity": "HIGH",
            "finding_info": {"title": "RDS snapshot is not encrypted at rest"},
            "resources": [{"type": "AwsRdsSnapshot", "uid": "snap-mobile-db-20260401", "name": "mobile-db-snapshot"}],
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "unmapped": {"check_type": "rds"},
        },
        {
            "status_code": "FAIL",
            "severity": "MEDIUM",
            "finding_info": {"title": "CloudTrail logging is disabled in us-east-1"},
            "resources": [{"type": "AwsCloudTrail", "uid": "trail-default", "name": "default-trail"}],
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "unmapped": {"check_type": "cloudtrail"},
        },
        {
            "status_code": "FAIL",
            "severity": "CRITICAL",
            "finding_info": {"title": "S3 bucket is publicly accessible"},
            "resources": [{"type": "AwsS3Bucket", "uid": "northstar-mobile-uploads", "name": "northstar-mobile-uploads"}],
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "unmapped": {"check_type": "s3"},
        },
        {
            "status_code": "FAIL",
            "severity": "HIGH",
            "finding_info": {"title": "IAM user has console access without MFA enabled"},
            "resources": [{"type": "AwsIamUser", "uid": "arn:aws:iam::user/deploy-bot", "name": "deploy-bot"}],
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "unmapped": {"check_type": "iam"},
        },
        {
            "status_code": "FAIL",
            "severity": "MEDIUM",
            "finding_info": {"title": "S3 bucket has default encryption disabled"},
            "resources": [{"type": "AwsS3Bucket", "uid": "northstar-logs-archive", "name": "northstar-logs-archive"}],
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "unmapped": {"check_type": "s3"},
        },
        {
            "status_code": "FAIL",
            "severity": "HIGH",
            "finding_info": {"title": "Security group allows 0.0.0.0/0 ingress on port 22"},
            "resources": [{"type": "AwsEc2SecurityGroup", "uid": "sg-0def456", "name": "bastion-sg"}],
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "unmapped": {"check_type": "ec2"},
        },
    ]
    path.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def _write_scoutsuite_js(path: Path) -> None:
    payload = {
        "services": {
            "s3": {
                "findings": [
                    {
                        "description": "Publicly accessible bucket with default encryption disabled",
                        "severity": "high",
                    }
                ]
            },
            "iam": {
                "findings": [
                    {
                        "description": "Cross-account trust with external principal and no MFA",
                        "severity": "high",
                    }
                ]
            },
        },
        "metadata": {"provider": "aws"},
    }
    path.write_text(
        f"var scoutsuite_results = {json.dumps(payload)};",
        encoding="utf-8",
    )


def _write_edge_case_fixtures(output_dir: Path) -> None:
    _write_file(output_dir / "empty.zip", b"")
    with (output_dir / "oversized.zip").open("wb") as handle:
        handle.truncate(26 * 1024 * 1024)
    _write_file(output_dir / "bad.json", "{invalid")
    _write_file(output_dir / "empty-findings.json", "[]\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare Northstar Bank environment-evidence fixtures.")
    parser.add_argument(
        "--output-dir",
        default=str(Path.home() / "test-fixtures"),
        help="Directory where the fixture set should be created.",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir).expanduser().resolve()
    repo_root = output_dir / "northstar-mobile-api"
    scoutsuite_dir = output_dir / "scoutsuite-output"

    _build_repo_tree(repo_root)
    _zip_tree(repo_root, output_dir / "northstar-mobile-api.zip")
    _write_manifest_bundle(repo_root, output_dir / "northstar-manifests-only.zip")
    _write_prowler_json(output_dir / "northstar-prowler-staging.json")
    scoutsuite_dir.mkdir(parents=True, exist_ok=True)
    _write_scoutsuite_js(scoutsuite_dir / "scoutsuite_results.js")
    _zip_tree(scoutsuite_dir, output_dir / "scoutsuite-output.zip")
    _write_simple_pdf(output_dir / "northstar-architecture.pdf", NORTHSTAR_ARCHITECTURE_TEXT)
    _write_edge_case_fixtures(output_dir)

    manifest = {
        "repo_archive": str(output_dir / "northstar-mobile-api.zip"),
        "manifest_bundle": str(output_dir / "northstar-manifests-only.zip"),
        "prowler_json": str(output_dir / "northstar-prowler-staging.json"),
        "scoutsuite_results_js": str(scoutsuite_dir / "scoutsuite_results.js"),
        "scoutsuite_zip": str(output_dir / "scoutsuite-output.zip"),
        "architecture_pdf": str(output_dir / "northstar-architecture.pdf"),
        "edge_cases": {
            "empty_file": str(output_dir / "empty.zip"),
            "oversized_repo_placeholder": str(output_dir / "oversized.zip"),
            "invalid_json": str(output_dir / "bad.json"),
            "empty_findings": str(output_dir / "empty-findings.json"),
        },
    }
    _write_file(output_dir / "environment-evidence-fixtures.json", json.dumps(manifest, indent=2))

    print(f"Environment-evidence fixtures ready in {output_dir}")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
