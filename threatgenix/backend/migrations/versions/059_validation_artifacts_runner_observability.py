"""Add validation artifact bundles and runner observability.

Revision ID: 059
Revises: 058
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "059"
down_revision = "058"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in _inspector().get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(
        column["name"] == column_name
        for column in _inspector().get_columns(table_name)
    )


def _has_index(table_name: str, index_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(index["name"] == index_name for index in _inspector().get_indexes(table_name))


def _add_scan_job_column(column: sa.Column) -> None:
    if not _has_column("scan_jobs", column.name):
        op.add_column("scan_jobs", column)


def upgrade() -> None:
    _add_scan_job_column(sa.Column("failure_code", sa.String(80), nullable=True))
    _add_scan_job_column(sa.Column("runner_id", sa.String(200), nullable=True))
    _add_scan_job_column(sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
    _add_scan_job_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    _add_scan_job_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    _add_scan_job_column(
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0")
    )
    _add_scan_job_column(
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3")
    )
    if not _has_index("scan_jobs", "ix_scan_jobs_status_created_at"):
        op.create_index(
            "ix_scan_jobs_status_created_at",
            "scan_jobs",
            ["status", "created_at"],
        )
    if not _has_index("scan_jobs", "ix_scan_jobs_runner_lease"):
        op.create_index(
            "ix_scan_jobs_runner_lease",
            "scan_jobs",
            ["runner_id", "lease_expires_at"],
        )

    if not _has_table("validation_artifact_bundles"):
        op.create_table(
            "validation_artifact_bundles",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("filename", sa.String(500), nullable=False),
            sa.Column("content_type", sa.String(200), nullable=True),
            sa.Column("byte_size", sa.Integer(), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="imported"),
            sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("storage_backend", sa.String(30), nullable=False, server_default="metadata_only"),
            sa.Column("storage_key", sa.Text(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("item_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.CheckConstraint(
                "status IN ('imported','partial','failed')",
                name="ck_validation_artifact_bundles_status",
            ),
            sa.CheckConstraint(
                "storage_backend IN ('metadata_only','object_store')",
                name="ck_validation_artifact_bundles_storage_backend",
            ),
            sa.ForeignKeyConstraint(["threat_model_id"], ["threat_models.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        )
    if not _has_index("validation_artifact_bundles", "ix_validation_artifact_bundles_model_created"):
        op.create_index(
            "ix_validation_artifact_bundles_model_created",
            "validation_artifact_bundles",
            ["threat_model_id", "created_at"],
        )
    if not _has_index("validation_artifact_bundles", "ix_validation_artifact_bundles_org_created"):
        op.create_index(
            "ix_validation_artifact_bundles_org_created",
            "validation_artifact_bundles",
            ["organization_id", "created_at"],
        )

    if not _has_table("validation_artifact_bundle_items"):
        op.create_table(
            "validation_artifact_bundle_items",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("bundle_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("scan_execution_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("tool_name", sa.String(50), nullable=False),
            sa.Column("target_type", sa.String(50), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("target_node_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("source_path", sa.Text(), nullable=False),
            sa.Column("raw_output_sha256", sa.String(64), nullable=False),
            sa.Column("raw_output_bytes", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="imported"),
            sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.CheckConstraint(
                "status IN ('imported','failed')",
                name="ck_validation_artifact_bundle_items_status",
            ),
            sa.ForeignKeyConstraint(["bundle_id"], ["validation_artifact_bundles.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["scan_execution_artifact_id"], ["scan_execution_artifacts.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["target_node_id"], ["dfd_nodes.id"], ondelete="SET NULL"),
        )
    if not _has_index("validation_artifact_bundle_items", "ix_validation_artifact_bundle_items_bundle_status"):
        op.create_index(
            "ix_validation_artifact_bundle_items_bundle_status",
            "validation_artifact_bundle_items",
            ["bundle_id", "status"],
        )
    if not _has_index("validation_artifact_bundle_items", "ix_validation_artifact_bundle_items_scan_job"):
        op.create_index(
            "ix_validation_artifact_bundle_items_scan_job",
            "validation_artifact_bundle_items",
            ["scan_job_id"],
        )

    if not _has_table("validation_worker_heartbeats"):
        op.create_table(
            "validation_worker_heartbeats",
            sa.Column("runner_id", sa.String(200), primary_key=True, nullable=False),
            sa.Column("hostname", sa.String(255), nullable=True),
            sa.Column("process_id", sa.Integer(), nullable=True),
            sa.Column("fly_machine_id", sa.String(120), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="starting"),
            sa.Column("current_scan_job_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("sandbox_mode", sa.String(30), nullable=True),
            sa.Column("runtime_mode", sa.String(30), nullable=True),
            sa.Column("version", sa.String(50), nullable=True),
            sa.Column("detail", sa.Text(), nullable=True),
            sa.CheckConstraint(
                "status IN ('starting','idle','running','stopping','error')",
                name="ck_validation_worker_heartbeats_status",
            ),
            sa.ForeignKeyConstraint(["current_scan_job_id"], ["scan_jobs.id"], ondelete="SET NULL"),
        )
    if not _has_index("validation_worker_heartbeats", "ix_validation_worker_heartbeats_last_seen"):
        op.create_index(
            "ix_validation_worker_heartbeats_last_seen",
            "validation_worker_heartbeats",
            ["last_seen_at"],
        )


def downgrade() -> None:
    if _has_table("validation_worker_heartbeats"):
        op.drop_table("validation_worker_heartbeats")
    if _has_table("validation_artifact_bundle_items"):
        op.drop_table("validation_artifact_bundle_items")
    if _has_table("validation_artifact_bundles"):
        op.drop_table("validation_artifact_bundles")
    for index_name in ("ix_scan_jobs_runner_lease", "ix_scan_jobs_status_created_at"):
        if _has_index("scan_jobs", index_name):
            op.drop_index(index_name, table_name="scan_jobs")
    for column_name in (
        "max_attempts",
        "attempt_count",
        "lease_expires_at",
        "heartbeat_at",
        "claimed_at",
        "runner_id",
        "failure_code",
    ):
        if _has_column("scan_jobs", column_name):
            op.drop_column("scan_jobs", column_name)
