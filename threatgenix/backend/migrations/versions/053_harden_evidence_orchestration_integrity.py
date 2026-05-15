"""Harden evidence graph and orchestration integrity.

Revision ID: 053
Revises: 052
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "053"
down_revision = "052"
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
        column["name"] == column_name for column in _inspector().get_columns(table_name)
    )


def _has_unique(table_name: str, name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(
        item.get("name") == name
        for item in _inspector().get_unique_constraints(table_name)
    )


def _has_fk(table_name: str, name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(
        item.get("name") == name for item in _inspector().get_foreign_keys(table_name)
    )


def _has_check(table_name: str, name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(
        item.get("name") == name
        for item in _inspector().get_check_constraints(table_name)
    )


def _has_index(table_name: str, name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(
        item.get("name") == name for item in _inspector().get_indexes(table_name)
    )


def _has_constraint(table_name: str, name: str) -> bool:
    return (
        _has_unique(table_name, name)
        or _has_fk(table_name, name)
        or _has_check(table_name, name)
    )


def _create_unique(table_name: str, name: str, columns: list[str]) -> None:
    if _has_table(table_name) and not _has_unique(table_name, name):
        op.create_unique_constraint(name, table_name, columns)


def _create_fk(
    table_name: str,
    name: str,
    columns: list[str],
    ref_table: str,
    ref_columns: list[str],
    *,
    ondelete: str | None = None,
) -> None:
    if (
        _has_table(table_name)
        and _has_table(ref_table)
        and not _has_fk(table_name, name)
    ):
        op.create_foreign_key(
            name,
            table_name,
            ref_table,
            columns,
            ref_columns,
            ondelete=ondelete,
        )


def upgrade() -> None:
    if _has_table("orchestration_jobs") and not _has_column(
        "orchestration_jobs", "idempotency_key"
    ):
        op.add_column(
            "orchestration_jobs",
            sa.Column("idempotency_key", sa.String(120), nullable=True),
        )

    _create_unique(
        "evidence_sources", "uq_evidence_sources_id_model", ["id", "threat_model_id"]
    )
    _create_unique(
        "evidence_items", "uq_evidence_items_id_model", ["id", "threat_model_id"]
    )
    _create_unique(
        "evidence_entities", "uq_evidence_entities_id_model", ["id", "threat_model_id"]
    )
    _create_unique(
        "evidence_observations",
        "uq_evidence_observations_id_model",
        ["id", "threat_model_id"],
    )
    _create_unique(
        "evidence_findings", "uq_evidence_findings_id_model", ["id", "threat_model_id"]
    )
    _create_unique(
        "orchestration_jobs",
        "uq_orchestration_jobs_id_model",
        ["id", "threat_model_id"],
    )
    _create_unique(
        "orchestration_tasks",
        "uq_orchestration_tasks_id_model",
        ["id", "threat_model_id"],
    )

    if _has_table("orchestration_jobs") and not _has_index(
        "orchestration_jobs", "ix_orchestration_jobs_idempotency"
    ):
        op.create_index(
            "ix_orchestration_jobs_idempotency",
            "orchestration_jobs",
            ["threat_model_id", "owner_id", "idempotency_key"],
            unique=True,
        )

    _create_fk(
        "evidence_items",
        "fk_evidence_items_source_model",
        ["source_id", "threat_model_id"],
        "evidence_sources",
        ["id", "threat_model_id"],
        ondelete="CASCADE",
    )
    _create_fk(
        "evidence_observations",
        "fk_evidence_observations_item_model",
        ["evidence_item_id", "threat_model_id"],
        "evidence_items",
        ["id", "threat_model_id"],
        ondelete="CASCADE",
    )
    _create_fk(
        "evidence_observations",
        "fk_evidence_observations_subject_model",
        ["subject_entity_id", "threat_model_id"],
        "evidence_entities",
        ["id", "threat_model_id"],
        ondelete="CASCADE",
    )
    _create_fk(
        "evidence_observations",
        "fk_evidence_observations_object_model",
        ["object_entity_id", "threat_model_id"],
        "evidence_entities",
        ["id", "threat_model_id"],
    )
    _create_fk(
        "evidence_relationships",
        "fk_evidence_relationships_from_model",
        ["from_entity_id", "threat_model_id"],
        "evidence_entities",
        ["id", "threat_model_id"],
        ondelete="CASCADE",
    )
    _create_fk(
        "evidence_relationships",
        "fk_evidence_relationships_to_model",
        ["to_entity_id", "threat_model_id"],
        "evidence_entities",
        ["id", "threat_model_id"],
        ondelete="CASCADE",
    )
    _create_fk(
        "evidence_relationships",
        "fk_evidence_relationships_item_model",
        ["evidence_item_id", "threat_model_id"],
        "evidence_items",
        ["id", "threat_model_id"],
    )
    _create_fk(
        "evidence_findings",
        "fk_evidence_findings_source_model",
        ["source_id", "threat_model_id"],
        "evidence_sources",
        ["id", "threat_model_id"],
    )
    _create_fk(
        "evidence_findings",
        "fk_evidence_findings_primary_item_model",
        ["primary_evidence_item_id", "threat_model_id"],
        "evidence_items",
        ["id", "threat_model_id"],
    )
    _create_fk(
        "evidence_finding_links",
        "fk_evidence_finding_links_finding_model",
        ["finding_id", "threat_model_id"],
        "evidence_findings",
        ["id", "threat_model_id"],
        ondelete="CASCADE",
    )
    _create_fk(
        "evidence_finding_links",
        "fk_evidence_finding_links_item_model",
        ["evidence_item_id", "threat_model_id"],
        "evidence_items",
        ["id", "threat_model_id"],
    )
    _create_fk(
        "evidence_finding_links",
        "fk_evidence_finding_links_observation_model",
        ["observation_id", "threat_model_id"],
        "evidence_observations",
        ["id", "threat_model_id"],
    )
    _create_fk(
        "evidence_finding_links",
        "fk_evidence_finding_links_entity_model",
        ["entity_id", "threat_model_id"],
        "evidence_entities",
        ["id", "threat_model_id"],
    )

    _create_fk(
        "orchestration_tasks",
        "fk_orchestration_tasks_job_model",
        ["job_id", "threat_model_id"],
        "orchestration_jobs",
        ["id", "threat_model_id"],
        ondelete="CASCADE",
    )
    _create_fk(
        "orchestration_events",
        "fk_orchestration_events_job_model",
        ["job_id", "threat_model_id"],
        "orchestration_jobs",
        ["id", "threat_model_id"],
        ondelete="CASCADE",
    )
    _create_fk(
        "orchestration_events",
        "fk_orchestration_events_task_model",
        ["task_id", "threat_model_id"],
        "orchestration_tasks",
        ["id", "threat_model_id"],
    )

    if _has_table("orchestration_tasks") and not _has_check(
        "orchestration_tasks",
        "ck_orchestration_tasks_attempt_bounds",
    ):
        op.create_check_constraint(
            "ck_orchestration_tasks_attempt_bounds",
            "orchestration_tasks",
            "attempt_count >= 0 AND max_attempts >= 1 AND attempt_count <= max_attempts",
        )


def downgrade() -> None:
    for table_name, constraint_name in (
        ("orchestration_tasks", "ck_orchestration_tasks_attempt_bounds"),
        ("orchestration_events", "fk_orchestration_events_task_model"),
        ("orchestration_events", "fk_orchestration_events_job_model"),
        ("orchestration_tasks", "fk_orchestration_tasks_job_model"),
        ("evidence_finding_links", "fk_evidence_finding_links_entity_model"),
        ("evidence_finding_links", "fk_evidence_finding_links_observation_model"),
        ("evidence_finding_links", "fk_evidence_finding_links_item_model"),
        ("evidence_finding_links", "fk_evidence_finding_links_finding_model"),
        ("evidence_findings", "fk_evidence_findings_primary_item_model"),
        ("evidence_findings", "fk_evidence_findings_source_model"),
        ("evidence_relationships", "fk_evidence_relationships_item_model"),
        ("evidence_relationships", "fk_evidence_relationships_to_model"),
        ("evidence_relationships", "fk_evidence_relationships_from_model"),
        ("evidence_observations", "fk_evidence_observations_object_model"),
        ("evidence_observations", "fk_evidence_observations_subject_model"),
        ("evidence_observations", "fk_evidence_observations_item_model"),
        ("evidence_items", "fk_evidence_items_source_model"),
        ("orchestration_tasks", "uq_orchestration_tasks_id_model"),
        ("orchestration_jobs", "uq_orchestration_jobs_id_model"),
        ("evidence_findings", "uq_evidence_findings_id_model"),
        ("evidence_observations", "uq_evidence_observations_id_model"),
        ("evidence_entities", "uq_evidence_entities_id_model"),
        ("evidence_items", "uq_evidence_items_id_model"),
        ("evidence_sources", "uq_evidence_sources_id_model"),
    ):
        if _has_constraint(table_name, constraint_name):
            op.drop_constraint(constraint_name, table_name)
    if _has_index("orchestration_jobs", "ix_orchestration_jobs_idempotency"):
        op.drop_index(
            "ix_orchestration_jobs_idempotency", table_name="orchestration_jobs"
        )
    if _has_column("orchestration_jobs", "idempotency_key"):
        op.drop_column("orchestration_jobs", "idempotency_key")
