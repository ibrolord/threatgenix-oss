"""Add canonical evidence graph projection tables.

Revision ID: 051
Revises: 050
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "051"
down_revision = "050"
branch_labels = None
depends_on = None

CONFIDENCE_LABELS = (
    "'validated','strongly_indicated','contextual','theoretical','unknown','suppressed'"
)
FRESHNESS_STATUSES = "'fresh','aging','stale','expired','unknown'"


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _jsonb_empty_object():
    return sa.text("'{}'::jsonb")


def upgrade() -> None:
    if not _has_table("evidence_sources"):
        op.create_table(
            "evidence_sources",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "owner_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("stable_key", sa.String(500), nullable=False),
            sa.Column("source_type", sa.String(40), nullable=False),
            sa.Column("source_name", sa.String(300), nullable=False),
            sa.Column("provider", sa.String(120), nullable=True),
            sa.Column("transport", sa.String(120), nullable=True),
            sa.Column("reference", sa.String(500), nullable=True),
            sa.Column("uri", sa.Text(), nullable=True),
            sa.Column("source_fingerprint_sha256", sa.String(64), nullable=True),
            sa.Column("ingestion_mode", sa.String(30), nullable=False, server_default="projection"),
            sa.Column("trust_level", sa.String(30), nullable=False, server_default="modeled"),
            sa.Column("status", sa.String(20), nullable=False, server_default="active"),
            sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("parser_version", sa.String(80), nullable=True),
            sa.Column(
                "metadata",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint(
                "source_type IN ('threat_model','dfd','document','repository','cloud_scan',"
                "'iac','scan','threat_register','coverage','review','manual')",
                name="ck_evidence_sources_type",
            ),
            sa.CheckConstraint(
                "ingestion_mode IN ('projection','upload','import','execution','manual','seed')",
                name="ck_evidence_sources_ingestion_mode",
            ),
            sa.CheckConstraint(
                "trust_level IN ('verified','indicated','modeled','inferred','untrusted')",
                name="ck_evidence_sources_trust_level",
            ),
            sa.CheckConstraint(
                "status IN ('active','stale','expired','deleted','error')",
                name="ck_evidence_sources_status",
            ),
            sa.UniqueConstraint(
                "threat_model_id",
                "stable_key",
                name="uq_evidence_sources_model_stable_key",
            ),
        )
        op.create_index("ix_evidence_sources_threat_model_type", "evidence_sources", ["threat_model_id", "source_type"])
        op.create_index("ix_evidence_sources_threat_model_status", "evidence_sources", ["threat_model_id", "status"])

    if not _has_table("evidence_items"):
        op.create_table(
            "evidence_items",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "source_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_sources.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("stable_key", sa.String(600), nullable=False),
            sa.Column("item_type", sa.String(80), nullable=False),
            sa.Column("title", sa.String(500), nullable=False),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("raw_ref", sa.String(600), nullable=True),
            sa.Column(
                "raw_payload",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column("content_sha256", sa.String(64), nullable=True),
            sa.Column("confidence_score", sa.Float(), nullable=False, server_default="50"),
            sa.Column("confidence_label", sa.String(30), nullable=False, server_default="contextual"),
            sa.Column("freshness_status", sa.String(20), nullable=False, server_default="unknown"),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint(
                f"confidence_label IN ({CONFIDENCE_LABELS})",
                name="ck_evidence_items_confidence_label",
            ),
            sa.CheckConstraint(
                f"freshness_status IN ({FRESHNESS_STATUSES})",
                name="ck_evidence_items_freshness_status",
            ),
            sa.CheckConstraint(
                "confidence_score >= 0 AND confidence_score <= 100",
                name="ck_evidence_items_confidence_score",
            ),
            sa.UniqueConstraint(
                "threat_model_id",
                "stable_key",
                name="uq_evidence_items_model_stable_key",
            ),
        )
        op.create_index("ix_evidence_items_source_id", "evidence_items", ["source_id"])
        op.create_index("ix_evidence_items_threat_model_type", "evidence_items", ["threat_model_id", "item_type"])
        op.create_index("ix_evidence_items_threat_model_freshness", "evidence_items", ["threat_model_id", "freshness_status"])

    if not _has_table("evidence_entities"):
        op.create_table(
            "evidence_entities",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("entity_type", sa.String(80), nullable=False),
            sa.Column("canonical_key", sa.String(700), nullable=False),
            sa.Column("display_name", sa.String(500), nullable=False),
            sa.Column("source_object_type", sa.String(100), nullable=True),
            sa.Column("source_object_id", sa.String(120), nullable=True),
            sa.Column(
                "properties",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("status", sa.String(20), nullable=False, server_default="active"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint("status IN ('active','tombstoned')", name="ck_evidence_entities_status"),
            sa.UniqueConstraint(
                "threat_model_id",
                "canonical_key",
                name="uq_evidence_entities_model_canonical_key",
            ),
        )
        op.create_index("ix_evidence_entities_threat_model_type", "evidence_entities", ["threat_model_id", "entity_type"])
        op.create_index("ix_evidence_entities_source_object", "evidence_entities", ["source_object_type", "source_object_id"])

    if not _has_table("evidence_observations"):
        op.create_table(
            "evidence_observations",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "evidence_item_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_items.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "subject_entity_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_entities.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("predicate", sa.String(120), nullable=False),
            sa.Column(
                "object_entity_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_entities.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("value_text", sa.Text(), nullable=True),
            sa.Column(
                "value_json",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column("severity", sa.String(20), nullable=True),
            sa.Column("confidence_score", sa.Float(), nullable=False, server_default="50"),
            sa.Column("confidence_label", sa.String(30), nullable=False, server_default="contextual"),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint(
                f"confidence_label IN ({CONFIDENCE_LABELS})",
                name="ck_evidence_observations_confidence_label",
            ),
            sa.CheckConstraint(
                "confidence_score >= 0 AND confidence_score <= 100",
                name="ck_evidence_observations_confidence_score",
            ),
        )
        op.create_index("ix_evidence_observations_item_id", "evidence_observations", ["evidence_item_id"])
        op.create_index("ix_evidence_observations_subject", "evidence_observations", ["subject_entity_id"])
        op.create_index("ix_evidence_observations_threat_model_predicate", "evidence_observations", ["threat_model_id", "predicate"])

    if not _has_table("evidence_relationships"):
        op.create_table(
            "evidence_relationships",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("stable_key", sa.String(800), nullable=False),
            sa.Column(
                "from_entity_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_entities.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "to_entity_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_entities.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("relationship_type", sa.String(100), nullable=False),
            sa.Column(
                "evidence_item_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_items.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("confidence_score", sa.Float(), nullable=False, server_default="50"),
            sa.Column("confidence_label", sa.String(30), nullable=False, server_default="contextual"),
            sa.Column("rationale", sa.Text(), nullable=True),
            sa.Column(
                "properties",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint(
                f"confidence_label IN ({CONFIDENCE_LABELS})",
                name="ck_evidence_relationships_confidence_label",
            ),
            sa.CheckConstraint(
                "confidence_score >= 0 AND confidence_score <= 100",
                name="ck_evidence_relationships_confidence_score",
            ),
            sa.UniqueConstraint(
                "threat_model_id",
                "stable_key",
                name="uq_evidence_relationships_model_stable_key",
            ),
        )
        op.create_index("ix_evidence_relationships_from", "evidence_relationships", ["from_entity_id"])
        op.create_index("ix_evidence_relationships_to", "evidence_relationships", ["to_entity_id"])
        op.create_index("ix_evidence_relationships_threat_model_type", "evidence_relationships", ["threat_model_id", "relationship_type"])

    if not _has_table("evidence_findings"):
        op.create_table(
            "evidence_findings",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("finding_key", sa.String(700), nullable=False),
            sa.Column("finding_kind", sa.String(80), nullable=False),
            sa.Column("title", sa.String(500), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("severity", sa.String(20), nullable=False, server_default="Unknown"),
            sa.Column("status", sa.String(30), nullable=False, server_default="open"),
            sa.Column(
                "source_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_sources.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "primary_evidence_item_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_items.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("confidence_score", sa.Float(), nullable=False, server_default="50"),
            sa.Column("confidence_label", sa.String(30), nullable=False, server_default="contextual"),
            sa.Column("freshness_status", sa.String(20), nullable=False, server_default="unknown"),
            sa.Column("source_system", sa.String(100), nullable=True),
            sa.Column("source_object_type", sa.String(100), nullable=True),
            sa.Column("source_object_id", sa.String(120), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "metadata",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint(
                "severity IN ('Critical','High','Medium','Low','Info','Unknown')",
                name="ck_evidence_findings_severity",
            ),
            sa.CheckConstraint(
                "status IN ('open','in_progress','mitigated','accepted','dismissed','refuted','informational')",
                name="ck_evidence_findings_status",
            ),
            sa.CheckConstraint(
                f"confidence_label IN ({CONFIDENCE_LABELS})",
                name="ck_evidence_findings_confidence_label",
            ),
            sa.CheckConstraint(
                f"freshness_status IN ({FRESHNESS_STATUSES})",
                name="ck_evidence_findings_freshness_status",
            ),
            sa.CheckConstraint(
                "confidence_score >= 0 AND confidence_score <= 100",
                name="ck_evidence_findings_confidence_score",
            ),
            sa.UniqueConstraint(
                "threat_model_id",
                "finding_key",
                name="uq_evidence_findings_model_finding_key",
            ),
        )
        op.create_index("ix_evidence_findings_source_id", "evidence_findings", ["source_id"])
        op.create_index("ix_evidence_findings_threat_model_kind", "evidence_findings", ["threat_model_id", "finding_kind"])
        op.create_index("ix_evidence_findings_threat_model_status", "evidence_findings", ["threat_model_id", "status"])
        op.create_index("ix_evidence_findings_source_object", "evidence_findings", ["source_object_type", "source_object_id"])

    if not _has_table("evidence_finding_links"):
        op.create_table(
            "evidence_finding_links",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "finding_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_findings.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "evidence_item_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_items.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "observation_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_observations.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "entity_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("evidence_entities.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("link_type", sa.String(40), nullable=False),
            sa.Column("confidence_score", sa.Float(), nullable=False, server_default="50"),
            sa.Column("confidence_label", sa.String(30), nullable=False, server_default="contextual"),
            sa.Column("rationale", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint(
                "link_type IN ('supports','refutes','affects','observed_on','derived_from',"
                "'needs_evidence')",
                name="ck_evidence_finding_links_type",
            ),
            sa.CheckConstraint(
                f"confidence_label IN ({CONFIDENCE_LABELS})",
                name="ck_evidence_finding_links_confidence_label",
            ),
            sa.CheckConstraint(
                "confidence_score >= 0 AND confidence_score <= 100",
                name="ck_evidence_finding_links_confidence_score",
            ),
        )
        op.create_index("ix_evidence_finding_links_finding_id", "evidence_finding_links", ["finding_id"])
        op.create_index("ix_evidence_finding_links_evidence_item_id", "evidence_finding_links", ["evidence_item_id"])
        op.create_index("ix_evidence_finding_links_entity_id", "evidence_finding_links", ["entity_id"])
        op.create_index("ix_evidence_finding_links_threat_model", "evidence_finding_links", ["threat_model_id"])


def downgrade() -> None:
    for index_name, table_name in (
        ("ix_evidence_finding_links_threat_model", "evidence_finding_links"),
        ("ix_evidence_finding_links_entity_id", "evidence_finding_links"),
        ("ix_evidence_finding_links_evidence_item_id", "evidence_finding_links"),
        ("ix_evidence_finding_links_finding_id", "evidence_finding_links"),
        ("ix_evidence_findings_source_object", "evidence_findings"),
        ("ix_evidence_findings_threat_model_status", "evidence_findings"),
        ("ix_evidence_findings_threat_model_kind", "evidence_findings"),
        ("ix_evidence_findings_source_id", "evidence_findings"),
        ("ix_evidence_relationships_threat_model_type", "evidence_relationships"),
        ("ix_evidence_relationships_to", "evidence_relationships"),
        ("ix_evidence_relationships_from", "evidence_relationships"),
        ("ix_evidence_observations_threat_model_predicate", "evidence_observations"),
        ("ix_evidence_observations_subject", "evidence_observations"),
        ("ix_evidence_observations_item_id", "evidence_observations"),
        ("ix_evidence_entities_source_object", "evidence_entities"),
        ("ix_evidence_entities_threat_model_type", "evidence_entities"),
        ("ix_evidence_items_threat_model_freshness", "evidence_items"),
        ("ix_evidence_items_threat_model_type", "evidence_items"),
        ("ix_evidence_items_source_id", "evidence_items"),
        ("ix_evidence_sources_threat_model_status", "evidence_sources"),
        ("ix_evidence_sources_threat_model_type", "evidence_sources"),
    ):
        if _has_table(table_name):
            op.drop_index(index_name, table_name=table_name)

    for table_name in (
        "evidence_finding_links",
        "evidence_findings",
        "evidence_relationships",
        "evidence_observations",
        "evidence_entities",
        "evidence_items",
        "evidence_sources",
    ):
        if _has_table(table_name):
            op.drop_table(table_name)
