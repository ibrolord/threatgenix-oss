"""Add threat qualification workflow: analyst scores, clustering, completion tracking.

Revision ID: 031
Revises: 030
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "031"
down_revision = "030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── New table: threat_clusters ───────────────────────────────────────────
    op.create_table(
        "threat_clusters",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "threat_model_id",
            UUID(as_uuid=True),
            sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cluster_label", sa.String(200), nullable=False),
        sa.Column("cluster_reason", sa.String(50), nullable=False),
        sa.Column(
            "representative_threat_id",
            UUID(as_uuid=True),
            sa.ForeignKey("threats.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("threat_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_threat_clusters_threat_model_id", "threat_clusters", ["threat_model_id"])

    # ── New columns on threats ───────────────────────────────────────────────
    # Analyst-supplied score (0-100), separate from auto_score
    op.add_column("threats", sa.Column("auto_score", sa.Integer(), nullable=True))
    op.add_column("threats", sa.Column("analyst_score", sa.Integer(), nullable=True))
    op.add_column("threats", sa.Column("analyst_score_rationale", sa.Text(), nullable=True))

    # Cached AI likelihood assessment (stored as JSON text)
    op.add_column("threats", sa.Column("ai_likelihood_assessment", sa.Text(), nullable=True))
    op.add_column("threats", sa.Column("ai_likelihood_score", sa.Integer(), nullable=True))
    op.add_column(
        "threats",
        sa.Column("ai_likelihood_generated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Cluster membership
    op.add_column(
        "threats",
        sa.Column(
            "cluster_id",
            UUID(as_uuid=True),
            sa.ForeignKey("threat_clusters.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_threats_cluster_id", "threats", ["cluster_id"])

    # Structured false-positive reason for dismissed threats
    op.add_column(
        "threats",
        sa.Column("false_positive_reason", sa.String(50), nullable=True),
    )
    op.create_check_constraint(
        "ck_threats_false_positive_reason",
        "threats",
        "false_positive_reason IS NULL OR false_positive_reason IN ("
        "'compensating_control', 'not_applicable', 'duplicate', "
        "'architecture_mismatch', 'accepted_risk', 'other')",
    )

    # When analyst finished qualifying this threat
    op.add_column(
        "threats",
        sa.Column("qualification_completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Check constraints for new score fields
    op.create_check_constraint(
        "ck_threats_auto_score_range",
        "threats",
        "auto_score IS NULL OR (auto_score >= 0 AND auto_score <= 100)",
    )
    op.create_check_constraint(
        "ck_threats_analyst_score_range",
        "threats",
        "analyst_score IS NULL OR (analyst_score >= 0 AND analyst_score <= 100)",
    )
    op.create_check_constraint(
        "ck_threats_ai_likelihood_score_range",
        "threats",
        "ai_likelihood_score IS NULL OR (ai_likelihood_score >= 0 AND ai_likelihood_score <= 100)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_threats_ai_likelihood_score_range", "threats")
    op.drop_constraint("ck_threats_analyst_score_range", "threats")
    op.drop_constraint("ck_threats_auto_score_range", "threats")
    op.drop_constraint("ck_threats_false_positive_reason", "threats")
    op.drop_index("ix_threats_cluster_id", "threats")
    op.drop_column("threats", "qualification_completed_at")
    op.drop_column("threats", "false_positive_reason")
    op.drop_column("threats", "cluster_id")
    op.drop_column("threats", "ai_likelihood_generated_at")
    op.drop_column("threats", "ai_likelihood_score")
    op.drop_column("threats", "ai_likelihood_assessment")
    op.drop_column("threats", "analyst_score_rationale")
    op.drop_column("threats", "analyst_score")
    op.drop_column("threats", "auto_score")
    op.drop_index("ix_threat_clusters_threat_model_id", "threat_clusters")
    op.drop_table("threat_clusters")
