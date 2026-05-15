import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DFDNode(Base):
    __tablename__ = "dfd_nodes"
    __table_args__ = (
        CheckConstraint(
            "node_type IN ('process','data_store','external_entity','human_actor',"
            "'iam_role','managed_service','api_gateway','container','serverless')",
            name="ck_dfd_nodes_node_type",
        ),
        Index("ix_dfd_nodes_threat_model_id", "threat_model_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_model_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    position_x: Mapped[float] = mapped_column(Float, default=0)
    position_y: Mapped[float] = mapped_column(Float, default=0)
    trust_boundary_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("trust_boundaries.id", ondelete="SET NULL"))
    scan_target_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    scan_target_ports: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    properties: Mapped[dict] = mapped_column(JSONB, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    security_controls: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    threat_model = relationship("ThreatModel", back_populates="nodes")


class DFDEdge(Base):
    __tablename__ = "dfd_edges"
    __table_args__ = (
        Index("ix_dfd_edges_threat_model_id", "threat_model_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_model_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False)
    source_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("dfd_nodes.id", ondelete="CASCADE"), nullable=False)
    target_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("dfd_nodes.id", ondelete="CASCADE"), nullable=False)
    label: Mapped[str] = mapped_column(String(255), default="")
    properties: Mapped[dict] = mapped_column(JSONB, default=dict)
    tls_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    is_response: Mapped[bool] = mapped_column(Boolean, default=False)
    response_to_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("dfd_edges.id", ondelete="SET NULL"), nullable=True)
    data_objects: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    threat_model = relationship("ThreatModel", back_populates="edges")
    source_node = relationship("DFDNode", foreign_keys=[source_node_id])
    target_node = relationship("DFDNode", foreign_keys=[target_node_id])


class TrustBoundary(Base):
    __tablename__ = "trust_boundaries"
    __table_args__ = (
        Index("ix_trust_boundaries_threat_model_id", "threat_model_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_model_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), default="Trust Boundary")
    node_ids: Mapped[list] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    position_x: Mapped[float] = mapped_column(Float, default=0)
    position_y: Mapped[float] = mapped_column(Float, default=0)
    width: Mapped[float] = mapped_column(Float, default=280)
    height: Mapped[float] = mapped_column(Float, default=180)
    boundary_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    parent_boundary_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("trust_boundaries.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    threat_model = relationship("ThreatModel", back_populates="trust_boundaries")
