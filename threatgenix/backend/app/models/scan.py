"""Scan models: scanner jobs, validation artifacts, and runner telemetry."""

import uuid
from datetime import date, datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.services.validation_artifact_contract import validation_metadata_from_raw

from app.database import Base


class ScanCredential(Base):
    """AES-256-GCM encrypted credential for authenticated scans.

    ``encrypted_secret`` stores base64(12-byte nonce || ciphertext || 16-byte GCM tag).
    The plaintext is never stored or logged. See services/credential_crypto.py.
    """

    __tablename__ = "scan_credentials"
    __table_args__ = (
        CheckConstraint(
            "credential_type IN ('bearer_token','api_key_header','basic_auth','cookie')",
            name="ck_scan_credentials_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # User-visible label — NOT the secret value
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    credential_type: Mapped[str] = mapped_column(String(30), nullable=False)
    # For api_key_header type: header name to inject (e.g. "X-API-Key")
    header_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    # AES-256-GCM envelope: base64(nonce || ciphertext+tag)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ScanJob(Base):
    """A vulnerability scan run against a threat model's targets."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','running','completed','failed','cancelled')",
            name="ck_scan_jobs_status",
        ),
        CheckConstraint(
            "scan_type IN ('unauthenticated','authenticated')",
            name="ck_scan_jobs_scan_type",
        ),
        CheckConstraint(
            "scope IN ('external','internal','full')",
            name="ck_scan_jobs_scope",
        ),
        CheckConstraint(
            "tool_name IN ('nuclei','semgrep','osv-scanner','trivy','checkov','trufflehog','ai-red-team','external-report','pentest-report')",
            name="ck_scan_jobs_tool_name",
        ),
        CheckConstraint(
            "target_type IN ('url','repository_path','lockfile','container_image','iac_directory','ai_system')",
            name="ck_scan_jobs_target_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # FK to ScanCredential — populated when scan_type="authenticated"
    credential_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    scan_type: Mapped[str] = mapped_column(
        String(20), default="unauthenticated", nullable=False
    )
    scope: Mapped[str] = mapped_column(String(20), default="external", nullable=False)
    tool_name: Mapped[str] = mapped_column(String(50), default="nuclei", nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), default="url", nullable=False)
    targets: Mapped[dict] = mapped_column(JSONB, default=dict)  # {node_id: url}
    nuclei_templates: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # template tags to run
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    failure_code: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    runner_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    claimed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    findings = relationship(
        "ScanFinding", back_populates="scan_job", cascade="all, delete-orphan"
    )
    threat_results = relationship(
        "ScanThreatResult", back_populates="scan_job", cascade="all, delete-orphan"
    )
    execution_artifacts = relationship(
        "ScanExecutionArtifact",
        back_populates="scan_job",
        cascade="all, delete-orphan",
    )
    artifact_bundle_items = relationship(
        "ValidationArtifactBundleItem",
        back_populates="scan_job",
        cascade="all, delete-orphan",
    )


class ScanFinding(Base):
    """Raw finding from Nuclei — one row per matched template."""

    __tablename__ = "scan_findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info','unknown')",
            name="ck_scan_findings_severity",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    template_id: Mapped[str] = mapped_column(String(200), nullable=False)
    template_name: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    matched_at: Mapped[str] = mapped_column(
        String(500), nullable=False
    )  # URL where finding triggered
    extracted_results: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cve_ids: Mapped[list] = mapped_column(JSONB, default=list)  # ["CVE-2024-1234"]
    tags: Mapped[list] = mapped_column(JSONB, default=list)  # ["sqli", "owasp", ...]
    cvss_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    raw_output: Mapped[dict] = mapped_column(JSONB, default=dict)  # full Nuclei JSON
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan_job = relationship("ScanJob", back_populates="findings")

    @property
    def validation_metadata(self) -> dict:
        return validation_metadata_from_raw(self.raw_output)

    @property
    def tool_name(self) -> Optional[str]:
        value = self.validation_metadata.get("tool_name")
        return str(value) if value else None

    @property
    def tool_version(self) -> Optional[str]:
        value = self.validation_metadata.get("tool_version")
        return str(value) if value else None

    @property
    def validation_target(self) -> Optional[str]:
        value = self.validation_metadata.get("target")
        return str(value) if value else None

    @property
    def deterministic(self) -> Optional[bool]:
        value = self.validation_metadata.get("deterministic")
        return value if isinstance(value, bool) else None

    @property
    def evidence_origin(self) -> Optional[str]:
        value = self.validation_metadata.get("evidence_origin")
        return str(value) if value else None

    @property
    def synthetic(self) -> Optional[bool]:
        value = self.validation_metadata.get("synthetic")
        return value if isinstance(value, bool) else None


class ScanExecutionArtifact(Base):
    """Durable metadata about one deterministic validation target run or ingest."""

    __tablename__ = "scan_execution_artifacts"
    __table_args__ = (
        CheckConstraint(
            "source IN ('execution','ingest')",
            name="ck_scan_execution_artifacts_source",
        ),
        CheckConstraint(
            "status IN ('completed','failed','timed_out','blocked')",
            name="ck_scan_execution_artifacts_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(String(20), default="execution", nullable=False)
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    resolved_target: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="completed", nullable=False)
    deterministic: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sandboxed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sandbox_mode: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    container_image: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resource_limits: Mapped[dict] = mapped_column(JSONB, default=dict)
    policy_decision: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    command: Mapped[list] = mapped_column(JSONB, default=list)
    command_redacted: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    returncode: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    timed_out: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    output_limit_exceeded: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    stdout_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    stderr_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    network_mode: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    max_runtime_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    max_output_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan_job = relationship("ScanJob", back_populates="execution_artifacts")
    validation_bundle_items = relationship(
        "ValidationArtifactBundleItem",
        back_populates="scan_execution_artifact",
    )


class ValidationArtifactBundle(Base):
    """Tenant-scoped uploaded validation evidence bundle metadata."""

    __tablename__ = "validation_artifact_bundles"
    __table_args__ = (
        CheckConstraint(
            "status IN ('imported','partial','failed')",
            name="ck_validation_artifact_bundles_status",
        ),
        CheckConstraint(
            "storage_backend IN ('metadata_only','object_store')",
            name="ck_validation_artifact_bundles_storage_backend",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="imported", nullable=False)
    manifest: Mapped[dict] = mapped_column(JSONB, default=dict)
    storage_backend: Mapped[str] = mapped_column(
        String(30), default="metadata_only", nullable=False
    )
    storage_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    item_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    items = relationship(
        "ValidationArtifactBundleItem",
        back_populates="bundle",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class ValidationArtifactBundleItem(Base):
    """One parsed artifact entry from an uploaded validation bundle."""

    __tablename__ = "validation_artifact_bundle_items"
    __table_args__ = (
        CheckConstraint(
            "status IN ('imported','failed')",
            name="ck_validation_artifact_bundle_items_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    bundle_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("validation_artifact_bundles.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_job_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    scan_execution_artifact_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_execution_artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    target_node_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dfd_nodes.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    raw_output_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_output_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="imported", nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    bundle = relationship("ValidationArtifactBundle", back_populates="items")
    scan_job = relationship("ScanJob", back_populates="artifact_bundle_items")
    scan_execution_artifact = relationship(
        "ScanExecutionArtifact",
        back_populates="validation_bundle_items",
    )


class ValidationTargetBundle(Base):
    """Tenant-scoped source/IaC bundle that a hosted worker can materialize."""

    __tablename__ = "validation_target_bundles"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ready','expired','deleted')",
            name="ck_validation_target_bundles_status",
        ),
        CheckConstraint(
            "storage_backend IN ('database','object_store')",
            name="ck_validation_target_bundles_storage_backend",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ready", nullable=False)
    storage_backend: Mapped[str] = mapped_column(
        String(30), default="database", nullable=False
    )
    storage_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    archive_bytes: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    manifest: Mapped[dict] = mapped_column(JSONB, default=dict)
    retention_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ValidationWorkerHeartbeat(Base):
    """Latest heartbeat for a managed validation worker process."""

    __tablename__ = "validation_worker_heartbeats"
    __table_args__ = (
        CheckConstraint(
            "status IN ('starting','idle','running','stopping','error')",
            name="ck_validation_worker_heartbeats_status",
        ),
    )

    runner_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    fly_machine_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), default="starting", nullable=False)
    current_scan_job_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    sandbox_mode: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    runtime_mode: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ValidationSchedule(Base):
    """Saved validation target that can be run manually or by a future scheduler."""

    __tablename__ = "validation_schedules"
    __table_args__ = (
        CheckConstraint(
            "tool_name IN ('nuclei','semgrep','osv-scanner','trivy','checkov','trufflehog','ai-red-team')",
            name="ck_validation_schedules_tool_name",
        ),
        CheckConstraint(
            "target_type IN ('url','repository_path','lockfile','container_image','iac_directory','ai_system')",
            name="ck_validation_schedules_target_type",
        ),
        CheckConstraint(
            "scope IN ('external','internal','full')",
            name="ck_validation_schedules_scope",
        ),
        CheckConstraint(
            "cadence IN ('manual','daily','weekly','monthly')",
            name="ck_validation_schedules_cadence",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    target_node_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dfd_nodes.id", ondelete="SET NULL"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(String(20), default="external", nullable=False)
    cadence: Mapped[str] = mapped_column(String(20), default="manual", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_required: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    authorization_acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    threat_model = relationship("ThreatModel", back_populates="validation_schedules")
    target_node = relationship("DFDNode")


class ValidationCaseState(Base):
    """Persistent analyst workflow state for a derived Product Security validation case."""

    __tablename__ = "validation_case_states"
    __table_args__ = (
        UniqueConstraint(
            "threat_model_id", "case_key", name="uq_validation_case_state_model_case"
        ),
        CheckConstraint(
            "case_type IN ('threat','unbound_finding')",
            name="ck_validation_case_states_case_type",
        ),
        CheckConstraint(
            "workflow_status IN ('open','investigating','mitigated','accepted','dismissed','refuted')",
            name="ck_validation_case_states_workflow_status",
        ),
        CheckConstraint(
            "workflow_priority IN ('P1','P2','P3') OR workflow_priority IS NULL",
            name="ck_validation_case_states_priority",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    case_key: Mapped[str] = mapped_column(String(120), nullable=False)
    case_type: Mapped[str] = mapped_column(String(40), nullable=False)
    workflow_status: Mapped[str] = mapped_column(
        String(30), default="open", nullable=False
    )
    workflow_priority: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)
    owner_label: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    due_date: Mapped[Optional[date]] = mapped_column(Date(), nullable=True)
    analyst_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_decision: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    threat_model = relationship("ThreatModel", back_populates="validation_case_states")
    events = relationship(
        "ValidationCaseEvent", back_populates="case_state", cascade="all, delete-orphan"
    )


class ValidationCaseEvent(Base):
    """Audit event for analyst changes to a validation case."""

    __tablename__ = "validation_case_events"
    __table_args__ = (
        CheckConstraint(
            "action IN ('created','updated')",
            name="ck_validation_case_events_action",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_state_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("validation_case_states.id", ondelete="CASCADE"),
        nullable=False,
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(30), nullable=False)
    changes: Mapped[dict] = mapped_column(JSONB, default=dict)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    case_state = relationship("ValidationCaseState", back_populates="events")


class ScanThreatResult(Base):
    """Maps a scan result to a specific threat in the threat model."""

    __tablename__ = "scan_threat_results"
    __table_args__ = (
        CheckConstraint(
            "scan_status IN ('confirmed','mitigated','unverifiable','not_found')",
            name="ck_scan_threat_results_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    threat_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threats.id", ondelete="CASCADE"), nullable=False
    )
    scan_status: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # confirmed|mitigated|unverifiable|not_found
    evidence: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # list of finding IDs + summaries
    cve_ids: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scan_job = relationship("ScanJob", back_populates="threat_results")
    threat = relationship("Threat", back_populates="scan_results")


class ScanAuthorization(Base):
    """Mandatory authorization record before any scan can run."""

    __tablename__ = "scan_authorizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    acknowledged_text: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # the exact text they agreed to
    acknowledged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    targets_snapshot: Mapped[dict] = mapped_column(
        JSONB, default=dict
    )  # snapshot of targets at time of auth

    scan_job = relationship("ScanJob", foreign_keys=[scan_job_id])


class ScanTargetAuthorization(Base):
    """Tenant-scoped proof that a live URL scan target is authorized."""

    __tablename__ = "scan_target_authorizations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('verified','expired','revoked')",
            name="ck_scan_target_authorizations_status",
        ),
        CheckConstraint(
            "proof_method IN ('dns_txt','http_file','manual_admin','synthetic_test')",
            name="ck_scan_target_authorizations_proof_method",
        ),
        Index(
            "ix_scan_target_authorizations_lookup",
            "owner_id",
            "threat_model_id",
            "normalized_host",
            "status",
        ),
        Index(
            "ix_scan_target_authorizations_expires",
            "expires_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_host: Mapped[str] = mapped_column(String(255), nullable=False)
    target_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    proof_method: Mapped[str] = mapped_column(String(40), nullable=False)
    proof_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="verified", nullable=False)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
