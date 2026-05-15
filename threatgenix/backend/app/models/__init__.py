from app.models.audit import ThreatAuditLog
from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_bundle import ApplicationReviewBundle
from app.models.application_review_context import ApplicationReviewContextEntry
from app.models.application_risk_acceptance import ApplicationRiskAcceptance
from app.models.compliance import ComplianceMapping
from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.document import Document
from app.models.email_verification import EmailVerification
from app.models.evidence import (
    EvidenceEntity,
    EvidenceFinding,
    EvidenceFindingLink,
    EvidenceItem,
    EvidenceObservation,
    EvidenceRelationship,
    EvidenceSource,
)
from app.models.github_integration import GitHubRepositoryLink, GitHubReviewDispatch
from app.models.organization import Organization
from app.models.orchestration import (
    OrchestrationEvent,
    OrchestrationJob,
    OrchestrationTask,
)
from app.models.password_reset import PasswordResetToken
from app.models.remediation_webhook import RemediationWebhookNonce
from app.models.scan import (
    ScanAuthorization,
    ScanExecutionArtifact,
    ScanCredential,
    ScanFinding,
    ScanJob,
    ScanTargetAuthorization,
    ScanThreatResult,
    ValidationCaseEvent,
    ValidationCaseState,
    ValidationSchedule,
    ValidationTargetBundle,
)
from app.models.threat import Threat
from app.models.threat_agent_orchestration import ThreatRemediationRun, ThreatValidationRun
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.models.user_provider_key import UserProviderKey

__all__ = [
    "ThreatModel",
    "Document",
    "DFDNode",
    "DFDEdge",
    "TrustBoundary",
    "Threat",
    "ThreatValidationRun",
    "ThreatRemediationRun",
    "ThreatAuditLog",
    "ApplicationSecurityReview",
    "ApplicationReviewBundle",
    "ApplicationReviewContextEntry",
    "ApplicationRiskAcceptance",
    "ComplianceMapping",
    "EmailVerification",
    "EvidenceEntity",
    "EvidenceFinding",
    "EvidenceFindingLink",
    "EvidenceItem",
    "EvidenceObservation",
    "EvidenceRelationship",
    "EvidenceSource",
    "GitHubRepositoryLink",
    "GitHubReviewDispatch",
    "Organization",
    "OrchestrationEvent",
    "OrchestrationJob",
    "OrchestrationTask",
    "PasswordResetToken",
    "RemediationWebhookNonce",
    "User",
    "UserProviderKey",
    "ScanAuthorization",
    "ScanExecutionArtifact",
    "ScanCredential",
    "ScanFinding",
    "ScanJob",
    "ScanTargetAuthorization",
    "ScanThreatResult",
    "ValidationCaseEvent",
    "ValidationCaseState",
    "ValidationSchedule",
    "ValidationTargetBundle",
]

# threat_intel models require pgvector PostgreSQL extension — import only if available
try:
    from app.models.threat_intel import (  # noqa: F401
        AttackPattern,
        AttackTechnique,
        CCSCAdvisory,
        CRIMapping,
        KEVEntry,
        ThreatIntelSync,
        WeaknessEntry,
    )

    __all__.extend(
        [
            "AttackTechnique",
            "AttackPattern",
            "WeaknessEntry",
            "CRIMapping",
            "KEVEntry",
            "CCSCAdvisory",
            "ThreatIntelSync",
        ]
    )
except ImportError:
    pass  # pgvector not installed — threat intel features unavailable
