"""Seed compliance mappings and initialize database tables."""

import asyncio
import logging

from sqlalchemy import select, text

from app.database import async_session, engine, Base
from app.models import ComplianceMapping  # noqa: F401 — importing from __init__ registers all models on Base

logger = logging.getLogger(__name__)

VECTOR_THREAT_INTEL_TABLES = {
    "attack_techniques",
    "attack_patterns",
    "weakness_entries",
    "cccs_advisories",
}

BOOTSTRAP_SCHEMA_REPAIRS = (
    ("threat_models", "dfd_component_templates", "JSONB"),
    ("threat_models", "dfd_property_options", "JSONB"),
    ("threat_models", "last_analyze_requested_at", "TIMESTAMP WITH TIME ZONE"),
    ("threat_models", "organization_id", "UUID"),
    ("threat_models", "report_templates", "JSONB"),
    ("threat_models", "review_state", "JSONB"),
    ("threats", "qualification_score", "INTEGER"),
    ("threats", "qualification_note", "TEXT"),
    ("threats", "citations", "JSONB NOT NULL DEFAULT '[]'::jsonb"),
    ("scan_execution_artifacts", "sandbox_mode", "VARCHAR(30)"),
    ("scan_execution_artifacts", "container_image", "TEXT"),
    ("scan_execution_artifacts", "resource_limits", "JSONB NOT NULL DEFAULT '{}'::jsonb"),
    ("users", "report_template_library", "JSONB"),
    ("users", "organization_id", "UUID"),
)
THREAT_MODEL_JSONB_REPAIRS = tuple(
    (column_name, column_type)
    for table_name, column_name, column_type in BOOTSTRAP_SCHEMA_REPAIRS
    if table_name == "threat_models" and column_type == "JSONB"
)

SEED_DATA = [
    # Format: (stride_category, threat_subtype, framework, control_id, control_name)
    #
    # ════════════════════════════════════════════════════════════════════════════
    # NIST 800-53 — 82 mappings
    # ════════════════════════════════════════════════════════════════════════════
    # Spoofing
    ("Spoofing", "Identity spoofing across trust boundary", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Spoofing", "Identity spoofing across trust boundary", "NIST 800-53", "IA-8", "Identification and Authentication (Non-Organizational Users)"),
    ("Spoofing", "Spoofed data flow across boundary", "NIST 800-53", "IA-3", "Device Identification and Authentication"),
    ("Spoofing", "Spoofed data flow across boundary", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Spoofing", "External entity identity spoofing", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Spoofing", "External entity identity spoofing", "NIST 800-53", "IA-5", "Authenticator Management"),
    ("Spoofing", "Unauthenticated process receives cross-boundary flow", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Spoofing", "Unauthenticated process receives cross-boundary flow", "NIST 800-53", "AC-3", "Access Enforcement"),
    ("Spoofing", "Unauthenticated external entity writes to data store", "NIST 800-53", "IA-8", "Identification and Authentication (Non-Organizational Users)"),
    ("Spoofing", "Unauthenticated external entity writes to data store", "NIST 800-53", "IA-5", "Authenticator Management"),
    ("Spoofing", "Internet-facing process without authentication", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Spoofing", "Internet-facing process without authentication", "NIST 800-53", "AC-14", "Permitted Actions Without Identification or Authentication"),
    # Tampering
    ("Tampering", "Data tampering in transit across boundary", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Tampering", "Data tampering in transit across boundary", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Tampering", "Cross-boundary data store tampering", "NIST 800-53", "AC-3", "Access Enforcement"),
    ("Tampering", "Cross-boundary data store tampering", "NIST 800-53", "AC-4", "Information Flow Enforcement"),
    ("Tampering", "Unauthorized data store modification by external entity", "NIST 800-53", "SI-10", "Information Input Validation"),
    ("Tampering", "Unauthorized data store modification by external entity", "NIST 800-53", "SI-15", "Information Output Filtering"),
    ("Tampering", "Data store write integrity risk", "NIST 800-53", "SI-7", "Software, Firmware, and Information Integrity"),
    ("Tampering", "Data store write integrity risk", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Tampering", "Missing input validation on external input", "NIST 800-53", "SI-10", "Information Input Validation"),
    ("Tampering", "Missing input validation on external input", "NIST 800-53", "SI-15", "Information Output Filtering"),
    ("Tampering", "Unencrypted data store", "NIST 800-53", "SC-28", "Protection of Information at Rest"),
    ("Tampering", "Unencrypted data store", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Tampering", "Internet-facing process without encryption", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Tampering", "Internet-facing process without encryption", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Tampering", "Untrusted external entity input", "NIST 800-53", "SI-10", "Information Input Validation"),
    ("Tampering", "Untrusted external entity input", "NIST 800-53", "RA-3", "Risk Assessment"),
    # Repudiation
    ("Repudiation", "Unlogged process actions", "NIST 800-53", "AU-2", "Event Logging"),
    ("Repudiation", "Unlogged process actions", "NIST 800-53", "AU-3", "Content of Audit Records"),
    ("Repudiation", "Unaudited data store modification", "NIST 800-53", "AU-2", "Event Logging"),
    ("Repudiation", "Unaudited data store modification", "NIST 800-53", "AU-12", "Audit Record Generation"),
    ("Repudiation", "Unaudited external entity interaction", "NIST 800-53", "AU-3", "Content of Audit Records"),
    ("Repudiation", "Unaudited external entity interaction", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Repudiation", "Sensitive data process audit gap", "NIST 800-53", "AU-2", "Event Logging"),
    ("Repudiation", "Sensitive data process audit gap", "NIST 800-53", "AU-12", "Audit Record Generation"),
    ("Repudiation", "Credential store without backup", "NIST 800-53", "CP-9", "System Backup"),
    ("Repudiation", "Credential store without backup", "NIST 800-53", "AU-9", "Protection of Audit Information"),
    ("Repudiation", "Internet-facing process audit risk", "NIST 800-53", "AU-2", "Event Logging"),
    ("Repudiation", "Internet-facing process audit risk", "NIST 800-53", "AU-3", "Content of Audit Records"),
    # Information Disclosure
    ("Information Disclosure", "Data exposure in transit across boundary", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Information Disclosure", "Data exposure in transit across boundary", "NIST 800-53", "SC-28", "Protection of Information at Rest"),
    ("Information Disclosure", "Sensitive data leaked to external entity", "NIST 800-53", "SC-28", "Protection of Information at Rest"),
    ("Information Disclosure", "Sensitive data leaked to external entity", "NIST 800-53", "IA-5", "Authenticator Management"),
    ("Information Disclosure", "Sensitive data in flow label", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Information Disclosure", "Sensitive data in flow label", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Information Disclosure", "Data store exposure across boundary", "NIST 800-53", "AC-4", "Information Flow Enforcement"),
    ("Information Disclosure", "Data store exposure across boundary", "NIST 800-53", "SC-7", "Boundary Protection"),
    ("Information Disclosure", "Unencrypted credential storage", "NIST 800-53", "SC-28", "Protection of Information at Rest"),
    ("Information Disclosure", "Unencrypted credential storage", "NIST 800-53", "IA-5", "Authenticator Management"),
    ("Information Disclosure", "Sensitive data processed without encryption", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Information Disclosure", "Sensitive data processed without encryption", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Information Disclosure", "Internet-facing data store", "NIST 800-53", "SC-7", "Boundary Protection"),
    ("Information Disclosure", "Internet-facing data store", "NIST 800-53", "AC-17", "Remote Access"),
    ("Information Disclosure", "Data leakage to untrusted external entity", "NIST 800-53", "AC-4", "Information Flow Enforcement"),
    ("Information Disclosure", "Data leakage to untrusted external entity", "NIST 800-53", "SC-7", "Boundary Protection"),
    # Denial of Service
    ("Denial of Service", "External entity flood attack on process", "NIST 800-53", "SC-5", "Denial-of-Service Protection"),
    ("Denial of Service", "External entity flood attack on process", "NIST 800-53", "SI-10", "Information Input Validation"),
    ("Denial of Service", "Process resource exhaustion", "NIST 800-53", "SC-5", "Denial-of-Service Protection"),
    ("Denial of Service", "Process resource exhaustion", "NIST 800-53", "CP-9", "System Backup"),
    ("Denial of Service", "Single point of failure", "NIST 800-53", "CP-9", "System Backup"),
    ("Denial of Service", "Single point of failure", "NIST 800-53", "CP-10", "System Recovery and Reconstitution"),
    ("Denial of Service", "Internet-facing process without input validation", "NIST 800-53", "SI-10", "Information Input Validation"),
    ("Denial of Service", "Internet-facing process without input validation", "NIST 800-53", "SC-5", "Denial-of-Service Protection"),
    ("Denial of Service", "Internet-exposed flood vector", "NIST 800-53", "SC-5", "Denial-of-Service Protection"),
    ("Denial of Service", "Internet-exposed flood vector", "NIST 800-53", "SC-7", "Boundary Protection"),
    ("Denial of Service", "Data store without backup", "NIST 800-53", "CP-9", "System Backup"),
    ("Denial of Service", "Data store without backup", "NIST 800-53", "CP-10", "System Recovery and Reconstitution"),
    # Elevation of Privilege
    ("Elevation of Privilege", "Privilege escalation via external access across boundary", "NIST 800-53", "AC-6", "Least Privilege"),
    ("Elevation of Privilege", "Privilege escalation via external access across boundary", "NIST 800-53", "AC-3", "Access Enforcement"),
    ("Elevation of Privilege", "Unauthorized privilege escalation across boundary", "NIST 800-53", "AC-3", "Access Enforcement"),
    ("Elevation of Privilege", "Unauthorized privilege escalation across boundary", "NIST 800-53", "AC-4", "Information Flow Enforcement"),
    ("Elevation of Privilege", "Multiple entry points to trust boundary", "NIST 800-53", "AC-4", "Information Flow Enforcement"),
    ("Elevation of Privilege", "Multiple entry points to trust boundary", "NIST 800-53", "SC-7", "Boundary Protection"),
    ("Elevation of Privilege", "Internet-facing process privilege escalation", "NIST 800-53", "AC-6", "Least Privilege"),
    ("Elevation of Privilege", "Internet-facing process privilege escalation", "NIST 800-53", "AC-3", "Access Enforcement"),
    ("Elevation of Privilege", "Unauthenticated cross-boundary data store access", "NIST 800-53", "AC-3", "Access Enforcement"),
    ("Elevation of Privilege", "Unauthenticated cross-boundary data store access", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Elevation of Privilege", "Missing input validation on cross-boundary process", "NIST 800-53", "SI-10", "Information Input Validation"),
    ("Elevation of Privilege", "Missing input validation on cross-boundary process", "NIST 800-53", "AC-6", "Least Privilege"),
    ("Elevation of Privilege", "Untrusted unauthenticated data store access", "NIST 800-53", "IA-8", "Identification and Authentication (Non-Organizational Users)"),
    ("Elevation of Privilege", "Untrusted unauthenticated data store access", "NIST 800-53", "AC-3", "Access Enforcement"),
    #
    # ════════════════════════════════════════════════════════════════════════════
    # OSFI B-13 — 82 mappings
    # ════════════════════════════════════════════════════════════════════════════
    # Spoofing
    ("Spoofing", "Identity spoofing across trust boundary", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Spoofing", "Identity spoofing across trust boundary", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Spoofing", "Spoofed data flow across boundary", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Spoofing", "Spoofed data flow across boundary", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Spoofing", "External entity identity spoofing", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Spoofing", "External entity identity spoofing", "OSFI B-13", "B13-6.1", "Third Party Risk"),
    ("Spoofing", "Unauthenticated process receives cross-boundary flow", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Spoofing", "Unauthenticated process receives cross-boundary flow", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Spoofing", "Unauthenticated external entity writes to data store", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Spoofing", "Unauthenticated external entity writes to data store", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Spoofing", "Internet-facing process without authentication", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Spoofing", "Internet-facing process without authentication", "OSFI B-13", "B13-4.1", "Cyber Risk Management"),
    # Tampering
    ("Tampering", "Data tampering in transit across boundary", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Data tampering in transit across boundary", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Tampering", "Unauthorized data store modification by external entity", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Tampering", "Unauthorized data store modification by external entity", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Data store write integrity risk", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Data store write integrity risk", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Tampering", "Cross-boundary data store tampering", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Tampering", "Cross-boundary data store tampering", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Missing input validation on external input", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Tampering", "Missing input validation on external input", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Unencrypted data store", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Unencrypted data store", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Tampering", "Internet-facing process without encryption", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Internet-facing process without encryption", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Tampering", "Untrusted external entity input", "OSFI B-13", "B13-6.1", "Third Party Risk"),
    ("Tampering", "Untrusted external entity input", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    # Repudiation
    ("Repudiation", "Unlogged process actions", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Repudiation", "Unlogged process actions", "OSFI B-13", "B13-3.1", "Governance"),
    ("Repudiation", "Unaudited data store modification", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Repudiation", "Unaudited data store modification", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Repudiation", "Unaudited external entity interaction", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Repudiation", "Unaudited external entity interaction", "OSFI B-13", "B13-6.1", "Third Party Risk"),
    ("Repudiation", "Sensitive data process audit gap", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Repudiation", "Sensitive data process audit gap", "OSFI B-13", "B13-3.1", "Governance"),
    ("Repudiation", "Credential store without backup", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Repudiation", "Credential store without backup", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Repudiation", "Internet-facing process audit risk", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Repudiation", "Internet-facing process audit risk", "OSFI B-13", "B13-4.1", "Cyber Risk Management"),
    # Information Disclosure
    ("Information Disclosure", "Data exposure in transit across boundary", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Data exposure in transit across boundary", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Information Disclosure", "Sensitive data leaked to external entity", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Sensitive data leaked to external entity", "OSFI B-13", "B13-6.1", "Third Party Risk"),
    ("Information Disclosure", "Sensitive data in flow label", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Sensitive data in flow label", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Information Disclosure", "Data store exposure across boundary", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Data store exposure across boundary", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Information Disclosure", "Unencrypted credential storage", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Unencrypted credential storage", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Information Disclosure", "Sensitive data processed without encryption", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Sensitive data processed without encryption", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Information Disclosure", "Internet-facing data store", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Internet-facing data store", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Information Disclosure", "Data leakage to untrusted external entity", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Data leakage to untrusted external entity", "OSFI B-13", "B13-6.1", "Third Party Risk"),
    # Denial of Service
    ("Denial of Service", "External entity flood attack on process", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Denial of Service", "External entity flood attack on process", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Denial of Service", "Process resource exhaustion", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Denial of Service", "Process resource exhaustion", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Denial of Service", "Single point of failure", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Denial of Service", "Single point of failure", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Denial of Service", "Internet-facing process without input validation", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Denial of Service", "Internet-facing process without input validation", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Denial of Service", "Internet-exposed flood vector", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Denial of Service", "Internet-exposed flood vector", "OSFI B-13", "B13-4.1", "Cyber Risk Management"),
    ("Denial of Service", "Data store without backup", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Denial of Service", "Data store without backup", "OSFI B-13", "B13-3.2", "Risk Management"),
    # Elevation of Privilege
    ("Elevation of Privilege", "Privilege escalation via external access across boundary", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Privilege escalation via external access across boundary", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Elevation of Privilege", "Unauthorized privilege escalation across boundary", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Unauthorized privilege escalation across boundary", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Elevation of Privilege", "Multiple entry points to trust boundary", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Multiple entry points to trust boundary", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Elevation of Privilege", "Internet-facing process privilege escalation", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Internet-facing process privilege escalation", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Elevation of Privilege", "Unauthenticated cross-boundary data store access", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Unauthenticated cross-boundary data store access", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Elevation of Privilege", "Missing input validation on cross-boundary process", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Elevation of Privilege", "Missing input validation on cross-boundary process", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Untrusted unauthenticated data store access", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Untrusted unauthenticated data store access", "OSFI B-13", "B13-6.1", "Third Party Risk"),
    #
    # ════════════════════════════════════════════════════════════════════════════
    # PCI DSS 4.0 — 82 mappings
    # ════════════════════════════════════════════════════════════════════════════
    # Spoofing
    ("Spoofing", "Identity spoofing across trust boundary", "PCI DSS 4.0", "Req-8.3", "Multi-Factor Authentication for Access"),
    ("Spoofing", "Identity spoofing across trust boundary", "PCI DSS 4.0", "Req-1.2", "Network Security Controls Configuration"),
    ("Spoofing", "Spoofed data flow across boundary", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Spoofing", "Spoofed data flow across boundary", "PCI DSS 4.0", "Req-1.3", "Network Access Restrictions"),
    ("Spoofing", "External entity identity spoofing", "PCI DSS 4.0", "Req-8.2", "User Identification and Authentication Management"),
    ("Spoofing", "External entity identity spoofing", "PCI DSS 4.0", "Req-12.3", "Risk Assessment Process"),
    ("Spoofing", "Unauthenticated process receives cross-boundary flow", "PCI DSS 4.0", "Req-8.3", "Multi-Factor Authentication for Access"),
    ("Spoofing", "Unauthenticated process receives cross-boundary flow", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Spoofing", "Unauthenticated external entity writes to data store", "PCI DSS 4.0", "Req-8.2", "User Identification and Authentication Management"),
    ("Spoofing", "Unauthenticated external entity writes to data store", "PCI DSS 4.0", "Req-7.3", "Access Control Based on Need to Know"),
    ("Spoofing", "Internet-facing process without authentication", "PCI DSS 4.0", "Req-8.3", "Multi-Factor Authentication for Access"),
    ("Spoofing", "Internet-facing process without authentication", "PCI DSS 4.0", "Req-6.4", "Public-Facing Web Application Protection"),
    # Tampering
    ("Tampering", "Data tampering in transit across boundary", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Tampering", "Data tampering in transit across boundary", "PCI DSS 4.0", "Req-1.3", "Network Access Restrictions"),
    ("Tampering", "Unauthorized data store modification by external entity", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Tampering", "Unauthorized data store modification by external entity", "PCI DSS 4.0", "Req-6.5", "Secure Coding Practices"),
    ("Tampering", "Data store write integrity risk", "PCI DSS 4.0", "Req-10.2", "Audit Log Implementation"),
    ("Tampering", "Data store write integrity risk", "PCI DSS 4.0", "Req-3.5", "Protect Stored Account Data Cryptographic Keys"),
    ("Tampering", "Cross-boundary data store tampering", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Tampering", "Cross-boundary data store tampering", "PCI DSS 4.0", "Req-1.3", "Network Access Restrictions"),
    ("Tampering", "Missing input validation on external input", "PCI DSS 4.0", "Req-6.5", "Secure Coding Practices"),
    ("Tampering", "Missing input validation on external input", "PCI DSS 4.0", "Req-6.4", "Public-Facing Web Application Protection"),
    ("Tampering", "Unencrypted data store", "PCI DSS 4.0", "Req-3.5", "Protect Stored Account Data Cryptographic Keys"),
    ("Tampering", "Unencrypted data store", "PCI DSS 4.0", "Req-3.1", "Stored Account Data Protection Processes"),
    ("Tampering", "Internet-facing process without encryption", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Tampering", "Internet-facing process without encryption", "PCI DSS 4.0", "Req-2.2", "System Components are Configured and Managed Securely"),
    ("Tampering", "Untrusted external entity input", "PCI DSS 4.0", "Req-6.5", "Secure Coding Practices"),
    ("Tampering", "Untrusted external entity input", "PCI DSS 4.0", "Req-12.3", "Risk Assessment Process"),
    # Repudiation
    ("Repudiation", "Unlogged process actions", "PCI DSS 4.0", "Req-10.2", "Audit Log Implementation"),
    ("Repudiation", "Unlogged process actions", "PCI DSS 4.0", "Req-10.3", "Audit Log Protection"),
    ("Repudiation", "Unaudited data store modification", "PCI DSS 4.0", "Req-10.2", "Audit Log Implementation"),
    ("Repudiation", "Unaudited data store modification", "PCI DSS 4.0", "Req-10.4", "Audit Log Review"),
    ("Repudiation", "Unaudited external entity interaction", "PCI DSS 4.0", "Req-10.2", "Audit Log Implementation"),
    ("Repudiation", "Unaudited external entity interaction", "PCI DSS 4.0", "Req-8.2", "User Identification and Authentication Management"),
    ("Repudiation", "Sensitive data process audit gap", "PCI DSS 4.0", "Req-10.2", "Audit Log Implementation"),
    ("Repudiation", "Sensitive data process audit gap", "PCI DSS 4.0", "Req-10.7", "Failures of Critical Security Controls are Detected and Reported Promptly"),
    ("Repudiation", "Credential store without backup", "PCI DSS 4.0", "Req-10.3", "Audit Log Protection"),
    ("Repudiation", "Credential store without backup", "PCI DSS 4.0", "Req-12.10", "Incident Response Plan"),
    ("Repudiation", "Internet-facing process audit risk", "PCI DSS 4.0", "Req-10.2", "Audit Log Implementation"),
    ("Repudiation", "Internet-facing process audit risk", "PCI DSS 4.0", "Req-10.4", "Audit Log Review"),
    # Information Disclosure
    ("Information Disclosure", "Data exposure in transit across boundary", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Information Disclosure", "Data exposure in transit across boundary", "PCI DSS 4.0", "Req-4.1", "Strong Cryptography Processes for Data in Transit"),
    ("Information Disclosure", "Sensitive data leaked to external entity", "PCI DSS 4.0", "Req-3.3", "Sensitive Authentication Data Not Stored After Authorization"),
    ("Information Disclosure", "Sensitive data leaked to external entity", "PCI DSS 4.0", "Req-3.4", "Restrict Display of PAN"),
    ("Information Disclosure", "Sensitive data in flow label", "PCI DSS 4.0", "Req-3.4", "Restrict Display of PAN"),
    ("Information Disclosure", "Sensitive data in flow label", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Information Disclosure", "Data store exposure across boundary", "PCI DSS 4.0", "Req-1.3", "Network Access Restrictions"),
    ("Information Disclosure", "Data store exposure across boundary", "PCI DSS 4.0", "Req-3.1", "Stored Account Data Protection Processes"),
    ("Information Disclosure", "Unencrypted credential storage", "PCI DSS 4.0", "Req-8.5", "Secure Authentication Credentials"),
    ("Information Disclosure", "Unencrypted credential storage", "PCI DSS 4.0", "Req-3.5", "Protect Stored Account Data Cryptographic Keys"),
    ("Information Disclosure", "Sensitive data processed without encryption", "PCI DSS 4.0", "Req-3.5", "Protect Stored Account Data Cryptographic Keys"),
    ("Information Disclosure", "Sensitive data processed without encryption", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Information Disclosure", "Internet-facing data store", "PCI DSS 4.0", "Req-1.3", "Network Access Restrictions"),
    ("Information Disclosure", "Internet-facing data store", "PCI DSS 4.0", "Req-11.3", "External and Internal Vulnerability Scans"),
    ("Information Disclosure", "Data leakage to untrusted external entity", "PCI DSS 4.0", "Req-7.3", "Access Control Based on Need to Know"),
    ("Information Disclosure", "Data leakage to untrusted external entity", "PCI DSS 4.0", "Req-12.8", "Third-Party Service Provider Management"),
    # Denial of Service
    ("Denial of Service", "External entity flood attack on process", "PCI DSS 4.0", "Req-11.4", "Intrusion Detection and Prevention"),
    ("Denial of Service", "External entity flood attack on process", "PCI DSS 4.0", "Req-1.2", "Network Security Controls Configuration"),
    ("Denial of Service", "Process resource exhaustion", "PCI DSS 4.0", "Req-2.2", "System Components are Configured and Managed Securely"),
    ("Denial of Service", "Process resource exhaustion", "PCI DSS 4.0", "Req-12.10", "Incident Response Plan"),
    ("Denial of Service", "Single point of failure", "PCI DSS 4.0", "Req-12.10", "Incident Response Plan"),
    ("Denial of Service", "Single point of failure", "PCI DSS 4.0", "Req-2.2", "System Components are Configured and Managed Securely"),
    ("Denial of Service", "Internet-facing process without input validation", "PCI DSS 4.0", "Req-6.5", "Secure Coding Practices"),
    ("Denial of Service", "Internet-facing process without input validation", "PCI DSS 4.0", "Req-6.4", "Public-Facing Web Application Protection"),
    ("Denial of Service", "Internet-exposed flood vector", "PCI DSS 4.0", "Req-11.4", "Intrusion Detection and Prevention"),
    ("Denial of Service", "Internet-exposed flood vector", "PCI DSS 4.0", "Req-1.3", "Network Access Restrictions"),
    ("Denial of Service", "Data store without backup", "PCI DSS 4.0", "Req-12.10", "Incident Response Plan"),
    ("Denial of Service", "Data store without backup", "PCI DSS 4.0", "Req-12.10", "Incident Response Plan"),
    # Elevation of Privilege
    ("Elevation of Privilege", "Privilege escalation via external access across boundary", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Elevation of Privilege", "Privilege escalation via external access across boundary", "PCI DSS 4.0", "Req-8.3", "Multi-Factor Authentication for Access"),
    ("Elevation of Privilege", "Unauthorized privilege escalation across boundary", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Elevation of Privilege", "Unauthorized privilege escalation across boundary", "PCI DSS 4.0", "Req-1.3", "Network Access Restrictions"),
    ("Elevation of Privilege", "Multiple entry points to trust boundary", "PCI DSS 4.0", "Req-1.2", "Network Security Controls Configuration"),
    ("Elevation of Privilege", "Multiple entry points to trust boundary", "PCI DSS 4.0", "Req-11.3", "External and Internal Vulnerability Scans"),
    ("Elevation of Privilege", "Internet-facing process privilege escalation", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Elevation of Privilege", "Internet-facing process privilege escalation", "PCI DSS 4.0", "Req-6.4", "Public-Facing Web Application Protection"),
    ("Elevation of Privilege", "Unauthenticated cross-boundary data store access", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Elevation of Privilege", "Unauthenticated cross-boundary data store access", "PCI DSS 4.0", "Req-8.3", "Multi-Factor Authentication for Access"),
    ("Elevation of Privilege", "Missing input validation on cross-boundary process", "PCI DSS 4.0", "Req-6.5", "Secure Coding Practices"),
    ("Elevation of Privilege", "Missing input validation on cross-boundary process", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Elevation of Privilege", "Untrusted unauthenticated data store access", "PCI DSS 4.0", "Req-8.2", "User Identification and Authentication Management"),
    ("Elevation of Privilege", "Untrusted unauthenticated data store access", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    #
    # ════════════════════════════════════════════════════════════════════════════
    # ISO 27001:2022 — 82 mappings
    # ════════════════════════════════════════════════════════════════════════════
    # Spoofing
    ("Spoofing", "Identity spoofing across trust boundary", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Spoofing", "Identity spoofing across trust boundary", "ISO 27001", "A.5.15", "Access Control"),
    ("Spoofing", "Spoofed data flow across boundary", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Spoofing", "Spoofed data flow across boundary", "ISO 27001", "A.8.26", "Application Security Requirements"),
    ("Spoofing", "External entity identity spoofing", "ISO 27001", "A.5.15", "Access Control"),
    ("Spoofing", "External entity identity spoofing", "ISO 27001", "A.5.19", "Information Security in Supplier Relationships"),
    ("Spoofing", "Unauthenticated process receives cross-boundary flow", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Spoofing", "Unauthenticated process receives cross-boundary flow", "ISO 27001", "A.8.3", "Information Access Restriction"),
    ("Spoofing", "Unauthenticated external entity writes to data store", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Spoofing", "Unauthenticated external entity writes to data store", "ISO 27001", "A.5.15", "Access Control"),
    ("Spoofing", "Internet-facing process without authentication", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Spoofing", "Internet-facing process without authentication", "ISO 27001", "A.8.20", "Networks Security"),
    # Tampering
    ("Tampering", "Data tampering in transit across boundary", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "Data tampering in transit across boundary", "ISO 27001", "A.8.20", "Networks Security"),
    ("Tampering", "Unauthorized data store modification by external entity", "ISO 27001", "A.8.3", "Information Access Restriction"),
    ("Tampering", "Unauthorized data store modification by external entity", "ISO 27001", "A.8.25", "Secure Development Life Cycle"),
    ("Tampering", "Data store write integrity risk", "ISO 27001", "A.8.9", "Configuration Management"),
    ("Tampering", "Data store write integrity risk", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "Cross-boundary data store tampering", "ISO 27001", "A.8.3", "Information Access Restriction"),
    ("Tampering", "Cross-boundary data store tampering", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "Missing input validation on external input", "ISO 27001", "A.8.26", "Application Security Requirements"),
    ("Tampering", "Missing input validation on external input", "ISO 27001", "A.8.28", "Secure Coding"),
    ("Tampering", "Unencrypted data store", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "Unencrypted data store", "ISO 27001", "A.8.11", "Data Masking"),
    ("Tampering", "Internet-facing process without encryption", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "Internet-facing process without encryption", "ISO 27001", "A.8.20", "Networks Security"),
    ("Tampering", "Untrusted external entity input", "ISO 27001", "A.5.19", "Information Security in Supplier Relationships"),
    ("Tampering", "Untrusted external entity input", "ISO 27001", "A.8.26", "Application Security Requirements"),
    # Repudiation
    ("Repudiation", "Unlogged process actions", "ISO 27001", "A.8.15", "Logging"),
    ("Repudiation", "Unlogged process actions", "ISO 27001", "A.8.17", "Clock Synchronization"),
    ("Repudiation", "Unaudited data store modification", "ISO 27001", "A.8.15", "Logging"),
    ("Repudiation", "Unaudited data store modification", "ISO 27001", "A.8.16", "Monitoring Activities"),
    ("Repudiation", "Unaudited external entity interaction", "ISO 27001", "A.8.15", "Logging"),
    ("Repudiation", "Unaudited external entity interaction", "ISO 27001", "A.5.15", "Access Control"),
    ("Repudiation", "Sensitive data process audit gap", "ISO 27001", "A.8.15", "Logging"),
    ("Repudiation", "Sensitive data process audit gap", "ISO 27001", "A.8.16", "Monitoring Activities"),
    ("Repudiation", "Credential store without backup", "ISO 27001", "A.8.13", "Information Backup"),
    ("Repudiation", "Credential store without backup", "ISO 27001", "A.8.15", "Logging"),
    ("Repudiation", "Internet-facing process audit risk", "ISO 27001", "A.8.15", "Logging"),
    ("Repudiation", "Internet-facing process audit risk", "ISO 27001", "A.8.16", "Monitoring Activities"),
    # Information Disclosure
    ("Information Disclosure", "Data exposure in transit across boundary", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Information Disclosure", "Data exposure in transit across boundary", "ISO 27001", "A.8.20", "Networks Security"),
    ("Information Disclosure", "Sensitive data leaked to external entity", "ISO 27001", "A.5.14", "Information Transfer"),
    ("Information Disclosure", "Sensitive data leaked to external entity", "ISO 27001", "A.8.11", "Data Masking"),
    ("Information Disclosure", "Sensitive data in flow label", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Information Disclosure", "Sensitive data in flow label", "ISO 27001", "A.5.12", "Classification of Information"),
    ("Information Disclosure", "Data store exposure across boundary", "ISO 27001", "A.8.3", "Information Access Restriction"),
    ("Information Disclosure", "Data store exposure across boundary", "ISO 27001", "A.8.20", "Networks Security"),
    ("Information Disclosure", "Unencrypted credential storage", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Information Disclosure", "Unencrypted credential storage", "ISO 27001", "A.5.17", "Authentication Information"),
    ("Information Disclosure", "Sensitive data processed without encryption", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Information Disclosure", "Sensitive data processed without encryption", "ISO 27001", "A.8.11", "Data Masking"),
    ("Information Disclosure", "Internet-facing data store", "ISO 27001", "A.8.20", "Networks Security"),
    ("Information Disclosure", "Internet-facing data store", "ISO 27001", "A.8.3", "Information Access Restriction"),
    ("Information Disclosure", "Data leakage to untrusted external entity", "ISO 27001", "A.8.12", "Data Leakage Prevention"),
    ("Information Disclosure", "Data leakage to untrusted external entity", "ISO 27001", "A.5.19", "Information Security in Supplier Relationships"),
    # Denial of Service
    ("Denial of Service", "External entity flood attack on process", "ISO 27001", "A.8.20", "Networks Security"),
    ("Denial of Service", "External entity flood attack on process", "ISO 27001", "A.8.16", "Monitoring Activities"),
    ("Denial of Service", "Process resource exhaustion", "ISO 27001", "A.8.6", "Capacity Management"),
    ("Denial of Service", "Process resource exhaustion", "ISO 27001", "A.8.14", "Redundancy of Information Processing Facilities"),
    ("Denial of Service", "Single point of failure", "ISO 27001", "A.8.14", "Redundancy of Information Processing Facilities"),
    ("Denial of Service", "Single point of failure", "ISO 27001", "A.5.30", "ICT Readiness for Business Continuity"),
    ("Denial of Service", "Internet-facing process without input validation", "ISO 27001", "A.8.28", "Secure Coding"),
    ("Denial of Service", "Internet-facing process without input validation", "ISO 27001", "A.8.26", "Application Security Requirements"),
    ("Denial of Service", "Internet-exposed flood vector", "ISO 27001", "A.8.20", "Networks Security"),
    ("Denial of Service", "Internet-exposed flood vector", "ISO 27001", "A.8.21", "Security of Network Services"),
    ("Denial of Service", "Data store without backup", "ISO 27001", "A.8.13", "Information Backup"),
    ("Denial of Service", "Data store without backup", "ISO 27001", "A.5.30", "ICT Readiness for Business Continuity"),
    # Elevation of Privilege
    ("Elevation of Privilege", "Privilege escalation via external access across boundary", "ISO 27001", "A.8.2", "Privileged Access Rights"),
    ("Elevation of Privilege", "Privilege escalation via external access across boundary", "ISO 27001", "A.5.15", "Access Control"),
    ("Elevation of Privilege", "Unauthorized privilege escalation across boundary", "ISO 27001", "A.8.2", "Privileged Access Rights"),
    ("Elevation of Privilege", "Unauthorized privilege escalation across boundary", "ISO 27001", "A.8.3", "Information Access Restriction"),
    ("Elevation of Privilege", "Multiple entry points to trust boundary", "ISO 27001", "A.8.20", "Networks Security"),
    ("Elevation of Privilege", "Multiple entry points to trust boundary", "ISO 27001", "A.8.8", "Management of Technical Vulnerabilities"),
    ("Elevation of Privilege", "Internet-facing process privilege escalation", "ISO 27001", "A.8.2", "Privileged Access Rights"),
    ("Elevation of Privilege", "Internet-facing process privilege escalation", "ISO 27001", "A.8.8", "Management of Technical Vulnerabilities"),
    ("Elevation of Privilege", "Unauthenticated cross-boundary data store access", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Elevation of Privilege", "Unauthenticated cross-boundary data store access", "ISO 27001", "A.8.2", "Privileged Access Rights"),
    ("Elevation of Privilege", "Missing input validation on cross-boundary process", "ISO 27001", "A.8.28", "Secure Coding"),
    ("Elevation of Privilege", "Missing input validation on cross-boundary process", "ISO 27001", "A.8.2", "Privileged Access Rights"),
    ("Elevation of Privilege", "Untrusted unauthenticated data store access", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Elevation of Privilege", "Untrusted unauthenticated data store access", "ISO 27001", "A.8.3", "Information Access Restriction"),
    #
    # ════════════════════════════════════════════════════════════════════════════
    # Extended rules — property-dependent, cloud-native, TLS, financial-sector
    # (S-03, T-08, R-02, I-07, D-02, D-06, E-02, C-01–C-05, T-TLS-01/02, I-TLS-01)
    # ════════════════════════════════════════════════════════════════════════════

    # S-03: High-value external actor spoofing
    ("Spoofing", "High-value external actor spoofing", "NIST 800-53", "IA-8", "Identification and Authentication (Non-Organizational Users)"),
    ("Spoofing", "High-value external actor spoofing", "NIST 800-53", "IA-5", "Authenticator Management"),
    ("Spoofing", "High-value external actor spoofing", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Spoofing", "High-value external actor spoofing", "OSFI B-13", "B13-6.1", "Third Party Risk"),
    ("Spoofing", "High-value external actor spoofing", "PCI DSS 4.0", "Req-8.3", "Multi-Factor Authentication for Access"),
    ("Spoofing", "High-value external actor spoofing", "PCI DSS 4.0", "Req-12.8", "Third-Party Service Provider Management"),
    ("Spoofing", "High-value external actor spoofing", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Spoofing", "High-value external actor spoofing", "ISO 27001", "A.5.19", "Information Security in Supplier Relationships"),

    # C-03: IAM role not enforcing authentication (Spoofing)
    ("Spoofing", "IAM role not enforcing authentication", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Spoofing", "IAM role not enforcing authentication", "NIST 800-53", "IA-5", "Authenticator Management"),
    ("Spoofing", "IAM role not enforcing authentication", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Spoofing", "IAM role not enforcing authentication", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Spoofing", "IAM role not enforcing authentication", "PCI DSS 4.0", "Req-8.3", "Multi-Factor Authentication for Access"),
    ("Spoofing", "IAM role not enforcing authentication", "PCI DSS 4.0", "Req-8.2", "User Identification and Authentication Management"),
    ("Spoofing", "IAM role not enforcing authentication", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Spoofing", "IAM role not enforcing authentication", "ISO 27001", "A.5.15", "Access Control"),

    # T-08: High-risk control message tampering
    ("Tampering", "High-risk control message tampering", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Tampering", "High-risk control message tampering", "NIST 800-53", "SI-7", "Software, Firmware, and Information Integrity"),
    ("Tampering", "High-risk control message tampering", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "High-risk control message tampering", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Tampering", "High-risk control message tampering", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Tampering", "High-risk control message tampering", "PCI DSS 4.0", "Req-10.2", "Audit Log Implementation"),
    ("Tampering", "High-risk control message tampering", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "High-risk control message tampering", "ISO 27001", "A.8.26", "Application Security Requirements"),

    # C-04: API gateway accepting unvalidated input (Tampering)
    ("Tampering", "API gateway accepting unvalidated input", "NIST 800-53", "SI-10", "Information Input Validation"),
    ("Tampering", "API gateway accepting unvalidated input", "NIST 800-53", "SI-15", "Information Output Filtering"),
    ("Tampering", "API gateway accepting unvalidated input", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Tampering", "API gateway accepting unvalidated input", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "API gateway accepting unvalidated input", "PCI DSS 4.0", "Req-6.5", "Secure Coding Practices"),
    ("Tampering", "API gateway accepting unvalidated input", "PCI DSS 4.0", "Req-6.4", "Public-Facing Web Application Protection"),
    ("Tampering", "API gateway accepting unvalidated input", "ISO 27001", "A.8.26", "Application Security Requirements"),
    ("Tampering", "API gateway accepting unvalidated input", "ISO 27001", "A.8.28", "Secure Coding"),

    # C-05: Internet-facing container without encryption (Tampering)
    ("Tampering", "Internet-facing container without encryption", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Tampering", "Internet-facing container without encryption", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Tampering", "Internet-facing container without encryption", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Internet-facing container without encryption", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Tampering", "Internet-facing container without encryption", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Tampering", "Internet-facing container without encryption", "PCI DSS 4.0", "Req-2.2", "System Components are Configured and Managed Securely"),
    ("Tampering", "Internet-facing container without encryption", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "Internet-facing container without encryption", "ISO 27001", "A.8.20", "Networks Security"),

    # T-TLS-01: Deprecated TLS 1.0 on data flow (Tampering)
    ("Tampering", "Deprecated TLS 1.0 on data flow", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Tampering", "Deprecated TLS 1.0 on data flow", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Tampering", "Deprecated TLS 1.0 on data flow", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Deprecated TLS 1.0 on data flow", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Tampering", "Deprecated TLS 1.0 on data flow", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Tampering", "Deprecated TLS 1.0 on data flow", "PCI DSS 4.0", "Req-2.2", "System Components are Configured and Managed Securely"),
    ("Tampering", "Deprecated TLS 1.0 on data flow", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "Deprecated TLS 1.0 on data flow", "ISO 27001", "A.8.26", "Application Security Requirements"),

    # T-TLS-02: Deprecated TLS 1.1 on data flow (Tampering)
    ("Tampering", "Deprecated TLS 1.1 on data flow", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Tampering", "Deprecated TLS 1.1 on data flow", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Tampering", "Deprecated TLS 1.1 on data flow", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Tampering", "Deprecated TLS 1.1 on data flow", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Tampering", "Deprecated TLS 1.1 on data flow", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Tampering", "Deprecated TLS 1.1 on data flow", "PCI DSS 4.0", "Req-2.2", "System Components are Configured and Managed Securely"),
    ("Tampering", "Deprecated TLS 1.1 on data flow", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Tampering", "Deprecated TLS 1.1 on data flow", "ISO 27001", "A.8.26", "Application Security Requirements"),

    # R-02: Weak auditability on critical workflow (Repudiation)
    ("Repudiation", "Weak auditability on critical workflow", "NIST 800-53", "AU-2", "Event Logging"),
    ("Repudiation", "Weak auditability on critical workflow", "NIST 800-53", "AU-12", "Audit Record Generation"),
    ("Repudiation", "Weak auditability on critical workflow", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Repudiation", "Weak auditability on critical workflow", "OSFI B-13", "B13-3.1", "Governance"),
    ("Repudiation", "Weak auditability on critical workflow", "PCI DSS 4.0", "Req-10.2", "Audit Log Implementation"),
    ("Repudiation", "Weak auditability on critical workflow", "PCI DSS 4.0", "Req-10.3", "Audit Log Protection"),
    ("Repudiation", "Weak auditability on critical workflow", "ISO 27001", "A.8.15", "Logging"),
    ("Repudiation", "Weak auditability on critical workflow", "ISO 27001", "A.8.16", "Monitoring Activities"),

    # I-07: Token vault exposure (Information Disclosure)
    ("Information Disclosure", "Token vault exposure", "NIST 800-53", "SC-28", "Protection of Information at Rest"),
    ("Information Disclosure", "Token vault exposure", "NIST 800-53", "IA-5", "Authenticator Management"),
    ("Information Disclosure", "Token vault exposure", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Token vault exposure", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Information Disclosure", "Token vault exposure", "PCI DSS 4.0", "Req-3.5", "Protect Stored Account Data Cryptographic Keys"),
    ("Information Disclosure", "Token vault exposure", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Information Disclosure", "Token vault exposure", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Information Disclosure", "Token vault exposure", "ISO 27001", "A.8.3", "Information Access Restriction"),

    # C-01: Managed service without encryption at rest (Information Disclosure)
    ("Information Disclosure", "Managed service without encryption at rest", "NIST 800-53", "SC-28", "Protection of Information at Rest"),
    ("Information Disclosure", "Managed service without encryption at rest", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Information Disclosure", "Managed service without encryption at rest", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "Managed service without encryption at rest", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Information Disclosure", "Managed service without encryption at rest", "PCI DSS 4.0", "Req-3.5", "Protect Stored Account Data Cryptographic Keys"),
    ("Information Disclosure", "Managed service without encryption at rest", "PCI DSS 4.0", "Req-3.1", "Stored Account Data Protection Processes"),
    ("Information Disclosure", "Managed service without encryption at rest", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Information Disclosure", "Managed service without encryption at rest", "ISO 27001", "A.8.11", "Data Masking"),

    # I-TLS-01: No TLS on sensitive data flow (Information Disclosure)
    ("Information Disclosure", "No TLS on sensitive data flow", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Information Disclosure", "No TLS on sensitive data flow", "NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("Information Disclosure", "No TLS on sensitive data flow", "OSFI B-13", "B13-4.4", "Data Protection"),
    ("Information Disclosure", "No TLS on sensitive data flow", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Information Disclosure", "No TLS on sensitive data flow", "PCI DSS 4.0", "Req-4.2", "Protect Data in Transit with Strong Cryptography"),
    ("Information Disclosure", "No TLS on sensitive data flow", "PCI DSS 4.0", "Req-4.1", "Strong Cryptography Processes for Data in Transit"),
    ("Information Disclosure", "No TLS on sensitive data flow", "ISO 27001", "A.8.24", "Use of Cryptography"),
    ("Information Disclosure", "No TLS on sensitive data flow", "ISO 27001", "A.8.20", "Networks Security"),

    # D-02: Critical workflow process exhaustion (Denial of Service)
    ("Denial of Service", "Critical workflow process exhaustion", "NIST 800-53", "SC-5", "Denial-of-Service Protection"),
    ("Denial of Service", "Critical workflow process exhaustion", "NIST 800-53", "CP-9", "System Backup"),
    ("Denial of Service", "Critical workflow process exhaustion", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Denial of Service", "Critical workflow process exhaustion", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Denial of Service", "Critical workflow process exhaustion", "PCI DSS 4.0", "Req-2.2", "System Components are Configured and Managed Securely"),
    ("Denial of Service", "Critical workflow process exhaustion", "PCI DSS 4.0", "Req-12.10", "Incident Response Plan"),
    ("Denial of Service", "Critical workflow process exhaustion", "ISO 27001", "A.8.6", "Capacity Management"),
    ("Denial of Service", "Critical workflow process exhaustion", "ISO 27001", "A.8.14", "Redundancy of Information Processing Facilities"),

    # D-06: Core ledger resilience failure (Denial of Service)
    ("Denial of Service", "Core ledger resilience failure", "NIST 800-53", "CP-9", "System Backup"),
    ("Denial of Service", "Core ledger resilience failure", "NIST 800-53", "CP-10", "System Recovery and Reconstitution"),
    ("Denial of Service", "Core ledger resilience failure", "OSFI B-13", "B13-5.1", "Technology Strategy"),
    ("Denial of Service", "Core ledger resilience failure", "OSFI B-13", "B13-5.2", "Business Continuity"),
    ("Denial of Service", "Core ledger resilience failure", "OSFI B-13", "B13-3.2", "Risk Management"),
    ("Denial of Service", "Core ledger resilience failure", "PCI DSS 4.0", "Req-12.3.4", "Hardware and Software Technologies Reviewed at Least Once Every 12 Months"),
    ("Denial of Service", "Core ledger resilience failure", "PCI DSS 4.0", "Req-12.10", "Incident Response Plan"),
    ("Denial of Service", "Core ledger resilience failure", "ISO 27001", "A.8.13", "Information Backup"),
    ("Denial of Service", "Core ledger resilience failure", "ISO 27001", "A.5.30", "ICT Readiness for Business Continuity"),

    # E-02: Privileged workflow abuse across boundary (Elevation of Privilege)
    ("Elevation of Privilege", "Privileged workflow abuse across boundary", "NIST 800-53", "AC-6", "Least Privilege"),
    ("Elevation of Privilege", "Privileged workflow abuse across boundary", "NIST 800-53", "AC-4", "Information Flow Enforcement"),
    ("Elevation of Privilege", "Privileged workflow abuse across boundary", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Privileged workflow abuse across boundary", "OSFI B-13", "B13-5.3", "Monitoring"),
    ("Elevation of Privilege", "Privileged workflow abuse across boundary", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Elevation of Privilege", "Privileged workflow abuse across boundary", "PCI DSS 4.0", "Req-1.3", "Network Access Restrictions"),
    ("Elevation of Privilege", "Privileged workflow abuse across boundary", "ISO 27001", "A.8.2", "Privileged Access Rights"),
    ("Elevation of Privilege", "Privileged workflow abuse across boundary", "ISO 27001", "A.8.20", "Networks Security"),

    # C-02: Serverless function crossing trust boundary without authentication (Elevation of Privilege)
    ("Elevation of Privilege", "Serverless function crossing trust boundary without authentication", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Elevation of Privilege", "Serverless function crossing trust boundary without authentication", "NIST 800-53", "AC-3", "Access Enforcement"),
    ("Elevation of Privilege", "Serverless function crossing trust boundary without authentication", "OSFI B-13", "B13-4.3", "Access Controls"),
    ("Elevation of Privilege", "Serverless function crossing trust boundary without authentication", "OSFI B-13", "B13-4.2", "Vulnerability Management"),
    ("Elevation of Privilege", "Serverless function crossing trust boundary without authentication", "PCI DSS 4.0", "Req-8.3", "Multi-Factor Authentication for Access"),
    ("Elevation of Privilege", "Serverless function crossing trust boundary without authentication", "PCI DSS 4.0", "Req-7.2", "Access Control System Configuration"),
    ("Elevation of Privilege", "Serverless function crossing trust boundary without authentication", "ISO 27001", "A.8.5", "Secure Authentication"),
    ("Elevation of Privilege", "Serverless function crossing trust boundary without authentication", "ISO 27001", "A.8.2", "Privileged Access Rights"),
]


OSFI_B13_ALIGNMENT_IDS = {
    "Access Controls": "TG-B13-ACCESS",
    "Cyber Risk Management": "TG-B13-CYBER",
    "Vulnerability Management": "TG-B13-VULN",
    "Data Protection": "TG-B13-DATA",
    "Monitoring": "TG-B13-MON",
    "Business Continuity": "TG-B13-BCP",
    "Governance": "TG-B13-GOV",
    "Risk Management": "TG-B13-RISK",
    "Third Party Risk": "TG-B13-TPRM",
}


def normalized_compliance_seed_data() -> list[tuple[str, str, str, str, str]]:
    """Return seed mappings with internal OSFI alignment labels made explicit."""
    normalized: list[tuple[str, str, str, str, str]] = []
    seen_keys: set[tuple[str, str, str, str]] = set()
    for stride_category, threat_subtype, framework, control_id, control_name in SEED_DATA:
        if framework == "OSFI B-13" and control_id.startswith("B13-"):
            control_id = OSFI_B13_ALIGNMENT_IDS.get(
                control_name,
                "TG-B13-ALIGN",
            )
            control_name = f"{control_name} (ThreatGenix internal OSFI B-13 alignment)"
        key = (stride_category, threat_subtype, framework, control_id)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        normalized.append((stride_category, threat_subtype, framework, control_id, control_name))
    return normalized


async def seed():
    pgvector_enabled = await ensure_pgvector_extension()

    # Import threat intel models so their tables are registered on Base.metadata
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
    except ImportError:
        logger.warning("threat_intel models not available (pgvector not installed?)")

    await create_bootstrap_tables(pgvector_enabled)

    async with async_session() as session:
        # Idempotent per-entry upsert — safe to run against already-seeded databases.
        # Fetches existing (stride_category, threat_subtype, framework, control_id) keys
        # in one query, then only inserts rows that are absent.
        existing_rows = await session.execute(
            select(
                ComplianceMapping.stride_category,
                ComplianceMapping.threat_subtype,
                ComplianceMapping.framework,
                ComplianceMapping.control_id,
            )
        )
        existing_keys: set[tuple] = {tuple(row) for row in existing_rows.all()}

        seed_entries = normalized_compliance_seed_data()
        new_entries = [
            ComplianceMapping(
                stride_category=stride_cat,
                threat_subtype=subtype,
                framework=framework,
                control_id=control_id,
                control_name=control_name,
            )
            for stride_cat, subtype, framework, control_id, control_name in seed_entries
            if (stride_cat, subtype, framework, control_id) not in existing_keys
        ]

        if new_entries:
            session.add_all(new_entries)
            await session.commit()
            print(f"Seeded {len(new_entries)} new compliance mappings ({len(existing_keys)} already present).")
        else:
            print(f"Compliance mappings already up to date ({len(existing_keys)} entries).")

        # Seed CRI Profile mappings (deterministic, no external fetch needed)
        try:
            from app.models.threat_intel import CRIMapping as CRIMappingModel
            existing_cri = await session.execute(select(CRIMappingModel.id))
            if existing_cri.scalars().first() is None:
                from app.services.threat_intel.ingest_cri import ingest_cri
                count = await ingest_cri(session)
                print(f"Seeded {count} CRI Profile mappings.")
            else:
                print("CRI Profile mappings already seeded, skipping.")
        except Exception as exc:
            logger.warning("CRI Profile seeding skipped: %s", exc)


async def ensure_pgvector_extension() -> bool:
    """Enable pgvector when available and report whether vector tables are safe to create."""
    async with engine.begin() as conn:
        try:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            logger.info("pgvector extension enabled")
            return True
        except Exception as exc:
            logger.warning("Could not enable pgvector extension (non-fatal): %s", exc)
            return False


def get_bootstrap_table_names(pgvector_enabled: bool) -> set[str]:
    """Return the tables that can be created safely for this database."""
    table_names = set(Base.metadata.tables)
    if pgvector_enabled:
        return table_names
    return table_names - VECTOR_THREAT_INTEL_TABLES


def get_bootstrap_tables(pgvector_enabled: bool) -> list:
    """Preserve metadata order while excluding vector-backed tables when needed."""
    table_names = get_bootstrap_table_names(pgvector_enabled)
    return [table for table in Base.metadata.sorted_tables if table.name in table_names]


def repair_runtime_schema(sync_conn) -> None:
    """Backfill columns that older environments may be missing despite newer code."""
    for table_name, column_name, column_type in BOOTSTRAP_SCHEMA_REPAIRS:
        sync_conn.execute(
            text(
                f"ALTER TABLE IF EXISTS {table_name} "
                f"ADD COLUMN IF NOT EXISTS {column_name} {column_type}"
            )
        )


def repair_threat_model_schema(sync_conn) -> None:
    """Backward-compatible entry point for threat-model JSONB bootstrap repairs."""
    repair_runtime_schema(sync_conn)


async def create_bootstrap_tables(pgvector_enabled: bool) -> None:
    """Create the subset of tables supported by the current Postgres instance."""
    tables = get_bootstrap_tables(pgvector_enabled)
    if not pgvector_enabled and VECTOR_THREAT_INTEL_TABLES & set(Base.metadata.tables):
        skipped = ", ".join(sorted(VECTOR_THREAT_INTEL_TABLES))
        logger.warning("Skipping pgvector-backed tables during bootstrap: %s", skipped)

    async with engine.begin() as conn:
        def _bootstrap(sync_conn) -> None:
            Base.metadata.create_all(sync_conn, tables=tables)
            repair_runtime_schema(sync_conn)

        await conn.run_sync(_bootstrap)


if __name__ == "__main__":
    asyncio.run(seed())
