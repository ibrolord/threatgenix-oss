"""Seed a realistic Northstar Bank demo scenario for pilot demonstrations.

Usage: python -m app.seed_demo
Idempotent — safe to re-run. Skips if demo user already exists.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.database import async_session
from app.models.organization import Organization
from app.models.user import User
from app.models.threat_model import ThreatModel
from app.models.dfd import DFDNode, DFDEdge, TrustBoundary
from app.models.threat import Threat
from app.models.scan import ScanJob, ScanFinding, ScanThreatResult  # noqa: F401 — resolve ORM relationships
from app.seed import create_bootstrap_tables, ensure_pgvector_extension
from app.services.auth import hash_password

logger = logging.getLogger(__name__)

# Deterministic UUIDs for demo data
DEMO_ORG_ID = uuid.UUID("00000000-0000-0000-0000-000000000000")
DEMO_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
DEMO_TM_ID = uuid.UUID("00000000-0000-0000-0000-000000000010")

# DFD Nodes
N_MOBILE = uuid.UUID("00000000-0000-0000-0001-000000000001")
N_WEB = uuid.UUID("00000000-0000-0000-0001-000000000002")
N_API_GW = uuid.UUID("00000000-0000-0000-0001-000000000003")
N_AUTH_SVC = uuid.UUID("00000000-0000-0000-0001-000000000004")
N_CORE_BANK = uuid.UUID("00000000-0000-0000-0001-000000000005")
N_CUSTOMER_DB = uuid.UUID("00000000-0000-0000-0001-000000000006")
N_AUDIT_LOG = uuid.UUID("00000000-0000-0000-0001-000000000007")
N_THIRD_PARTY = uuid.UUID("00000000-0000-0000-0001-000000000008")
N_WAF = uuid.UUID("00000000-0000-0000-0001-000000000009")
N_OAUTH_AS = uuid.UUID("00000000-0000-0000-0001-000000000010")
N_SECRETS_MGR = uuid.UUID("00000000-0000-0000-0001-000000000011")

# Trust Boundaries
B_EXTERNAL = uuid.UUID("00000000-0000-0000-0002-000000000001")
B_DMZ = uuid.UUID("00000000-0000-0000-0002-000000000002")
B_INTERNAL = uuid.UUID("00000000-0000-0000-0002-000000000003")
B_PCI_DATA = uuid.UUID("00000000-0000-0000-0002-000000000004")
B_THIRD_PARTY = uuid.UUID("00000000-0000-0000-0002-000000000005")

# Edges
E1 = uuid.UUID("00000000-0000-0000-0003-000000000001")
E2 = uuid.UUID("00000000-0000-0000-0003-000000000002")
E3 = uuid.UUID("00000000-0000-0000-0003-000000000003")
E4 = uuid.UUID("00000000-0000-0000-0003-000000000004")
E5 = uuid.UUID("00000000-0000-0000-0003-000000000005")
E6 = uuid.UUID("00000000-0000-0000-0003-000000000006")
E7 = uuid.UUID("00000000-0000-0000-0003-000000000007")
E8 = uuid.UUID("00000000-0000-0000-0003-000000000008")
E9 = uuid.UUID("00000000-0000-0000-0003-000000000009")
E10 = uuid.UUID("00000000-0000-0000-0003-000000000010")
E11 = uuid.UUID("00000000-0000-0000-0003-000000000011")
E12 = uuid.UUID("00000000-0000-0000-0003-000000000012")
E13 = uuid.UUID("00000000-0000-0000-0003-000000000013")
E14 = uuid.UUID("00000000-0000-0000-0003-000000000014")
E15 = uuid.UUID("00000000-0000-0000-0003-000000000015")


async def seed_demo():
    pgvector_enabled = await ensure_pgvector_extension()
    await create_bootstrap_tables(pgvector_enabled)

    async with async_session() as db:
        # Check if demo user exists
        existing = await db.execute(select(User).where(User.id == DEMO_USER_ID))
        if existing.scalar_one_or_none() is not None:
            # Backfill governance snapshots if missing (supports re-runs after adding snapshots)
            tm_result = await db.execute(
                select(ThreatModel).where(ThreatModel.id == DEMO_TM_ID)
            )
            existing_tm = tm_result.scalar_one_or_none()
            if existing_tm is not None and not existing_tm.model_snapshots:
                from datetime import timedelta
                _today = datetime.now(timezone.utc).date()
                existing_tm.model_snapshots = [
                    {"created_at": str(_today - timedelta(days=13)), "threats": [{"severity": "High"}, {"severity": "Critical"}, {"severity": "Medium"}]},
                    {"created_at": str(_today - timedelta(days=10)), "threats": [{"severity": "Critical"}, {"severity": "High"}, {"severity": "High"}, {"severity": "Medium"}]},
                    {"created_at": str(_today - timedelta(days=7)), "threats": [{"severity": "Critical"}, {"severity": "High"}, {"severity": "Medium"}, {"severity": "Low"}]},
                    {"created_at": str(_today - timedelta(days=3)), "threats": [{"severity": "High"}, {"severity": "Medium"}, {"severity": "Medium"}, {"severity": "Low"}]},
                    {"created_at": str(_today), "threats": [{"severity": "High"}, {"severity": "Medium"}, {"severity": "Low"}]},
                ]
                existing_tm.review_records = [
                    {"updated_at": str(_today - timedelta(days=10)), "reviewer": "priya@example.test", "decision": "approved"},
                    {"updated_at": str(_today - timedelta(days=3)), "reviewer": "priya@example.test", "decision": "approved"},
                    {"updated_at": str(_today), "reviewer": "priya@example.test", "decision": "pending"},
                ]
                from sqlalchemy import update as sa_update
                await db.execute(
                    sa_update(ThreatModel)
                    .where(ThreatModel.id == DEMO_TM_ID)
                    .values(
                        model_snapshots=existing_tm.model_snapshots,
                        review_records=existing_tm.review_records,
                    )
                )
                await db.commit()
                logger.info("Demo governance snapshots backfilled.")
            else:
                logger.info("Demo data already seeded — skipping.")
            return

        # 1. Demo organization + user
        organization = Organization(
            id=DEMO_ORG_ID,
            name="Northstar Bank Demo Organization",
        )
        db.add(organization)

        user = User(
            id=DEMO_USER_ID,
            email="priya@example.test",
            hashed_password=hash_password("ThreatGenix2026!"),
            full_name="Priya Sharma",
            role="admin",
            is_active=True,
            organization_id=DEMO_ORG_ID,
        )
        db.add(user)

        # 2. Threat model
        from datetime import timedelta
        _today = datetime.now(timezone.utc).date()
        # Seed 14 days of governance activity so the dashboard trends chart is not blank
        _demo_snapshots = [
            {
                "created_at": str(_today - timedelta(days=13)),
                "threats": [{"severity": "High"}, {"severity": "Critical"}, {"severity": "Medium"}],
            },
            {
                "created_at": str(_today - timedelta(days=10)),
                "threats": [{"severity": "Critical"}, {"severity": "High"}, {"severity": "High"}, {"severity": "Medium"}],
            },
            {
                "created_at": str(_today - timedelta(days=7)),
                "threats": [{"severity": "Critical"}, {"severity": "High"}, {"severity": "Medium"}, {"severity": "Low"}],
            },
            {
                "created_at": str(_today - timedelta(days=3)),
                "threats": [{"severity": "High"}, {"severity": "Medium"}, {"severity": "Medium"}, {"severity": "Low"}],
            },
            {
                "created_at": str(_today),
                "threats": [{"severity": "High"}, {"severity": "Medium"}, {"severity": "Low"}],
            },
        ]
        _demo_review_records = [
            {"updated_at": str(_today - timedelta(days=10)), "reviewer": "priya@example.test", "decision": "approved"},
            {"updated_at": str(_today - timedelta(days=3)), "reviewer": "priya@example.test", "decision": "approved"},
            {"updated_at": str(_today), "reviewer": "priya@example.test", "decision": "pending"},
        ]
        tm = ThreatModel(
            id=DEMO_TM_ID,
            system_name="Northstar Bank — Open Banking API Platform",
            description="Customer-facing open banking platform enabling third-party fintech integrations via PSD2-compliant APIs. Processes real-time payments, account aggregation, and consent management.",
            data_classification="Restricted",
            regulatory_scope=["OSFI B-13", "PCI DSS", "PIPEDA"],
            deployment_model="cloud",
            owner_id=DEMO_USER_ID,
            organization_id=DEMO_ORG_ID,
            model_snapshots=_demo_snapshots,
            review_records=_demo_review_records,
        )
        db.add(tm)

        # 3. Trust Boundaries (must be created before nodes reference them)
        boundaries = [
            TrustBoundary(id=B_EXTERNAL, threat_model_id=DEMO_TM_ID, name="External Network",
                          node_ids=[N_MOBILE, N_WEB], boundary_type="network"),
            TrustBoundary(id=B_DMZ, threat_model_id=DEMO_TM_ID, name="DMZ",
                          node_ids=[N_API_GW, N_WAF], boundary_type="network"),
            TrustBoundary(id=B_INTERNAL, threat_model_id=DEMO_TM_ID, name="Internal Network (PCI CDE)",
                          node_ids=[N_AUTH_SVC, N_CORE_BANK, N_AUDIT_LOG, N_OAUTH_AS], boundary_type="regulatory"),
            TrustBoundary(id=B_PCI_DATA, threat_model_id=DEMO_TM_ID, name="PCI Data Tier",
                          node_ids=[N_CUSTOMER_DB, N_SECRETS_MGR], boundary_type="regulatory"),
            TrustBoundary(id=B_THIRD_PARTY, threat_model_id=DEMO_TM_ID, name="Third-Party / Partner Network",
                          node_ids=[N_THIRD_PARTY], boundary_type="organizational"),
        ]
        for b in boundaries:
            db.add(b)
        await db.flush()

        # 4. DFD Nodes
        nodes = [
            DFDNode(id=N_MOBILE, threat_model_id=DEMO_TM_ID, node_type="external_entity",
                    name="Mobile Banking App", position_x=0, position_y=0,
                    properties={"authenticated": True, "trusted": False, "internet_facing": True,
                                "uses_encryption": True,
                                "data_classification": "Restricted", "network_exposure": "PUBLIC"}),
            DFDNode(id=N_WEB, threat_model_id=DEMO_TM_ID, node_type="external_entity",
                    name="Web Portal", position_x=0, position_y=120,
                    properties={"authenticated": True, "trusted": False, "internet_facing": True,
                                "uses_encryption": True,
                                "data_classification": "Restricted", "network_exposure": "PUBLIC"}),
            DFDNode(id=N_WAF, threat_model_id=DEMO_TM_ID, node_type="api_gateway",
                    name="WAF / DDoS Protection", position_x=100, position_y=60,
                    trust_boundary_id=B_DMZ,
                    security_controls=[{"control_type": "WAF", "name": "AWS WAF", "covers": ["input_validation", "rate_limiting", "sql_injection"]},
                                       {"control_type": "DDoS", "name": "AWS Shield", "covers": ["ddos_protection"]}],
                    properties={"internet_facing": True, "validates_input": True, "uses_auth": True,
                                "uses_encryption": True, "rate_limited": True,
                                "data_classification": "Public", "network_exposure": "PUBLIC"}),
            DFDNode(id=N_API_GW, threat_model_id=DEMO_TM_ID, node_type="process",
                    name="API Gateway", position_x=200, position_y=60,
                    trust_boundary_id=B_DMZ,
                    properties={"uses_auth": True, "validates_input": True, "internet_facing": True,
                                "uses_encryption": True, "handles_sensitive_data": True, "rate_limited": True,
                                "logging_level": "full", "data_classification": "Restricted",
                                "network_exposure": "PUBLIC"}),
            DFDNode(id=N_AUTH_SVC, threat_model_id=DEMO_TM_ID, node_type="process",
                    name="Authentication Service", position_x=400, position_y=0,
                    trust_boundary_id=B_INTERNAL,
                    properties={"uses_auth": True, "uses_encryption": True, "validates_input": True,
                                "handles_sensitive_data": True, "handles_pii": True, "internet_facing": False,
                                "logging_level": "full", "data_classification": "Restricted",
                                "network_exposure": "PRIVATE"}),
            DFDNode(id=N_OAUTH_AS, threat_model_id=DEMO_TM_ID, node_type="process",
                    name="OAuth Authorization Server", position_x=500, position_y=0,
                    trust_boundary_id=B_INTERNAL,
                    properties={"uses_auth": True, "uses_encryption": True, "validates_input": True,
                                "handles_sensitive_data": True, "handles_pii": True, "stores_credentials": True,
                                "internet_facing": False, "data_classification": "Restricted",
                                "network_exposure": "PRIVATE"}),
            DFDNode(id=N_CORE_BANK, threat_model_id=DEMO_TM_ID, node_type="process",
                    name="Core Banking Engine", position_x=400, position_y=120,
                    trust_boundary_id=B_INTERNAL,
                    properties={"uses_auth": True, "uses_encryption": True, "validates_input": True,
                                "handles_sensitive_data": True, "handles_pii": True,
                                "handles_financial_data": True, "internet_facing": False,
                                "logging_level": "full", "data_classification": "Restricted",
                                "network_exposure": "PRIVATE"}),
            DFDNode(id=N_CUSTOMER_DB, threat_model_id=DEMO_TM_ID, node_type="data_store",
                    name="Customer Database", position_x=600, position_y=60,
                    trust_boundary_id=B_PCI_DATA,
                    properties={"stores_credentials": True, "encrypted_at_rest": True, "has_backup": True,
                                "handles_pii": True, "handles_financial_data": True,
                                "handles_sensitive_data": True, "data_classification": "Restricted",
                                "network_exposure": "ISOLATED"}),
            DFDNode(id=N_SECRETS_MGR, threat_model_id=DEMO_TM_ID, node_type="data_store",
                    name="Secrets Manager (KMS)", position_x=700, position_y=120,
                    trust_boundary_id=B_PCI_DATA,
                    properties={"stores_credentials": True, "encrypted_at_rest": True,
                                "handles_sensitive_data": True, "data_classification": "Restricted",
                                "network_exposure": "ISOLATED"}),
            DFDNode(id=N_AUDIT_LOG, threat_model_id=DEMO_TM_ID, node_type="data_store",
                    name="Audit Log Store", position_x=600, position_y=180,
                    trust_boundary_id=B_INTERNAL,
                    properties={"encrypted_at_rest": True, "handles_sensitive_data": True,
                                "handles_pii": True, "data_classification": "Confidential",
                                "network_exposure": "PRIVATE", "integrity_controls": "append-only"}),
            DFDNode(id=N_THIRD_PARTY, threat_model_id=DEMO_TM_ID, node_type="external_entity",
                    name="Third-Party Payment API", position_x=400, position_y=240,
                    trust_boundary_id=B_THIRD_PARTY,
                    properties={"internet_facing": True, "trusted": False, "handles_pii": True,
                                "handles_financial_data": True, "data_classification": "Restricted"}),
        ]
        for n in nodes:
            db.add(n)

        # 5. DFD Edges
        edges = [
            DFDEdge(id=E1, threat_model_id=DEMO_TM_ID, source_node_id=N_MOBILE, target_node_id=N_WAF,
                    label="HTTPS request", tls_version="tls_1_3",
                    properties={"protocol": "HTTPS/TLS1.3", "encryption_in_transit": True,
                                "carries_pii": True, "carries_credentials": True,
                                "auth_mechanism": "OAuth2/JWT", "rate_limited": True,
                                "data_classification": "Restricted"}),
            DFDEdge(id=E2, threat_model_id=DEMO_TM_ID, source_node_id=N_WEB, target_node_id=N_WAF,
                    label="HTTPS request", tls_version="tls_1_3",
                    properties={"protocol": "HTTPS/TLS1.3", "encryption_in_transit": True,
                                "carries_pii": True, "carries_credentials": True,
                                "auth_mechanism": "OAuth2/JWT", "rate_limited": True,
                                "data_classification": "Restricted"}),
            DFDEdge(id=E3, threat_model_id=DEMO_TM_ID, source_node_id=N_API_GW, target_node_id=N_AUTH_SVC,
                    label="OAuth token validation",
                    properties={"protocol": "HTTPS/mTLS", "encryption_in_transit": True,
                                "carries_credentials": True, "carries_secrets": True,
                                "auth_mechanism": "mTLS", "data_classification": "Restricted"}),
            DFDEdge(id=E4, threat_model_id=DEMO_TM_ID, source_node_id=N_API_GW, target_node_id=N_CORE_BANK,
                    label="Authenticated API call",
                    properties={"protocol": "HTTPS/mTLS", "encryption_in_transit": True,
                                "carries_pii": True, "carries_financial_data": True,
                                "auth_mechanism": "JWT", "data_classification": "Restricted"}),
            DFDEdge(id=E5, threat_model_id=DEMO_TM_ID, source_node_id=N_CORE_BANK, target_node_id=N_CUSTOMER_DB,
                    label="SQL query (customer data)",
                    properties={"protocol": "TLS", "encryption_in_transit": True,
                                "carries_pii": True, "carries_financial_data": True,
                                "carries_credentials": True, "auth_mechanism": "service-account",
                                "data_classification": "Restricted"}),
            DFDEdge(id=E6, threat_model_id=DEMO_TM_ID, source_node_id=N_CUSTOMER_DB, target_node_id=N_CORE_BANK,
                    label="Query results",
                    properties={"protocol": "TLS", "encryption_in_transit": True,
                                "carries_pii": True, "carries_financial_data": True,
                                "data_classification": "Restricted"}),
            DFDEdge(id=E7, threat_model_id=DEMO_TM_ID, source_node_id=N_CORE_BANK, target_node_id=N_AUDIT_LOG,
                    label="Audit event",
                    properties={"protocol": "TLS", "encryption_in_transit": True,
                                "carries_pii": True, "data_classification": "Confidential",
                                "integrity_protected": True}),
            DFDEdge(id=E8, threat_model_id=DEMO_TM_ID, source_node_id=N_CORE_BANK, target_node_id=N_THIRD_PARTY,
                    label="Payment instruction",
                    properties={"protocol": "HTTPS/mTLS", "encryption_in_transit": True,
                                "carries_financial_data": True, "carries_pii": True,
                                "auth_mechanism": "mTLS+API-key", "data_classification": "Restricted"}),
            DFDEdge(id=E9, threat_model_id=DEMO_TM_ID, source_node_id=N_API_GW, target_node_id=N_MOBILE,
                    label="API response",
                    properties={"protocol": "HTTPS/TLS1.3", "encryption_in_transit": True,
                                "data_classification": "Restricted"}),
            DFDEdge(id=E10, threat_model_id=DEMO_TM_ID, source_node_id=N_API_GW, target_node_id=N_AUDIT_LOG,
                    label="API access event",
                    properties={"protocol": "TLS", "encryption_in_transit": True,
                                "carries_pii": True, "data_classification": "Confidential",
                                "integrity_protected": True}),
            DFDEdge(id=E11, threat_model_id=DEMO_TM_ID, source_node_id=N_AUTH_SVC, target_node_id=N_SECRETS_MGR,
                    label="Key/secret retrieval",
                    properties={"protocol": "TLS", "encryption_in_transit": True,
                                "carries_secrets": True, "data_classification": "Restricted"}),
            DFDEdge(id=E12, threat_model_id=DEMO_TM_ID, source_node_id=N_CORE_BANK, target_node_id=N_SECRETS_MGR,
                    label="DB credential retrieval",
                    properties={"protocol": "TLS", "encryption_in_transit": True,
                                "carries_secrets": True, "data_classification": "Restricted"}),
            DFDEdge(id=E13, threat_model_id=DEMO_TM_ID, source_node_id=N_WAF, target_node_id=N_API_GW,
                    label="Filtered HTTPS traffic", tls_version="tls_1_3",
                    properties={"protocol": "HTTPS/TLS1.3", "encryption_in_transit": True,
                                "rate_limited": True, "data_classification": "Restricted"}),
            DFDEdge(id=E14, threat_model_id=DEMO_TM_ID, source_node_id=N_AUTH_SVC, target_node_id=N_OAUTH_AS,
                    label="OAuth token validation", tls_version="tls_1_3",
                    properties={"protocol": "HTTPS", "encryption_in_transit": True,
                                "data_classification": "Restricted"}),
            # E15: inbound payment initiation from third-party fintech — models PSD2/Open Banking
            # attack surface where an external partner sends payment instructions into Core Banking.
            # Without this edge, spoofing/tampering/EoP threats on inbound fintech flows are absent.
            DFDEdge(id=E15, threat_model_id=DEMO_TM_ID, source_node_id=N_THIRD_PARTY, target_node_id=N_CORE_BANK,
                    label="Payment initiation request", tls_version="tls_1_3",
                    properties={"protocol": "HTTPS/mTLS", "encryption_in_transit": True,
                                "carries_financial_data": True, "carries_pii": True,
                                "auth_mechanism": "mTLS+OAuth2", "data_classification": "Restricted"}),
        ]
        for e in edges:
            db.add(e)

        # 6. Pre-generated threats (realistic mix of triage states)
        threats_data = [
            ("T-001", "Spoofing", "High", "A rogue mobile application impersonating the Mobile Banking App can present valid OAuth tokens obtained via credential stuffing or phishing, making it indistinguishable from a legitimate client to the WAF and API Gateway. The system authenticates the token, not the app instance.", "AI-006", "AI", "Open", [N_MOBILE, N_WAF], [E1]),
            ("T-002", "Tampering", "High", "Data in transit between the API Gateway and Core Banking Engine crosses the DMZ→Internal Network (PCI CDE) trust boundary. TLS termination at the DMZ layer means data is briefly in-the-clear before re-encryption. An attacker with access to the Internal Network segment could intercept or tamper with requests before they reach the Core Banking Engine.", "AI-005", "AI", "Open", [N_API_GW, N_CORE_BANK], [E4]),
            ("T-003", "Tampering", "Critical", "An attacker could modify payment instructions sent from Core Banking Engine to Third-Party Fintech API, potentially redirecting funds.", "T-08", "Rules", "Accepted", [N_CORE_BANK, N_THIRD_PARTY], [E8]),
            ("T-004", "Repudiation", "Medium", "The Mobile Banking App could deny having initiated a transaction. Without cryptographic non-repudiation, disputed transactions cannot be attributed.", "R-01", "Rules", "Open", [N_MOBILE, N_WAF], [E1]),
            ("T-005", "Information Disclosure", "Critical", "Customer credentials stored in the Customer Database could be exposed if an attacker gains access to the Internal Network boundary.", "I-03", "Rules", "Open", [N_CUSTOMER_DB, N_CORE_BANK], [E6]),
            ("T-006", "Information Disclosure", "High", "SQL query results containing customer PII flow from Customer Database to Core Banking Engine. A compromised service account or privileged insider with access to the PCI Data Tier network segment could intercept plaintext query results before application-layer decryption.", "AI-001", "AI", "Dismissed", [N_CUSTOMER_DB, N_CORE_BANK], [E6]),
            ("T-007", "Denial of Service", "High", "The API Gateway is a high-degree connectivity hub (5+ connected edges) and a single point of failure. Disruption via targeted request flooding, connection exhaustion, or upstream WAF bypass would cascade across all dependent services.", "D-03", "Rules", "Open", [N_API_GW], [E1, E3, E4, E9, E10, E13]),
            ("T-008", "Elevation of Privilege", "Critical", "An attacker who compromises the API Gateway in the DMZ could pivot to the Authentication Service in the Internal Network, escalating from DMZ to PCI CDE access.", "E-02", "Rules", "Open", [N_API_GW, N_AUTH_SVC], [E3]),
            ("T-009", "Spoofing", "Medium", "The Third-Party Fintech API is an unauthenticated external entity that could be impersonated to inject fraudulent payment confirmations.", "S-03", "AI", "Open", [N_THIRD_PARTY], []),
            ("T-010", "Tampering", "High", "Race condition in concurrent payment processing: two simultaneous requests could exploit TOCTOU vulnerability in balance verification.", "AI-001", "AI", "Accepted", [N_CORE_BANK, N_CUSTOMER_DB], [E5]),
            ("T-011", "Spoofing", "Critical", "An attacker could bypass WAF rules using HTTP header smuggling to reach the API Gateway directly, bypassing rate limiting and input validation.", "AI-002", "AI", "Open", [N_WAF, N_API_GW], [E13]),
            ("T-012", "Elevation of Privilege", "High", "OAuth Authorization Server could be exploited via JWT algorithm confusion (alg:none downgrade) allowing token forgery without valid credentials.", "AI-003", "AI", "Open", [N_OAUTH_AS, N_AUTH_SVC], [E3, E14]),
            ("T-013", "Information Disclosure", "Critical", "Secrets Manager misconfiguration could expose database credentials and JWT signing keys if IAM role boundaries are not enforced between PCI Data Tier and Application Tier.", "AI-004", "AI", "Open", [N_SECRETS_MGR], [E11, E12]),
        ]

        for i, (did, stride, sev, desc, rule_id, source, status, node_ids, edge_ids) in enumerate(threats_data):
            threat = Threat(
                threat_model_id=DEMO_TM_ID,
                display_id=did,
                stride_category=stride,
                severity=sev,
                description=desc,
                rule_id=rule_id,
                source=source,
                status=status,
                dismiss_reason="Compensating control: TLS 1.3 mutual auth enforced at network layer" if status == "Dismissed" else None,
                ai_enhanced=source == "AI",
                affected_node_ids=node_ids,
                affected_edge_ids=edge_ids,
                threat_subtype=f"{stride} threat",
            )
            db.add(threat)

        await db.commit()
        logger.info("Demo data seeded: user=priya@example.test, model='Northstar Bank — Open Banking API Platform', 11 nodes, 15 edges, 5 trust boundaries, 13 threats")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(seed_demo())
