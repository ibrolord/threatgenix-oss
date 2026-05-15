from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent
from uuid import UUID

import fitz
import yaml

from tests.evals.scenario_aurora_utility_der import AURORA_UTILITY_DER_SCENARIO

def _node(
    node_id: str,
    node_type: str,
    name: str,
    position_x: float,
    position_y: float,
    *,
    trust_boundary_id: str | None = None,
    properties: dict | None = None,
) -> dict:
    return {
        "id": node_id,
        "node_type": node_type,
        "name": name,
        "position_x": position_x,
        "position_y": position_y,
        "trust_boundary_id": trust_boundary_id,
        "properties": properties or {},
    }


def _edge(edge_id: str, source_node_id: str, target_node_id: str, label: str) -> dict:
    return {
        "id": edge_id,
        "source_node_id": source_node_id,
        "target_node_id": target_node_id,
        "label": label,
    }


def _boundary(boundary_id: str, name: str, node_ids: list[str]) -> dict:
    return {"id": boundary_id, "name": name, "node_ids": node_ids}


SCENARIO_DEFINITIONS: dict[str, dict] = {
    "northstar_bank": {
        "metadata": {
            "scenario_id": "northstar_bank",
            "title": "NorthStar Bank Omnichannel Payments",
            "industry": "Financial services",
            "difficulty": "extreme",
            "analyst_persona": "Senior payments security architect supporting OSFI and PCI DSS readiness",
            "description": (
                "Hybrid Canadian banking payments platform with consumer, partner, "
                "treasury, fraud, AML, SWIFT, and tokenization paths crossing cloud "
                "and on-prem boundaries."
            ),
            "system_name": "NorthStar Omnichannel Payments Platform",
            "data_classification": "Restricted",
            "regulatory_scope": ["OSFI B-13", "PCI DSS", "PIPEDA", "FINTRAC"],
            "deployment_model": "hybrid",
            "critical_components": [
                "API Gateway",
                "Payments Orchestrator",
                "Fraud Scoring Engine",
                "AML Screening Service",
                "SWIFT Connector",
                "Core Banking Ledger",
                "Card Token Vault",
            ],
            "critical_flows": [
                "Consumer Mobile App -> API Gateway (OAuth2 + payment initiation)",
                "Open Banking Partner -> API Gateway (signed payment requests)",
                "Payments Orchestrator -> Core Banking Ledger (posting and balance updates)",
                "Payments Orchestrator -> SWIFT Connector (international payment messages)",
                "Payments Orchestrator -> Card Token Vault (PAN tokenization lookup)",
            ],
            "critical_boundaries": [
                "Customer and Partner Edge",
                "Payments Control Plane",
                "Restricted Data Zone",
            ],
            "narrative_doc": "narrative.pdf",
            "structured_doc": "structured.pdf",
            "delta_doc": "delta.pdf",
        },
        "documents": {
            "narrative": dedent(
                """
                NorthStar Bank has spent the last eighteen months consolidating retail,
                treasury, and partner payment initiation onto a single omnichannel
                payments platform. The platform is used by consumer mobile and web
                banking, commercial treasury operators, and third-party open banking
                partners. The edge is cloud-hosted, while the bank's core ledger,
                payment file archive, and some high-sensitivity services remain in the
                on-prem restricted zone.

                A customer or commercial operator begins at the API Gateway. The edge
                tier validates OAuth2 or signed partner credentials and routes payment
                requests into the Payments Orchestrator. The orchestrator assembles the
                instruction, enriches it with customer profile data, invokes the Fraud
                Scoring Engine and AML Screening Service, and chooses whether the
                payment is sent to RTR, Interac, internal ledger posting, or the SWIFT
                Connector for correspondent banking. PANs are never supposed to traverse
                the control plane un-tokenized; the orchestrator reaches into the Card
                Token Vault when card-linked disbursements are requested.

                Operationally, the platform is difficult because investigators can pull
                enriched cases in near real time, partner traffic bursts around payroll
                windows, and treasury users can approve high-value batches. The fraud
                team needs analyst notes and model outcomes preserved in Case Management,
                while the core banking team insists that final posting and account
                balance mutation happen only in the on-prem Core Banking Ledger.

                The bank also supports inbound status callbacks to open banking partners,
                and treasury operators can trigger payment repairs when screening or
                SWIFT formatting fails. Those repair paths are privileged and should not
                be treated like ordinary customer flows. Existing controls include mTLS
                on partner traffic, signed SWIFT payloads, and encryption at rest on the
                Card Token Vault and Core Banking Ledger. Gaps remain around privileged
                repair workflows, callback trust, case-management exposure of sensitive
                narratives, and misuse of screening overrides during operational stress.
                """
            ).strip(),
            "structured": dedent(
                """
                System: NorthStar Omnichannel Payments Platform
                Classification: Restricted
                Deployment: Hybrid cloud edge plus on-prem restricted zone
                Regulatory Scope: OSFI B-13, PCI DSS, PIPEDA, FINTRAC

                Trust Boundary: Customer and Partner Edge
                Contains:
                - Consumer Mobile App [external_entity]
                - Open Banking Partner [external_entity]
                - Treasury Portal User [external_entity]
                - API Gateway [process]

                Trust Boundary: Payments Control Plane
                Contains:
                - Payments Orchestrator [process]
                - Fraud Scoring Engine [process]
                - AML Screening Service [process]
                - SWIFT Connector [process]

                Trust Boundary: Restricted Data Zone
                Contains:
                - Core Banking Ledger [data_store]
                - Card Token Vault [data_store]
                - Case Management Store [data_store]

                Data Flows:
                - Consumer Mobile App -> API Gateway: OAuth2 + payment initiation
                - Open Banking Partner -> API Gateway: mTLS signed payment request
                - Treasury Portal User -> API Gateway: privileged batch approval
                - API Gateway -> Payments Orchestrator: normalized payment instruction
                - Payments Orchestrator -> Fraud Scoring Engine: transaction scoring request
                - Payments Orchestrator -> AML Screening Service: sanctions screening request
                - Payments Orchestrator -> SWIFT Connector: signed SWIFT payment message
                - Payments Orchestrator -> Core Banking Ledger: posting and balance update
                - Payments Orchestrator -> Card Token Vault: tokenization lookup
                - Fraud Scoring Engine -> Case Management Store: investigation case record
                - Payments Orchestrator -> Open Banking Partner: payment status callback

                Security Properties:
                - API Gateway: internet_facing=true, uses_auth=true, validates_input=true, uses_encryption=true
                - Payments Orchestrator: handles_sensitive_data=true, uses_encryption=true
                - Core Banking Ledger: encrypted_at_rest=true, has_backup=true
                - Card Token Vault: stores_credentials=true, encrypted_at_rest=true
                - Open Banking Partner: authenticated=true, trusted=true
                """
            ).strip(),
            "delta": dedent(
                """
                Change Request: NorthStar payroll aggregator expansion

                Two material changes are being introduced:
                1. A Payroll Aggregator Partner will be onboarded to submit bulk payroll
                   files via the existing edge. The aggregator receives asynchronous
                   callbacks and can request replay of failed batches.
                2. Treasury Repair Console access is being delegated to a small
                   operations team that can override AML holds and resubmit SWIFT
                   messages under emergency change procedures.

                New/changed components:
                - Payroll Aggregator Partner [external_entity]
                - Treasury Repair Console [process]

                New/changed flows:
                - Payroll Aggregator Partner -> API Gateway: bulk payroll file submission
                - Payments Orchestrator -> Payroll Aggregator Partner: payroll batch callback
                - Treasury Portal User -> Treasury Repair Console: privileged repair session
                - Treasury Repair Console -> Payments Orchestrator: repair override and replay
                - Treasury Repair Console -> SWIFT Connector: message repair submission
                """
            ).strip(),
        },
        "gold_dfd": {
            "nodes": [
                _node("6fc299aa-9df0-4c0e-b705-7b8d33f60fa1", "external_entity", "Consumer Mobile App", 0, 40, properties={"internet_facing": True}),
                _node("ff59b6d7-6cb0-48ca-a498-8a7f51fd7b86", "external_entity", "Open Banking Partner", 0, 180, properties={"trusted": True, "authenticated": True, "internet_facing": True}),
                _node("9a8e6676-6ad4-4625-9be8-6e5b8013c89f", "external_entity", "Treasury Portal User", 0, 320, properties={"authenticated": True}),
                _node("ce95b689-96f8-47cc-af99-c5914d724db9", "process", "API Gateway", 260, 160, trust_boundary_id="80e99dc9-dcdb-4d72-9a16-f52dcf9beeb7", properties={"internet_facing": True, "uses_auth": True, "validates_input": True, "uses_encryption": True}),
                _node("c592eec8-5347-4c2f-8f6b-cf1326d8976f", "process", "Payments Orchestrator", 520, 160, trust_boundary_id="31022756-ee22-4a46-8fa1-62b8b9b4ef92", properties={"handles_sensitive_data": True, "uses_encryption": True}),
                _node("bc54bf5b-371c-4f5a-90e4-15c11d24dd47", "process", "Fraud Scoring Engine", 760, 40, trust_boundary_id="31022756-ee22-4a46-8fa1-62b8b9b4ef92", properties={"handles_sensitive_data": True}),
                _node("6568787f-8d49-4d18-91a2-8bdfeb8ce027", "process", "AML Screening Service", 760, 160, trust_boundary_id="31022756-ee22-4a46-8fa1-62b8b9b4ef92", properties={"handles_sensitive_data": True}),
                _node("e40f1946-8834-49b9-bd84-f4c15ea30a7d", "process", "SWIFT Connector", 760, 280, trust_boundary_id="31022756-ee22-4a46-8fa1-62b8b9b4ef92", properties={"uses_encryption": True}),
                _node("d46c7b0e-e2d6-4b89-92f2-9c308754e665", "data_store", "Core Banking Ledger", 1020, 120, trust_boundary_id="d80af2ee-56f8-43f7-81b0-45fdd4fd59c2", properties={"encrypted_at_rest": True, "has_backup": True}),
                _node("9d151410-ac1f-4a83-8d4f-fcc3d7cf8f35", "data_store", "Card Token Vault", 1020, 220, trust_boundary_id="d80af2ee-56f8-43f7-81b0-45fdd4fd59c2", properties={"stores_credentials": True, "encrypted_at_rest": True}),
                _node("5eac611c-b6a5-4634-96b7-a619fd0abf86", "data_store", "Case Management Store", 1020, 20, trust_boundary_id="d80af2ee-56f8-43f7-81b0-45fdd4fd59c2", properties={"encrypted_at_rest": True, "has_backup": True}),
            ],
            "edges": [
                _edge("8013145f-32d2-49d1-a3db-06039a2d35ef", "6fc299aa-9df0-4c0e-b705-7b8d33f60fa1", "ce95b689-96f8-47cc-af99-c5914d724db9", "OAuth2 + payment initiation"),
                _edge("88a12f20-36e7-45c5-a1f7-f6fe68532b83", "ff59b6d7-6cb0-48ca-a498-8a7f51fd7b86", "ce95b689-96f8-47cc-af99-c5914d724db9", "mTLS signed payment request"),
                _edge("0043ae4b-0ab0-4c2e-ad4c-4f0fc519dc72", "9a8e6676-6ad4-4625-9be8-6e5b8013c89f", "ce95b689-96f8-47cc-af99-c5914d724db9", "privileged batch approval"),
                _edge("393c42d4-aa60-4b8b-b115-d329ab6d958f", "ce95b689-96f8-47cc-af99-c5914d724db9", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "normalized payment instruction"),
                _edge("ae961466-c3d7-430c-b997-bc6c29b0cbbc", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "bc54bf5b-371c-4f5a-90e4-15c11d24dd47", "transaction scoring request"),
                _edge("d9d99c5d-e112-4597-b4f2-5ca830bd480f", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "6568787f-8d49-4d18-91a2-8bdfeb8ce027", "sanctions screening request"),
                _edge("cb3599cc-8f92-4e6c-981e-a8a7f7504dfe", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "e40f1946-8834-49b9-bd84-f4c15ea30a7d", "signed SWIFT payment message"),
                _edge("35dd489b-6490-41a1-a6da-ebc8131b6e3d", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "d46c7b0e-e2d6-4b89-92f2-9c308754e665", "posting and balance update"),
                _edge("81afbde8-c35b-4330-8a44-b6f4005133e2", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "9d151410-ac1f-4a83-8d4f-fcc3d7cf8f35", "tokenization lookup"),
                _edge("957835b5-44d5-4c63-a0e2-cd40c10bd05a", "bc54bf5b-371c-4f5a-90e4-15c11d24dd47", "5eac611c-b6a5-4634-96b7-a619fd0abf86", "investigation case record"),
                _edge("cae2b753-f7eb-441d-b720-24a9961f8151", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "ff59b6d7-6cb0-48ca-a498-8a7f51fd7b86", "payment status callback"),
            ],
            "trust_boundaries": [
                _boundary("80e99dc9-dcdb-4d72-9a16-f52dcf9beeb7", "Customer and Partner Edge", ["ce95b689-96f8-47cc-af99-c5914d724db9"]),
                _boundary("31022756-ee22-4a46-8fa1-62b8b9b4ef92", "Payments Control Plane", ["c592eec8-5347-4c2f-8f6b-cf1326d8976f", "bc54bf5b-371c-4f5a-90e4-15c11d24dd47", "6568787f-8d49-4d18-91a2-8bdfeb8ce027", "e40f1946-8834-49b9-bd84-f4c15ea30a7d"]),
                _boundary("d80af2ee-56f8-43f7-81b0-45fdd4fd59c2", "Restricted Data Zone", ["d46c7b0e-e2d6-4b89-92f2-9c308754e665", "9d151410-ac1f-4a83-8d4f-fcc3d7cf8f35", "5eac611c-b6a5-4634-96b7-a619fd0abf86"]),
            ],
        },
        "gold_threat_themes": {
            "critical_themes": [
                {"id": "NSTAR-01", "title": "Partner callback spoofing", "description": "A forged partner callback or replay can corrupt payment status and customer notification state.", "severity": "High", "stride_categories": ["Spoofing", "Tampering"], "affected_assets": ["API Gateway", "Payments Orchestrator"]},
                {"id": "NSTAR-02", "title": "Privileged repair workflow abuse", "description": "Emergency repair or override flows can bypass AML or payment approval controls.", "severity": "Critical", "stride_categories": ["Elevation of Privilege", "Tampering"], "affected_assets": ["Payments Orchestrator", "SWIFT Connector"]},
                {"id": "NSTAR-03", "title": "SWIFT message manipulation", "description": "An attacker who reaches the SWIFT path can alter cross-border payment instructions or beneficiary data.", "severity": "Critical", "stride_categories": ["Tampering", "Repudiation"], "affected_assets": ["SWIFT Connector"]},
                {"id": "NSTAR-04", "title": "Token vault exposure", "description": "Improper access to tokenization services can expose PAN-derived data or enable fraudulent detokenization.", "severity": "Critical", "stride_categories": ["Information Disclosure", "Elevation of Privilege"], "affected_assets": ["Card Token Vault"]},
                {"id": "NSTAR-05", "title": "Case data leakage", "description": "Fraud investigation notes and enriched case narratives can expose highly sensitive payment or identity details.", "severity": "High", "stride_categories": ["Information Disclosure"], "affected_assets": ["Case Management Store"]},
                {"id": "NSTAR-06", "title": "Core ledger integrity failure", "description": "Posting or replay logic errors can result in double posting, out-of-balance accounts, or unreconciled ledger state.", "severity": "Critical", "stride_categories": ["Tampering", "Denial of Service"], "affected_assets": ["Core Banking Ledger"]},
                {"id": "NSTAR-07", "title": "Fraud/AML override drift", "description": "Operational pressure can lead to misuse of investigation or screening override functions.", "severity": "High", "stride_categories": ["Elevation of Privilege", "Repudiation"], "affected_assets": ["Fraud Scoring Engine", "AML Screening Service"]},
                {"id": "NSTAR-08", "title": "High-volume partner flood", "description": "Payroll or partner bursts can overwhelm synchronous scoring and screening dependencies.", "severity": "High", "stride_categories": ["Denial of Service"], "affected_assets": ["API Gateway", "Payments Orchestrator"]},
            ],
            "important_themes": [
                {"id": "NSTAR-09", "title": "Treasury impersonation risk", "description": "Treasury sessions represent high-value operator identities and batch approval capability.", "severity": "High", "stride_categories": ["Spoofing"], "affected_assets": ["Treasury Portal User", "API Gateway"]},
                {"id": "NSTAR-10", "title": "Partner payload validation gaps", "description": "Malformed or malicious partner payloads can propagate into orchestration or screening pipelines.", "severity": "Medium", "stride_categories": ["Tampering"], "affected_assets": ["API Gateway"]},
                {"id": "NSTAR-11", "title": "Sensitive callback disclosure", "description": "Status callbacks can leak internal adjudication or failure details to external parties.", "severity": "Medium", "stride_categories": ["Information Disclosure"], "affected_assets": ["Open Banking Partner"]},
                {"id": "NSTAR-12", "title": "Scoring dependency outage", "description": "Fraud or AML service degradation can cause delayed posting or unsafe fail-open behavior.", "severity": "High", "stride_categories": ["Denial of Service"], "affected_assets": ["Fraud Scoring Engine", "AML Screening Service"]},
            ],
            "expected_stride_coverage": ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
            "critical_assets": ["Payments Orchestrator", "SWIFT Connector", "Core Banking Ledger", "Card Token Vault"],
            "critical_boundaries": ["Customer and Partner Edge", "Payments Control Plane", "Restricted Data Zone"],
            "top_severity_expectations": ["NSTAR-02", "NSTAR-03", "NSTAR-04", "NSTAR-06"],
            "must_not_hallucinate": [
                "Public blockchain settlement",
                "Smart contract exploit paths",
                "Consumer social media login",
                "Biometric edge sensor compromise",
            ],
        },
        "must_not_hallucinate": [
            "crypto wallet",
            "blockchain bridge",
            "ATM network switch",
            "physical branch teller workstation",
        ],
        "delta_patch": {
            "add_nodes": [
                _node("47e7238a-b24f-4358-8571-0c8f83ce5b08", "external_entity", "Payroll Aggregator Partner", 0, 420, properties={"trusted": True, "authenticated": True}),
                _node("900fd4d0-3f85-40b3-9d0a-7ddf92f3ab95", "process", "Treasury Repair Console", 760, 400, trust_boundary_id="31022756-ee22-4a46-8fa1-62b8b9b4ef92", properties={"uses_auth": True, "handles_sensitive_data": True}),
            ],
            "add_edges": [
                _edge("7a3d11a3-446d-49d8-bf2f-1967ba898f3e", "47e7238a-b24f-4358-8571-0c8f83ce5b08", "ce95b689-96f8-47cc-af99-c5914d724db9", "bulk payroll file submission"),
                _edge("9de8f76d-e58f-487f-a467-e051c860683d", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "47e7238a-b24f-4358-8571-0c8f83ce5b08", "payroll batch callback"),
                _edge("4215642b-0cdb-48cc-aee9-65f4ff59e5d9", "9a8e6676-6ad4-4625-9be8-6e5b8013c89f", "900fd4d0-3f85-40b3-9d0a-7ddf92f3ab95", "privileged repair session"),
                _edge("d4afcd96-f4a3-4258-bbc4-5dbff47de1e9", "900fd4d0-3f85-40b3-9d0a-7ddf92f3ab95", "c592eec8-5347-4c2f-8f6b-cf1326d8976f", "repair override and replay"),
                _edge("a62a8d3e-8b01-49d1-a1be-c9870499eb33", "900fd4d0-3f85-40b3-9d0a-7ddf92f3ab95", "e40f1946-8834-49b9-bd84-f4c15ea30a7d", "message repair submission"),
            ],
            "add_boundary_membership": {
                "Customer and Partner Edge": ["ce95b689-96f8-47cc-af99-c5914d724db9"],
                "Payments Control Plane": ["900fd4d0-3f85-40b3-9d0a-7ddf92f3ab95"],
            },
        },
    },
    "medledger_health": {
        "metadata": {
            "scenario_id": "medledger_health",
            "title": "MedLedger Health Exchange",
            "industry": "Healthcare",
            "difficulty": "extreme",
            "analyst_persona": "Principal healthcare threat analyst preparing for ransomware tabletop and privacy review",
            "description": (
                "Clinical integration platform joining patient portal, insurer APIs, "
                "PACS, lab results, vendor support, and break-glass workflows."
            ),
            "system_name": "MedLedger Clinical Exchange",
            "data_classification": "Restricted",
            "regulatory_scope": ["PIPEDA", "ISO 27001", "NIST"],
            "deployment_model": "hybrid",
            "critical_components": [
                "Identity Gateway",
                "Clinical Integration Bus",
                "Break-Glass Service",
                "Vendor Support Bastion",
                "Electronic Health Record Store",
                "PACS Archive",
                "Lab Results Repository",
            ],
            "critical_flows": [
                "Patient Portal User -> Identity Gateway (patient login and records access)",
                "Clinical Integration Bus -> Electronic Health Record Store (patient chart query)",
                "Clinical Integration Bus -> PACS Archive (imaging retrieval)",
                "Vendor Support Technician -> Vendor Support Bastion (privileged vendor session)",
                "Break-Glass Service -> Electronic Health Record Store (emergency override query)",
            ],
            "critical_boundaries": [
                "Patient and Partner Edge",
                "Clinical Operations Zone",
                "Restricted Clinical Data Zone",
            ],
            "narrative_doc": "narrative.pdf",
            "structured_doc": "structured.pdf",
            "delta_doc": "delta.pdf",
        },
        "documents": {
            "narrative": dedent(
                """
                MedLedger Clinical Exchange is the hospital group's shared integration
                backbone for patient portal access, insurer eligibility, imaging,
                laboratory distribution, and emergency break-glass access. The edge is
                internet-facing for patients and payer integrations, while clinical
                systems and archives remain in the restricted clinical data zone. The
                architecture has become difficult because vendor diagnostics, emergency
                access, and modern AI imaging pilots now touch the same trust fabric.

                Patients authenticate through the Identity Gateway and request records,
                appointments, and lab results through the Clinical Integration Bus. The
                bus orchestrates chart reads from the Electronic Health Record Store,
                retrieves imaging from the PACS Archive, and brokers insurer API traffic
                for authorizations and claims status. Break-glass access is provided by
                a dedicated Break-Glass Service with strong audit requirements, yet the
                service can reach clinical repositories when staff are under duress or
                during emergency care.

                The Vendor Support Bastion is the only approved path for remote vendor
                access. Support staff sometimes need temporary privileged sessions to
                imaging or lab infrastructure. The organization is anxious about
                ransomware propagation from vendor access, insider misuse of emergency
                overrides, and inadvertent disclosure of protected health information in
                support notes, AI outputs, or insurer callbacks.
                """
            ).strip(),
            "structured": dedent(
                """
                System: MedLedger Clinical Exchange
                Classification: Restricted
                Deployment: Hybrid
                Regulatory Scope: PIPEDA, ISO 27001, NIST

                Trust Boundary: Patient and Partner Edge
                Contains:
                - Identity Gateway [process]

                Trust Boundary: Clinical Operations Zone
                Contains:
                - Clinical Integration Bus [process]
                - Break-Glass Service [process]
                - Vendor Support Bastion [process]
                - Imaging AI Gateway [process]

                Trust Boundary: Restricted Clinical Data Zone
                Contains:
                - Electronic Health Record Store [data_store]
                - PACS Archive [data_store]
                - Lab Results Repository [data_store]

                Data Flows:
                - Patient Portal User -> Identity Gateway: patient login and records access
                - Identity Gateway -> Clinical Integration Bus: authenticated patient session
                - Clinical Integration Bus -> Electronic Health Record Store: patient chart query
                - Clinical Integration Bus -> PACS Archive: imaging retrieval
                - Clinical Integration Bus -> Lab Results Repository: laboratory results query
                - Insurer API -> Clinical Integration Bus: eligibility and claims status
                - Break-Glass Service -> Electronic Health Record Store: emergency override query
                - Vendor Support Technician -> Vendor Support Bastion: privileged vendor session
                - Vendor Support Bastion -> PACS Archive: diagnostics session
                - Clinical Integration Bus -> Imaging AI Gateway: imaging inference request
                """
            ).strip(),
            "delta": dedent(
                """
                Change Request: AI imaging pilot and remote diagnostics expansion

                The hospital is introducing two material changes:
                1. Imaging AI Gateway can now send selected studies to a third-party
                   imaging AI vendor for second-read support.
                2. Remote vendor diagnostics are being expanded so vendors can collect
                   PACS performance bundles and temporary logs during incidents.

                New/changed components:
                - Imaging AI Vendor [external_entity]
                - Diagnostics Bundle Store [data_store]

                New/changed flows:
                - Imaging AI Gateway -> Imaging AI Vendor: selected study inference payload
                - Vendor Support Bastion -> Diagnostics Bundle Store: diagnostic bundle write
                - Diagnostics Bundle Store -> Vendor Support Technician: bundle retrieval
                """
            ).strip(),
        },
        "gold_dfd": {
            "nodes": [
                _node("7cc6b86f-c07b-467d-9852-9c35aa4fa8cc", "external_entity", "Patient Portal User", 0, 20, properties={"internet_facing": True}),
                _node("0a4610d0-a558-4652-a4b2-1a7bb352b77f", "external_entity", "Insurer API", 0, 150, properties={"trusted": True, "authenticated": True}),
                _node("a488a58c-d07c-4aeb-8cd0-d81580b7dc4f", "external_entity", "Vendor Support Technician", 0, 280, properties={"authenticated": True}),
                _node("c6e91376-a59a-45ce-a54d-db62de564795", "process", "Identity Gateway", 250, 90, trust_boundary_id="3562f670-74c1-4722-8038-30db524fcd7f", properties={"internet_facing": True, "uses_auth": True, "validates_input": True, "uses_encryption": True}),
                _node("b4f44224-96a4-4ef6-8ed5-72b0ad5c9a5a", "process", "Clinical Integration Bus", 520, 90, trust_boundary_id="2b2498d1-b8b8-4de0-9b7c-112bb9230e5f", properties={"handles_sensitive_data": True, "uses_encryption": True}),
                _node("630e0e40-e8ec-44b7-b7a0-7808943ec4d7", "process", "Break-Glass Service", 520, 220, trust_boundary_id="2b2498d1-b8b8-4de0-9b7c-112bb9230e5f", properties={"uses_auth": True, "handles_sensitive_data": True}),
                _node("b50f5d6b-34d3-4501-b956-d6f597947930", "process", "Vendor Support Bastion", 520, 340, trust_boundary_id="2b2498d1-b8b8-4de0-9b7c-112bb9230e5f", properties={"uses_auth": True, "uses_encryption": True}),
                _node("859053d1-46aa-443c-9047-96249b02025d", "process", "Imaging AI Gateway", 760, 220, trust_boundary_id="2b2498d1-b8b8-4de0-9b7c-112bb9230e5f", properties={"handles_sensitive_data": True}),
                _node("5b9f1f3a-df5a-4d92-a618-3242ce647a92", "data_store", "Electronic Health Record Store", 1020, 60, trust_boundary_id="8db7eb56-2919-472f-b35c-c663ef1f0e80", properties={"encrypted_at_rest": True, "has_backup": True}),
                _node("6b3d7e46-5411-4b5f-bd92-d6c046dbd0f6", "data_store", "PACS Archive", 1020, 180, trust_boundary_id="8db7eb56-2919-472f-b35c-c663ef1f0e80", properties={"encrypted_at_rest": True, "has_backup": True}),
                _node("eb815d10-7dd1-4c0a-8fd3-64f1022cad09", "data_store", "Lab Results Repository", 1020, 300, trust_boundary_id="8db7eb56-2919-472f-b35c-c663ef1f0e80", properties={"encrypted_at_rest": True, "has_backup": True}),
            ],
            "edges": [
                _edge("eec95bf7-b9c3-4be3-b73e-306d79468da2", "7cc6b86f-c07b-467d-9852-9c35aa4fa8cc", "c6e91376-a59a-45ce-a54d-db62de564795", "patient login and records access"),
                _edge("053308a0-7696-4eba-894e-2233eb9c0c3e", "c6e91376-a59a-45ce-a54d-db62de564795", "b4f44224-96a4-4ef6-8ed5-72b0ad5c9a5a", "authenticated patient session"),
                _edge("8434bc20-d41f-46ec-b071-e6bd6edb99ad", "b4f44224-96a4-4ef6-8ed5-72b0ad5c9a5a", "5b9f1f3a-df5a-4d92-a618-3242ce647a92", "patient chart query"),
                _edge("4542f82e-9091-46f0-a1d0-76719b0cb0dd", "b4f44224-96a4-4ef6-8ed5-72b0ad5c9a5a", "6b3d7e46-5411-4b5f-bd92-d6c046dbd0f6", "imaging retrieval"),
                _edge("7f23df95-3d33-4bc7-b6db-a52b1ae4a08a", "b4f44224-96a4-4ef6-8ed5-72b0ad5c9a5a", "eb815d10-7dd1-4c0a-8fd3-64f1022cad09", "laboratory results query"),
                _edge("86ca29f4-eb64-49cc-8e75-a5b0fd91c790", "0a4610d0-a558-4652-a4b2-1a7bb352b77f", "b4f44224-96a4-4ef6-8ed5-72b0ad5c9a5a", "eligibility and claims status"),
                _edge("1c7aaf5c-2db0-4c29-a0a5-d5933c989c4b", "630e0e40-e8ec-44b7-b7a0-7808943ec4d7", "5b9f1f3a-df5a-4d92-a618-3242ce647a92", "emergency override query"),
                _edge("40216d7a-f1d8-4e29-9b0d-bf4d0448ee16", "a488a58c-d07c-4aeb-8cd0-d81580b7dc4f", "b50f5d6b-34d3-4501-b956-d6f597947930", "privileged vendor session"),
                _edge("987325d7-89ab-47bd-b653-650476117e38", "b50f5d6b-34d3-4501-b956-d6f597947930", "6b3d7e46-5411-4b5f-bd92-d6c046dbd0f6", "diagnostics session"),
                _edge("87f0ba6e-ee7d-4d35-b0f4-79b20b11da36", "b4f44224-96a4-4ef6-8ed5-72b0ad5c9a5a", "859053d1-46aa-443c-9047-96249b02025d", "imaging inference request"),
            ],
            "trust_boundaries": [
                _boundary("3562f670-74c1-4722-8038-30db524fcd7f", "Patient and Partner Edge", ["c6e91376-a59a-45ce-a54d-db62de564795"]),
                _boundary("2b2498d1-b8b8-4de0-9b7c-112bb9230e5f", "Clinical Operations Zone", ["b4f44224-96a4-4ef6-8ed5-72b0ad5c9a5a", "630e0e40-e8ec-44b7-b7a0-7808943ec4d7", "b50f5d6b-34d3-4501-b956-d6f597947930", "859053d1-46aa-443c-9047-96249b02025d"]),
                _boundary("8db7eb56-2919-472f-b35c-c663ef1f0e80", "Restricted Clinical Data Zone", ["5b9f1f3a-df5a-4d92-a618-3242ce647a92", "6b3d7e46-5411-4b5f-bd92-d6c046dbd0f6", "eb815d10-7dd1-4c0a-8fd3-64f1022cad09"]),
            ],
        },
        "gold_threat_themes": {
            "critical_themes": [
                {"id": "MED-01", "title": "Break-glass misuse", "description": "Emergency override capability can be abused for unjustified chart access.", "severity": "Critical", "stride_categories": ["Elevation of Privilege", "Repudiation"], "affected_assets": ["Break-Glass Service", "Electronic Health Record Store"]},
                {"id": "MED-02", "title": "Vendor ransomware ingress", "description": "Remote diagnostics can provide a path for ransomware or destructive tooling into clinical systems.", "severity": "Critical", "stride_categories": ["Tampering", "Denial of Service"], "affected_assets": ["Vendor Support Bastion", "PACS Archive"]},
                {"id": "MED-03", "title": "Patient record overexposure", "description": "Portal or integration queries can expose broader datasets than the requesting user should see.", "severity": "High", "stride_categories": ["Information Disclosure"], "affected_assets": ["Clinical Integration Bus", "Electronic Health Record Store"]},
                {"id": "MED-04", "title": "Insurer callback trust failure", "description": "Partner eligibility or claim callbacks can be spoofed or tampered with.", "severity": "High", "stride_categories": ["Spoofing", "Tampering"], "affected_assets": ["Clinical Integration Bus"]},
                {"id": "MED-05", "title": "Imaging AI privacy spill", "description": "Inference payloads can disclose patient identity or diagnostic details outside approved clinical use.", "severity": "High", "stride_categories": ["Information Disclosure"], "affected_assets": ["Imaging AI Gateway", "PACS Archive"]},
                {"id": "MED-06", "title": "Clinical archive outage", "description": "PACS or lab repository disruption can directly impact care continuity and emergency treatment.", "severity": "Critical", "stride_categories": ["Denial of Service"], "affected_assets": ["PACS Archive", "Lab Results Repository"]},
                {"id": "MED-07", "title": "Audit bypass in emergency mode", "description": "Under incident conditions the organization may fail to preserve adequate audit evidence for sensitive access.", "severity": "High", "stride_categories": ["Repudiation"], "affected_assets": ["Break-Glass Service", "Vendor Support Bastion"]},
            ],
            "important_themes": [
                {"id": "MED-08", "title": "Patient impersonation", "description": "Compromised patient sessions can expose records or authorize downstream actions.", "severity": "Medium", "stride_categories": ["Spoofing"], "affected_assets": ["Identity Gateway"]},
                {"id": "MED-09", "title": "Support note leakage", "description": "Diagnostic bundles or case notes can contain PHI or sensitive operational details.", "severity": "Medium", "stride_categories": ["Information Disclosure"], "affected_assets": ["Vendor Support Bastion"]},
                {"id": "MED-10", "title": "Data reconciliation drift", "description": "Async insurer or lab updates can desynchronize clinical state and payer state.", "severity": "Medium", "stride_categories": ["Tampering"], "affected_assets": ["Clinical Integration Bus"]},
                {"id": "MED-11", "title": "AI dependency backlog", "description": "Imaging pipeline congestion can delay patient care if inference becomes an operational dependency.", "severity": "High", "stride_categories": ["Denial of Service"], "affected_assets": ["Imaging AI Gateway"]},
            ],
            "expected_stride_coverage": ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
            "critical_assets": ["Electronic Health Record Store", "PACS Archive", "Break-Glass Service", "Vendor Support Bastion"],
            "critical_boundaries": ["Patient and Partner Edge", "Clinical Operations Zone", "Restricted Clinical Data Zone"],
            "top_severity_expectations": ["MED-01", "MED-02", "MED-06"],
            "must_not_hallucinate": [
                "Consumer ad-tech tracking pixel",
                "Cryptocurrency claims settlement",
                "Retail point-of-sale malware",
            ],
        },
        "must_not_hallucinate": [
            "smart home device",
            "social media account takeover",
            "shipping warehouse robotics",
            "public blockchain wallet",
        ],
        "delta_patch": {
            "add_nodes": [
                _node("72be6989-dbb9-47ba-a975-fd630e2ea147", "external_entity", "Imaging AI Vendor", 0, 420, properties={"trusted": False}),
                _node("7a8f61e2-c87e-4f8f-ba42-59c13d5bb3cc", "data_store", "Diagnostics Bundle Store", 1020, 420, trust_boundary_id="8db7eb56-2919-472f-b35c-c663ef1f0e80", properties={"encrypted_at_rest": True}),
            ],
            "add_edges": [
                _edge("f1f5b6c7-d03e-4c2e-b820-4c9c4fce52a6", "859053d1-46aa-443c-9047-96249b02025d", "72be6989-dbb9-47ba-a975-fd630e2ea147", "selected study inference payload"),
                _edge("50ca4bd5-acf5-4067-8b3c-d4dc3a1ec7cf", "b50f5d6b-34d3-4501-b956-d6f597947930", "7a8f61e2-c87e-4f8f-ba42-59c13d5bb3cc", "diagnostic bundle write"),
                _edge("622ce88e-9528-42db-a924-cd0eb6793e08", "7a8f61e2-c87e-4f8f-ba42-59c13d5bb3cc", "a488a58c-d07c-4aeb-8cd0-d81580b7dc4f", "bundle retrieval"),
            ],
            "add_boundary_membership": {
                "Patient and Partner Edge": [],
                "Clinical Operations Zone": [],
                "Restricted Clinical Data Zone": ["7a8f61e2-c87e-4f8f-ba42-59c13d5bb3cc"],
            },
        },
    },
    "gridforge_ot": {
        "metadata": {
            "scenario_id": "gridforge_ot",
            "title": "GridForge OT Telemetry and Maintenance Platform",
            "industry": "Industrial / operational technology",
            "difficulty": "extreme",
            "analyst_persona": "Lead OT security analyst preparing a remote maintenance risk review",
            "description": (
                "Industrial telemetry and maintenance platform spanning supplier "
                "portal, VPN jump hosts, plant DMZ, historian, field gateways, and "
                "predictive analytics."
            ),
            "system_name": "GridForge Plant Operations Platform",
            "data_classification": "Confidential",
            "regulatory_scope": ["NIST", "ISO 27001"],
            "deployment_model": "hybrid",
            "critical_components": [
                "VPN Gateway",
                "OT Jump Host",
                "Maintenance Orchestrator",
                "Telemetry Broker",
                "Plant Historian",
                "Field Gateway",
                "PLC Command Store",
            ],
            "critical_flows": [
                "Remote Maintenance Vendor -> VPN Gateway (remote maintenance tunnel)",
                "VPN Gateway -> OT Jump Host (interactive privileged session)",
                "Maintenance Orchestrator -> Field Gateway (maintenance job dispatch)",
                "Field Gateway -> Telemetry Broker (plant telemetry stream)",
                "Telemetry Broker -> Plant Historian (time-series archive write)",
            ],
            "critical_boundaries": [
                "External Access Zone",
                "Plant DMZ",
                "OT Core Zone",
            ],
            "narrative_doc": "narrative.pdf",
            "structured_doc": "structured.pdf",
            "delta_doc": "delta.pdf",
        },
        "documents": {
            "narrative": dedent(
                """
                GridForge Plant Operations Platform is the utility's control-adjacent
                platform for remote maintenance, supplier coordination, telemetry
                brokering, and predictive analytics. The environment is segmented into
                an external access zone, a plant DMZ, and the OT core where field
                gateways, command data, and the historian live. What makes this system
                difficult is that it mixes remote human access, high-volume telemetry,
                and maintenance automation with assets that can affect plant safety.

                Suppliers and remote maintenance vendors authenticate through a VPN
                Gateway and land on an OT Jump Host. Approved sessions are brokered to
                the Maintenance Orchestrator, which can dispatch jobs to Field Gateway
                nodes and request data from the Plant Historian. Telemetry from plant
                equipment streams through the Telemetry Broker, while predictive
                analytics run in the DMZ and consume selected historian or live data.

                Engineers are especially worried about remote maintenance abuse,
                manipulation of command or recipe data, denial of view into plant
                conditions, and lateral movement from contractor access into the OT
                core. Analytics are valuable, but they are not supposed to become a path
                for control commands into the plant.
                """
            ).strip(),
            "structured": dedent(
                """
                System: GridForge Plant Operations Platform
                Classification: Confidential
                Deployment: Hybrid
                Regulatory Scope: NIST, ISO 27001

                Trust Boundary: External Access Zone
                Contains:
                - Supplier Portal User [external_entity]
                - Remote Maintenance Vendor [external_entity]
                - Site Reliability Analyst [external_entity]
                - VPN Gateway [process]

                Trust Boundary: Plant DMZ
                Contains:
                - OT Jump Host [process]
                - Maintenance Orchestrator [process]
                - Telemetry Broker [process]
                - Predictive Analytics Service [process]

                Trust Boundary: OT Core Zone
                Contains:
                - Field Gateway [process]
                - Plant Historian [data_store]
                - PLC Command Store [data_store]

                Data Flows:
                - Remote Maintenance Vendor -> VPN Gateway: remote maintenance tunnel
                - Site Reliability Analyst -> VPN Gateway: emergency operator session
                - VPN Gateway -> OT Jump Host: interactive privileged session
                - OT Jump Host -> Maintenance Orchestrator: approved maintenance task
                - Maintenance Orchestrator -> Field Gateway: maintenance job dispatch
                - Field Gateway -> Telemetry Broker: plant telemetry stream
                - Telemetry Broker -> Plant Historian: time-series archive write
                - Predictive Analytics Service -> Plant Historian: analytics query
                - Maintenance Orchestrator -> PLC Command Store: command package staging
                - Supplier Portal User -> Maintenance Orchestrator: supplier work order upload
                """
            ).strip(),
            "delta": dedent(
                """
                Change Request: contractor access and streaming maintenance expansion

                Two changes are planned:
                1. Contractors will receive temporary remote access for calibration and
                   firmware support through the same VPN and jump host pattern.
                2. Predictive Analytics Service will begin consuming near-real-time
                   telemetry streams instead of only historian reads.

                New/changed components:
                - Contractor Technician [external_entity]
                - Stream Buffer [process]

                New/changed flows:
                - Contractor Technician -> VPN Gateway: temporary contractor remote access
                - Telemetry Broker -> Stream Buffer: live telemetry fan-out
                - Stream Buffer -> Predictive Analytics Service: near-real-time telemetry feed
                - Predictive Analytics Service -> Maintenance Orchestrator: maintenance recommendation
                """
            ).strip(),
        },
        "gold_dfd": {
            "nodes": [
                _node("e181d13c-a169-445d-ae32-85faf8ff3e67", "external_entity", "Supplier Portal User", 0, 30),
                _node("4ea9fd38-1357-4e32-b5c0-967a8664639e", "external_entity", "Remote Maintenance Vendor", 0, 160, properties={"authenticated": True}),
                _node("d5d1233c-1325-4cdc-b841-96dc77b80117", "external_entity", "Site Reliability Analyst", 0, 290, properties={"authenticated": True}),
                _node("7b76f5db-e5e9-4673-9146-f3ee9060ad6e", "process", "VPN Gateway", 250, 160, trust_boundary_id="b9674a0b-a4c5-43be-9d2e-f2e6f83bc40f", properties={"internet_facing": True, "uses_auth": True, "uses_encryption": True}),
                _node("ae8dfb2d-c7c8-48f3-a85e-cf07e38ba917", "process", "OT Jump Host", 520, 60, trust_boundary_id="5f62737f-c2d8-4ed8-8194-30ff0bfb4597", properties={"uses_auth": True}),
                _node("2489a2dc-0f37-498d-a5c1-0c5b2a852fc8", "process", "Maintenance Orchestrator", 520, 200, trust_boundary_id="5f62737f-c2d8-4ed8-8194-30ff0bfb4597", properties={"uses_auth": True}),
                _node("7ebd3489-f44d-40c7-bd0f-1e42ef59f5b7", "process", "Telemetry Broker", 520, 340, trust_boundary_id="5f62737f-c2d8-4ed8-8194-30ff0bfb4597", properties={"uses_encryption": True}),
                _node("cfbfae80-db06-47ff-b315-aac55ed4ea07", "process", "Predictive Analytics Service", 780, 340, trust_boundary_id="5f62737f-c2d8-4ed8-8194-30ff0bfb4597", properties={"handles_sensitive_data": True}),
                _node("d191d851-b416-472b-9235-9a7252368ae2", "process", "Field Gateway", 1040, 200, trust_boundary_id="0a25ba1c-b8a5-4be9-9307-37838d10078d", properties={"uses_auth": True}),
                _node("7ce25864-aacf-49c1-bd0c-a04d6d85071b", "data_store", "Plant Historian", 1040, 60, trust_boundary_id="0a25ba1c-b8a5-4be9-9307-37838d10078d", properties={"encrypted_at_rest": True, "has_backup": True}),
                _node("37f45db1-b6bc-4434-bb6d-90c4d4f8c0cb", "data_store", "PLC Command Store", 1040, 340, trust_boundary_id="0a25ba1c-b8a5-4be9-9307-37838d10078d", properties={"encrypted_at_rest": True, "has_backup": True}),
            ],
            "edges": [
                _edge("9309ec06-8cfb-4379-bfc9-ec091cc66e63", "4ea9fd38-1357-4e32-b5c0-967a8664639e", "7b76f5db-e5e9-4673-9146-f3ee9060ad6e", "remote maintenance tunnel"),
                _edge("37ad0580-af49-4f4f-a2ba-e30f1ef653ef", "d5d1233c-1325-4cdc-b841-96dc77b80117", "7b76f5db-e5e9-4673-9146-f3ee9060ad6e", "emergency operator session"),
                _edge("327cfc65-e077-4241-a5c9-a02a1be06f6c", "7b76f5db-e5e9-4673-9146-f3ee9060ad6e", "ae8dfb2d-c7c8-48f3-a85e-cf07e38ba917", "interactive privileged session"),
                _edge("8c6501a8-8260-4ffb-a10c-c73377464db4", "ae8dfb2d-c7c8-48f3-a85e-cf07e38ba917", "2489a2dc-0f37-498d-a5c1-0c5b2a852fc8", "approved maintenance task"),
                _edge("9b7d8d1a-469e-44dd-bff3-48bedb528e5f", "2489a2dc-0f37-498d-a5c1-0c5b2a852fc8", "d191d851-b416-472b-9235-9a7252368ae2", "maintenance job dispatch"),
                _edge("fc5e5076-0160-4de5-a3f7-177fbafc9cc7", "d191d851-b416-472b-9235-9a7252368ae2", "7ebd3489-f44d-40c7-bd0f-1e42ef59f5b7", "plant telemetry stream"),
                _edge("33778247-6a7e-40a0-ac55-505dc8d39071", "7ebd3489-f44d-40c7-bd0f-1e42ef59f5b7", "7ce25864-aacf-49c1-bd0c-a04d6d85071b", "time-series archive write"),
                _edge("7826c1f7-3515-4b58-a862-b155ab954dda", "cfbfae80-db06-47ff-b315-aac55ed4ea07", "7ce25864-aacf-49c1-bd0c-a04d6d85071b", "analytics query"),
                _edge("24a5062c-94ec-48cb-8a43-aece731ac07e", "2489a2dc-0f37-498d-a5c1-0c5b2a852fc8", "37f45db1-b6bc-4434-bb6d-90c4d4f8c0cb", "command package staging"),
                _edge("4f5bc365-d35f-4bda-a7c2-2f086e7907f3", "e181d13c-a169-445d-ae32-85faf8ff3e67", "2489a2dc-0f37-498d-a5c1-0c5b2a852fc8", "supplier work order upload"),
            ],
            "trust_boundaries": [
                _boundary("b9674a0b-a4c5-43be-9d2e-f2e6f83bc40f", "External Access Zone", ["7b76f5db-e5e9-4673-9146-f3ee9060ad6e"]),
                _boundary("5f62737f-c2d8-4ed8-8194-30ff0bfb4597", "Plant DMZ", ["ae8dfb2d-c7c8-48f3-a85e-cf07e38ba917", "2489a2dc-0f37-498d-a5c1-0c5b2a852fc8", "7ebd3489-f44d-40c7-bd0f-1e42ef59f5b7", "cfbfae80-db06-47ff-b315-aac55ed4ea07"]),
                _boundary("0a25ba1c-b8a5-4be9-9307-37838d10078d", "OT Core Zone", ["d191d851-b416-472b-9235-9a7252368ae2", "7ce25864-aacf-49c1-bd0c-a04d6d85071b", "37f45db1-b6bc-4434-bb6d-90c4d4f8c0cb"]),
            ],
        },
        "gold_threat_themes": {
            "critical_themes": [
                {"id": "GRID-01", "title": "Remote maintenance privilege abuse", "description": "Interactive vendor access can be escalated into unauthorized control-adjacent actions.", "severity": "Critical", "stride_categories": ["Elevation of Privilege"], "affected_assets": ["VPN Gateway", "OT Jump Host", "Maintenance Orchestrator"]},
                {"id": "GRID-02", "title": "Command package tampering", "description": "Manipulation of staged command or recipe data can affect plant operations or safety.", "severity": "Critical", "stride_categories": ["Tampering"], "affected_assets": ["PLC Command Store", "Maintenance Orchestrator"]},
                {"id": "GRID-03", "title": "Loss of plant visibility", "description": "Telemetry or historian outage can blind operators to unsafe or unstable plant conditions.", "severity": "Critical", "stride_categories": ["Denial of Service"], "affected_assets": ["Telemetry Broker", "Plant Historian"]},
                {"id": "GRID-04", "title": "Contractor to OT-core pivot", "description": "External access paths can enable lateral movement from DMZ systems into field gateways.", "severity": "Critical", "stride_categories": ["Elevation of Privilege", "Tampering"], "affected_assets": ["OT Jump Host", "Field Gateway"]},
                {"id": "GRID-05", "title": "Telemetry integrity manipulation", "description": "Altered sensor streams can mislead analytics, operators, or maintenance workflows.", "severity": "High", "stride_categories": ["Tampering", "Repudiation"], "affected_assets": ["Telemetry Broker", "Predictive Analytics Service"]},
                {"id": "GRID-06", "title": "Supplier upload abuse", "description": "Supplier work orders can become a path for malicious payloads or unauthorized change requests.", "severity": "High", "stride_categories": ["Spoofing", "Tampering"], "affected_assets": ["Maintenance Orchestrator"]},
                {"id": "GRID-07", "title": "Historian data leakage", "description": "Operational telemetry can reveal plant capacity, incident state, or proprietary processes.", "severity": "High", "stride_categories": ["Information Disclosure"], "affected_assets": ["Plant Historian"]},
            ],
            "important_themes": [
                {"id": "GRID-08", "title": "Analytics trust erosion", "description": "Recommendations from predictive analytics may be over-trusted or insufficiently reviewed.", "severity": "Medium", "stride_categories": ["Repudiation", "Tampering"], "affected_assets": ["Predictive Analytics Service"]},
                {"id": "GRID-09", "title": "Emergency operator spoofing", "description": "High-stress emergency access can create identity assurance gaps.", "severity": "High", "stride_categories": ["Spoofing"], "affected_assets": ["Site Reliability Analyst", "VPN Gateway"]},
                {"id": "GRID-10", "title": "Field gateway overload", "description": "Maintenance bursts or malformed jobs can degrade field communications.", "severity": "High", "stride_categories": ["Denial of Service"], "affected_assets": ["Field Gateway"]},
                {"id": "GRID-11", "title": "DMZ analytics bypass", "description": "Analytics paths must not become covert write paths into OT control assets.", "severity": "High", "stride_categories": ["Elevation of Privilege"], "affected_assets": ["Predictive Analytics Service", "Maintenance Orchestrator"]},
            ],
            "expected_stride_coverage": ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
            "critical_assets": ["VPN Gateway", "OT Jump Host", "Field Gateway", "Plant Historian", "PLC Command Store"],
            "critical_boundaries": ["External Access Zone", "Plant DMZ", "OT Core Zone"],
            "top_severity_expectations": ["GRID-01", "GRID-02", "GRID-03", "GRID-04"],
            "must_not_hallucinate": [
                "Consumer mobile ad tracking",
                "Hospital patient portal",
                "Retail checkout skimmer",
            ],
        },
        "must_not_hallucinate": [
            "email marketing workflow",
            "social media influencer portal",
            "consumer mobile wallet",
            "public SaaS HR database",
        ],
        "delta_patch": {
            "add_nodes": [
                _node("2854ec85-c9d2-486c-ab22-f0956cfbb17e", "external_entity", "Contractor Technician", 0, 420, properties={"authenticated": True}),
                _node("f4817af3-a338-43bd-b463-b4a899b0be70", "process", "Stream Buffer", 780, 420, trust_boundary_id="5f62737f-c2d8-4ed8-8194-30ff0bfb4597", properties={"uses_encryption": True}),
            ],
            "add_edges": [
                _edge("77d30c3a-4aa8-41fa-a032-2b4e54c9570f", "2854ec85-c9d2-486c-ab22-f0956cfbb17e", "7b76f5db-e5e9-4673-9146-f3ee9060ad6e", "temporary contractor remote access"),
                _edge("43f7fac7-168e-4703-9dca-3d22df9d9972", "7ebd3489-f44d-40c7-bd0f-1e42ef59f5b7", "f4817af3-a338-43bd-b463-b4a899b0be70", "live telemetry fan-out"),
                _edge("ba84fb59-c372-494e-94a1-c505f2a0b070", "f4817af3-a338-43bd-b463-b4a899b0be70", "cfbfae80-db06-47ff-b315-aac55ed4ea07", "near-real-time telemetry feed"),
                _edge("03dfd0b8-2189-4f1f-ae6c-14bd2a672bc0", "cfbfae80-db06-47ff-b315-aac55ed4ea07", "2489a2dc-0f37-498d-a5c1-0c5b2a852fc8", "maintenance recommendation"),
            ],
            "add_boundary_membership": {
                "Plant DMZ": ["f4817af3-a338-43bd-b463-b4a899b0be70"],
            },
        },
    },
    "skybridge_airline_ops": {
        "metadata": {
            "scenario_id": "skybridge_airline_ops",
            "title": "SkyBridge Airways Integrated Flight Operations, Maintenance, and Turnaround Control Platform",
            "industry": "Commercial aviation",
            "difficulty": "extreme",
            "analyst_persona": "Principal airline operations threat analyst preparing a safety and operational-resilience review",
            "description": (
                "Hybrid airline operations-control platform spanning dispatch release, "
                "crew recovery, maintenance deferrals, turnaround readiness, EFB "
                "synchronization, vendor support, and immutable operational records."
            ),
            "system_name": "SkyBridge Airways Flight Operations and Maintenance Control Platform",
            "data_classification": "Restricted",
            "regulatory_scope": ["ISO 27001", "NIST"],
            "deployment_model": "hybrid",
            "critical_components": [
                "Dispatch Release Service",
                "Maintenance Control Service",
                "Turnaround Coordination Service",
                "Crew Recovery Engine",
                "Privileged Access Broker",
                "Records Retention Vault",
                "EFB Sync Service",
            ],
            "critical_flows": [
                "Ground Handler Partner API -> Turnaround Coordination Service (turnaround milestone update)",
                "Aircraft Health Feed -> Maintenance Control Service (aircraft health alert)",
                "Turnaround Coordination Service -> Dispatch Release Service (turnaround readiness state)",
                "Dispatch Release Service -> Audit and Decision Log (dispatch decision record)",
                "Audit and Decision Log -> Records Retention Vault (immutable record replication)",
            ],
            "critical_boundaries": [
                "Corporate Identity and Core Records Boundary",
                "Cloud Operations Platform Boundary",
                "Vendor Support and Security Boundary",
            ],
            "narrative_doc": "narrative.pdf",
            "structured_doc": "structured.pdf",
            "delta_doc": "delta.pdf",
        },
        "documents": {
            "narrative": dedent(
                """
                SkyBridge Airways is a full-service international airline replacing several legacy
                operations tools with a unified Flight Operations and Maintenance Control Platform.
                The target state combines dispatch planning, crew assignment, aircraft routing,
                maintenance event tracking, minimum equipment list deferral workflows, turnaround
                status, and operational messaging into one enterprise workflow.

                The platform is used by dispatchers in the airline operations center, maintenance
                controllers, crew schedulers, station managers, safety investigators, and a small
                set of privileged reliability-engineering and vendor-support personnel. Flight crews
                interact with selected data through the airline's Electronic Flight Bag (EFB)
                synchronization service and receive dispatch releases, notices, and aircraft-specific
                status packages before departure. Airport station teams and contracted ground handlers
                use a restricted turnaround portal to update gate events, fueling completion,
                baggage loading milestones, de-icing status, and pushback readiness.

                The architecture is intentionally hybrid. Core identity, privileged access
                management, records retention, and several system-of-record databases remain on
                premises in airline data centers. Workflow applications, API mediation, rules
                processing, and analytics workloads run in a primary public cloud tenant with a warm
                standby region. The airline also depends on external providers for weather,
                flight-plan optimization, airport decision-making feeds, maintenance data, vendor
                support, and crew operational messaging.

                Several workflows are safety- and compliance-critical. Only authorized dispatchers
                can finalize flight releases, and those releases must incorporate weather, aircraft
                status, turnaround readiness, crew legality, and maintenance deferral state.
                Maintenance control can create and close engineering events, but only licensed
                controllers can approve selected return-to-service decisions. Crew schedulers can
                recover disruptions by reassigning pairings during irregular operations. These urgent
                override paths are exactly where airline leadership expects attackers to focus because
                they can bypass normal review steps when the network is already under pressure.

                A major concern is the boundary between operational truth and operational status
                updates. Ground handlers can submit turnaround events and exceptions through partner
                APIs. Maintenance vendors can upload health-monitoring alerts and recommended
                actions. ACARS and EFB channels can deliver aircraft-tail-specific information to
                crews. Auditors have repeatedly flagged that break-glass diagnostics, vendor support
                sessions, and emergency maintenance workflows are not consistently threat-modeled,
                especially when multiple systems disagree about aircraft status and operators rely on
                exception handling to keep flights moving.
                """
            ).strip(),
            "structured": dedent(
                """
                System Name: SkyBridge Airways Integrated Flight Operations, Maintenance, and Turnaround Control Platform
                Primary Objective:
                Provide a unified operational platform for flight dispatch, crew recovery, maintenance event control,
                turnaround coordination, EFB package synchronization, and regulated operational record retention.

                Trust Boundary: Corporate Identity and Core Records Boundary
                Contains:
                - Active Directory Forest [Process]
                - Federated Identity Service [Process]
                - Privileged Access Broker [Process]
                - Records Retention Vault [Data Store]
                - On-Prem Operational Mirror Database [Data Store]
                - Safety Investigation Workspace [Process]

                Trust Boundary: Cloud Operations Platform Boundary
                Contains:
                - API Gateway [Process]
                - Operations Workflow Service [Process]
                - Dispatch Release Service [Process]
                - Crew Recovery Engine [Process]
                - Maintenance Control Service [Process]
                - Turnaround Coordination Service [Process]
                - EFB Sync Service [Process]
                - Operational Messaging Service [Process]
                - Audit and Decision Log [Data Store]
                - Operations Data Lake [Data Store]
                - Rules and Policy Engine [Process]

                Trust Boundary: Airport and Station Operations Boundary
                Contains:
                - Station Operations Portal [Process]
                - Ground Handler Partner API [Process]
                - Fueling Status Adapter [Process]
                - De-Icing Status Adapter [Process]

                Trust Boundary: Aircraft and Crew Edge Boundary
                Contains:
                - Electronic Flight Bag Client [External Entity]
                - ACARS / Satcom Messaging Provider [External Entity]
                - Aircraft Health Feed [External Entity]

                Trust Boundary: External Aviation Services Boundary
                Contains:
                - Weather Intelligence Provider [External Entity]
                - Flight Plan Optimization Vendor [External Entity]
                - Airport CDM Feed [External Entity]
                - Civil Aviation Regulatory Exchange [External Entity]
                - Border / Crew Clearance Interface [External Entity]
                - MRO Vendor System [External Entity]

                Trust Boundary: Vendor Support and Security Boundary
                Contains:
                - Vendor Support Enclave [External Entity]
                - SOC Monitoring Platform [External Entity]
                - SIEM / Telemetry Pipeline [Process]

                Critical Assets:
                - Dispatch Release Package
                - Aircraft Tail Status
                - Maintenance Deferral State
                - Return-to-Service Approval
                - Crew Legality Status
                - Turnaround Readiness State
                - EFB Flight Folder
                - Audit and Decision Log
                - Break-Glass Approval Record

                Privileged Workflows:
                - Dispatcher finalizes flight release after reviewing weather, aircraft status, crew legality, and MEL constraints.
                - Maintenance controller creates engineering events and proposes deferrals.
                - Licensed maintenance supervisor approves selected deferrals and return-to-service decisions.
                - Crew recovery manager reassigns pairings during disruptions under legality constraints.
                - Reliability engineer opens break-glass diagnostics session through Privileged Access Broker.
                - Vendor support operator receives time-boxed diagnostic access after airline approval.
                - Safety investigator retrieves immutable decision records from Records Retention Vault.

                Security Properties:
                - Federated Identity Service: MFA required for workforce users; phishing-resistant MFA required for dispatch, maintenance control, and privileged roles
                - Privileged Access Broker: just-in-time elevation; time-boxed sessions; approval required for vendor support; session recording enabled
                - Audit and Decision Log: append-only application log; replicated to Records Retention Vault
                - Records Retention Vault: immutable retention controls; separate admin domain
                - EFB Sync Service: signed package manifest required before client synchronization
                - Operational Messaging Service: message integrity checks for provider handoff acknowledgements
                - Ground Handler Partner API: mTLS for partner integrations; event-level attribution required
                - Turnaround Coordination Service: role separation between station updates and maintenance authority
                - Dispatch Release Service: dual-condition approval for selected release exceptions
                - Maintenance Control Service: licensed-role check for return-to-service and selected MEL deferrals
                - Operations Data Lake: analytics-only replica; not authoritative for operational control
                - SIEM / Telemetry Pipeline: receives high-value audit events from dispatch, maintenance, crew recovery, and privileged access workflows

                Abuse Cases To Consider:
                - False turnaround readiness causing unsafe or non-compliant departure pressure
                - Manipulated maintenance deferral or return-to-service state
                - Crew legality override abuse during disruption recovery
                - Wrong-tail or stale dispatch package synchronized to pilot EFB
                - Unauthorized vendor diagnostic access during major incident response
                - Tampered health-feed or MRO updates causing incorrect maintenance decisions
                - Suppressed or altered audit trail for dispatch or maintenance actions
                - Abuse of emergency workflows to bypass normal segregation of duties
                """
            ).strip(),
            "delta": dedent(
                """
                Change Request: Irregular Operations escalation path expansion

                Two material changes are being introduced:
                1. An Irregular Operations Override Console will be added for major disruption recovery.
                   It can trigger emergency legality overrides and release exception reviews under explicit
                   approval from the Privileged Access Broker.
                2. A Remote Line Maintenance Tablet workflow will allow field maintenance staff to submit
                   remote return-to-service acknowledgements during severe weather and airport closure events.

                New or changed components:
                - Irregular Operations Override Console [Process]
                - Remote Line Maintenance Tablet [External Entity]

                New or changed flows:
                - Privileged Access Broker -> Irregular Operations Override Console: approved emergency support session
                - Irregular Operations Override Console -> Crew Recovery Engine: emergency legality override
                - Remote Line Maintenance Tablet -> Maintenance Control Service: remote return-to-service acknowledgement
                - Dispatch Release Service -> Electronic Flight Bag Client: release replay and wrong-tail package revalidation
                """
            ).strip(),
        },
        "gold_dfd": {
            "nodes": [
                _node("319af7de-6f4d-4711-bd7e-11d45a57111f", "process", "Federated Identity Service", 80, 40, trust_boundary_id="77bd8e75-f595-4d0a-aafd-b8107eb0b15d", properties={"uses_auth": True}),
                _node("0c78242d-6f4e-4d5d-a731-1ef7533dd66a", "process", "Privileged Access Broker", 320, 40, trust_boundary_id="77bd8e75-f595-4d0a-aafd-b8107eb0b15d", properties={"uses_auth": True}),
                _node("52a9dfdb-1d7f-4f79-b9ec-a117877ec19f", "data_store", "Records Retention Vault", 560, 40, trust_boundary_id="77bd8e75-f595-4d0a-aafd-b8107eb0b15d", properties={"encrypted_at_rest": True, "has_backup": True}),
                _node("3fd566d9-5b51-40dc-9d03-ea67ee1f3a7c", "data_store", "On-Prem Operational Mirror Database", 800, 40, trust_boundary_id="77bd8e75-f595-4d0a-aafd-b8107eb0b15d", properties={"encrypted_at_rest": True, "has_backup": True}),
                _node("0e45a6df-6016-4610-b594-1c63a8ae7f4a", "process", "Safety Investigation Workspace", 1040, 40, trust_boundary_id="77bd8e75-f595-4d0a-aafd-b8107eb0b15d"),
                _node("d8c33d0e-c262-4a8d-aec1-8a9cb9c1e4c5", "process", "API Gateway", 80, 220, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3", properties={"internet_facing": True, "uses_auth": True, "uses_encryption": True}),
                _node("477849dc-c0cb-4982-9ce2-7f69ff1f908e", "process", "Operations Workflow Service", 320, 220, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3"),
                _node("9fb81886-a52d-4f90-8527-b2785c7ebc4c", "process", "Dispatch Release Service", 560, 220, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3", properties={"handles_sensitive_data": True}),
                _node("bdc399df-f35e-4efa-8916-9e2bcfa085b1", "process", "Crew Recovery Engine", 800, 220, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3", properties={"handles_sensitive_data": True}),
                _node("4b3a68ad-2c73-48f8-96c6-658cdd906cdc", "process", "Maintenance Control Service", 1040, 220, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3", properties={"handles_sensitive_data": True}),
                _node("fd337053-b01f-49d9-bdd6-9d2af2d97763", "process", "Turnaround Coordination Service", 80, 400, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3"),
                _node("d0f935ff-01fe-42d5-a8c5-20d11e80d26f", "process", "EFB Sync Service", 320, 400, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3", properties={"uses_encryption": True}),
                _node("c1c38db7-2aa8-4fc2-b415-51da1735272c", "process", "Operational Messaging Service", 560, 400, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3"),
                _node("55abfc48-5a3d-443f-9516-c2246046ae3d", "data_store", "Audit and Decision Log", 800, 400, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3", properties={"encrypted_at_rest": True, "has_backup": True}),
                _node("3f50ab1e-fef6-4cfb-a973-cd81295d81e5", "data_store", "Operations Data Lake", 1040, 400, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3"),
                _node("0a74815f-68af-478c-b057-73fe179a7acd", "process", "Rules and Policy Engine", 1280, 400, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3"),
                _node("34d32b6e-4de5-4bdd-a1d6-d6defd40f2b6", "process", "Station Operations Portal", 80, 580, trust_boundary_id="7334d515-a9da-40eb-b8d8-19ab6c4dc4d0"),
                _node("2b79808d-c664-45bb-b3b4-7146a285f76d", "process", "Ground Handler Partner API", 320, 580, trust_boundary_id="7334d515-a9da-40eb-b8d8-19ab6c4dc4d0", properties={"uses_encryption": True}),
                _node("c50bcaf5-b00d-4b4e-91d0-021295b7651e", "external_entity", "Electronic Flight Bag Client", 560, 580, trust_boundary_id="f90b1662-bef5-4cac-8fb2-e80715f4d1b3"),
                _node("f95288ef-492d-4619-af7f-25c0f3e1137c", "external_entity", "ACARS / Satcom Messaging Provider", 800, 580, trust_boundary_id="f90b1662-bef5-4cac-8fb2-e80715f4d1b3"),
                _node("4d8cf6f6-39fb-4b67-98f1-9614159f2ffc", "external_entity", "Aircraft Health Feed", 1040, 580, trust_boundary_id="f90b1662-bef5-4cac-8fb2-e80715f4d1b3"),
                _node("2cb67d0b-f2f1-4655-a145-1d84f1ad1736", "external_entity", "Weather Intelligence Provider", 1280, 580, trust_boundary_id="1d3c2c2e-c307-4523-8b8c-bf7c40d6eedb"),
                _node("2a6da97f-c62e-42d0-a9e2-4c5e7634888d", "external_entity", "MRO Vendor System", 1520, 580, trust_boundary_id="1d3c2c2e-c307-4523-8b8c-bf7c40d6eedb"),
                _node("ee767592-60c7-4ab4-8f31-3f5f3f5b6fc3", "external_entity", "Vendor Support Enclave", 1760, 580, trust_boundary_id="33fd0b1f-e0b1-4fc4-9139-1270895ad59f", properties={"authenticated": True}),
                _node("d37bd381-fca6-4eb3-a6ff-f9a8220587cb", "external_entity", "SOC Monitoring Platform", 2000, 580, trust_boundary_id="33fd0b1f-e0b1-4fc4-9139-1270895ad59f"),
                _node("488bf7e2-57dc-49a5-b6ee-3cbdd2785b88", "process", "SIEM / Telemetry Pipeline", 2240, 580, trust_boundary_id="33fd0b1f-e0b1-4fc4-9139-1270895ad59f"),
            ],
            "edges": [
                _edge("049fca9c-dba6-47d4-ae5b-f65daa3f8992", "319af7de-6f4d-4711-bd7e-11d45a57111f", "0c78242d-6f4e-4d5d-a731-1ef7533dd66a", "workforce MFA assertion"),
                _edge("244fd94f-b428-48cf-b9d0-32ad2c625c83", "d8c33d0e-c262-4a8d-aec1-8a9cb9c1e4c5", "477849dc-c0cb-4982-9ce2-7f69ff1f908e", "normalized flight operations workflow"),
                _edge("a5f0c0da-56ef-4ef6-a8af-9137d219a6ca", "477849dc-c0cb-4982-9ce2-7f69ff1f908e", "9fb81886-a52d-4f90-8527-b2785c7ebc4c", "flight release workflow"),
                _edge("59e9300d-616f-4048-8ca1-3c7df73fc5c9", "477849dc-c0cb-4982-9ce2-7f69ff1f908e", "bdc399df-f35e-4efa-8916-9e2bcfa085b1", "disruption recovery action"),
                _edge("37fd91f3-53e5-4db7-b755-fb6efed4ab03", "2b79808d-c664-45bb-b3b4-7146a285f76d", "fd337053-b01f-49d9-bdd6-9d2af2d97763", "turnaround milestone update"),
                _edge("7449512a-84c1-4c39-bbe9-6a53ca0b585f", "34d32b6e-4de5-4bdd-a1d6-d6defd40f2b6", "fd337053-b01f-49d9-bdd6-9d2af2d97763", "station readiness update"),
                _edge("e71338d8-f875-47e4-b04a-b9f70b77f2b0", "fd337053-b01f-49d9-bdd6-9d2af2d97763", "9fb81886-a52d-4f90-8527-b2785c7ebc4c", "turnaround readiness state"),
                _edge("6cebdb93-cfbb-4d02-8057-ef72a61582f8", "2cb67d0b-f2f1-4655-a145-1d84f1ad1736", "9fb81886-a52d-4f90-8527-b2785c7ebc4c", "weather and NOTAM package"),
                _edge("769eec56-580c-48f4-8eb7-bd012fdd0d48", "4d8cf6f6-39fb-4b67-98f1-9614159f2ffc", "4b3a68ad-2c73-48f8-96c6-658cdd906cdc", "aircraft health alert"),
                _edge("0fb34162-b935-4046-b3c7-18b9187ca9bf", "2a6da97f-c62e-42d0-a9e2-4c5e7634888d", "4b3a68ad-2c73-48f8-96c6-658cdd906cdc", "maintenance recommendation upload"),
                _edge("a49ae0fd-0995-4ef5-bd2a-f754667744fc", "9fb81886-a52d-4f90-8527-b2785c7ebc4c", "55abfc48-5a3d-443f-9516-c2246046ae3d", "dispatch decision record"),
                _edge("d87362cb-5007-42a8-b1f1-cec2f1622c38", "4b3a68ad-2c73-48f8-96c6-658cdd906cdc", "55abfc48-5a3d-443f-9516-c2246046ae3d", "maintenance deferral decision"),
                _edge("78346899-b1c8-4c18-9edf-f49099788b75", "55abfc48-5a3d-443f-9516-c2246046ae3d", "52a9dfdb-1d7f-4f79-b9ec-a117877ec19f", "immutable record replication"),
                _edge("e2218782-0eb1-4262-bc4c-46a3ad60f7bf", "d0f935ff-01fe-42d5-a8c5-20d11e80d26f", "c50bcaf5-b00d-4b4e-91d0-021295b7651e", "dispatch release package"),
                _edge("f3c85cd4-5444-4d9c-b4a2-c19b14d16b4e", "c1c38db7-2aa8-4fc2-b415-51da1735272c", "f95288ef-492d-4619-af7f-25c0f3e1137c", "crew operational message"),
                _edge("8bb5d6db-e143-47e3-8d8e-f8e5e5060c90", "0c78242d-6f4e-4d5d-a731-1ef7533dd66a", "ee767592-60c7-4ab4-8f31-3f5f3f5b6fc3", "approved time-boxed diagnostic session"),
                _edge("917d6ca6-f2ca-47a9-b938-a86925702eab", "ee767592-60c7-4ab4-8f31-3f5f3f5b6fc3", "477849dc-c0cb-4982-9ce2-7f69ff1f908e", "vendor diagnostic query"),
                _edge("46f64eb2-2142-476b-b943-a564a940d41d", "0a74815f-68af-478c-b057-73fe179a7acd", "9fb81886-a52d-4f90-8527-b2785c7ebc4c", "release rule evaluation"),
                _edge("96a95d30-7f4a-4753-9252-f647d4c726d6", "488bf7e2-57dc-49a5-b6ee-3cbdd2785b88", "d37bd381-fca6-4eb3-a6ff-f9a8220587cb", "security telemetry feed"),
            ],
            "trust_boundaries": [
                _boundary("77bd8e75-f595-4d0a-aafd-b8107eb0b15d", "Corporate Identity and Core Records Boundary", ["319af7de-6f4d-4711-bd7e-11d45a57111f", "0c78242d-6f4e-4d5d-a731-1ef7533dd66a", "52a9dfdb-1d7f-4f79-b9ec-a117877ec19f", "3fd566d9-5b51-40dc-9d03-ea67ee1f3a7c", "0e45a6df-6016-4610-b594-1c63a8ae7f4a"]),
                _boundary("55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3", "Cloud Operations Platform Boundary", ["d8c33d0e-c262-4a8d-aec1-8a9cb9c1e4c5", "477849dc-c0cb-4982-9ce2-7f69ff1f908e", "9fb81886-a52d-4f90-8527-b2785c7ebc4c", "bdc399df-f35e-4efa-8916-9e2bcfa085b1", "4b3a68ad-2c73-48f8-96c6-658cdd906cdc", "fd337053-b01f-49d9-bdd6-9d2af2d97763", "d0f935ff-01fe-42d5-a8c5-20d11e80d26f", "c1c38db7-2aa8-4fc2-b415-51da1735272c", "55abfc48-5a3d-443f-9516-c2246046ae3d", "3f50ab1e-fef6-4cfb-a973-cd81295d81e5", "0a74815f-68af-478c-b057-73fe179a7acd"]),
                _boundary("7334d515-a9da-40eb-b8d8-19ab6c4dc4d0", "Airport and Station Operations Boundary", ["34d32b6e-4de5-4bdd-a1d6-d6defd40f2b6", "2b79808d-c664-45bb-b3b4-7146a285f76d"]),
                _boundary("f90b1662-bef5-4cac-8fb2-e80715f4d1b3", "Aircraft and Crew Edge Boundary", ["c50bcaf5-b00d-4b4e-91d0-021295b7651e", "f95288ef-492d-4619-af7f-25c0f3e1137c", "4d8cf6f6-39fb-4b67-98f1-9614159f2ffc"]),
                _boundary("1d3c2c2e-c307-4523-8b8c-bf7c40d6eedb", "External Aviation Services Boundary", ["2cb67d0b-f2f1-4655-a145-1d84f1ad1736", "2a6da97f-c62e-42d0-a9e2-4c5e7634888d"]),
                _boundary("33fd0b1f-e0b1-4fc4-9139-1270895ad59f", "Vendor Support and Security Boundary", ["ee767592-60c7-4ab4-8f31-3f5f3f5b6fc3", "d37bd381-fca6-4eb3-a6ff-f9a8220587cb", "488bf7e2-57dc-49a5-b6ee-3cbdd2785b88"]),
            ],
        },
        "gold_threat_themes": {
            "critical_themes": [
                {"id": "SKY-01", "title": "Unsafe dispatch from tampered aircraft or maintenance state", "description": "Incorrect aircraft-tail status, maintenance state, or turnaround readiness can drive release of an aircraft under invalid conditions.", "severity": "Critical", "stride_categories": ["Tampering"], "affected_assets": ["Dispatch Release Service", "Maintenance Control Service"]},
                {"id": "SKY-02", "title": "Break-glass or vendor-support abuse", "description": "Emergency diagnostics and vendor-support paths can bypass normal controls and grant leverage over dispatch or maintenance workflows.", "severity": "Critical", "stride_categories": ["Elevation of Privilege"], "affected_assets": ["Privileged Access Broker", "Vendor Support Enclave"]},
                {"id": "SKY-03", "title": "False turnaround readiness", "description": "Semi-trusted partner and station updates can create unsafe departure pressure or conceal incomplete critical tasks.", "severity": "Critical", "stride_categories": ["Tampering", "Spoofing"], "affected_assets": ["Turnaround Coordination Service", "Dispatch Release Service"]},
                {"id": "SKY-04", "title": "Wrong-tail or stale EFB package distribution", "description": "Crew decisions can be affected by incorrect release packages, notices, or aircraft-specific status data.", "severity": "High", "stride_categories": ["Information Disclosure", "Tampering"], "affected_assets": ["EFB Sync Service", "Electronic Flight Bag Client"]},
                {"id": "SKY-05", "title": "Crew legality and disruption-recovery manipulation", "description": "Business-logic abuse can force non-compliant crew assignments during irregular operations.", "severity": "High", "stride_categories": ["Elevation of Privilege", "Repudiation"], "affected_assets": ["Crew Recovery Engine"]},
                {"id": "SKY-06", "title": "Audit and decision-log suppression", "description": "Loss of trustworthy decision records undermines safety investigation, accountability, and regulatory defense.", "severity": "Critical", "stride_categories": ["Repudiation"], "affected_assets": ["Audit and Decision Log", "Records Retention Vault"]},
                {"id": "SKY-07", "title": "Tampered health-feed or MRO updates", "description": "Third-party operational inputs directly influence safety-relevant maintenance decisions.", "severity": "High", "stride_categories": ["Tampering"], "affected_assets": ["Maintenance Control Service", "Aircraft Health Feed", "MRO Vendor System"]},
                {"id": "SKY-08", "title": "Segregation-of-duties failure across operations roles", "description": "Dispatch, maintenance, station, and privileged roles must remain constrained to prevent unsafe operational control.", "severity": "High", "stride_categories": ["Elevation of Privilege"], "affected_assets": ["Station Operations Portal", "Maintenance Control Service", "Dispatch Release Service"]},
            ],
            "important_themes": [
                {"id": "SKY-09", "title": "Operational messaging integrity gaps", "description": "Provider acknowledgements and crew messages can be spoofed or altered during handoff.", "severity": "High", "stride_categories": ["Spoofing", "Tampering"], "affected_assets": ["Operational Messaging Service", "ACARS / Satcom Messaging Provider"]},
                {"id": "SKY-10", "title": "Analytics replica misuse", "description": "Analytics replicas can reveal sensitive operational state and inform fraud or disruption planning.", "severity": "Medium", "stride_categories": ["Information Disclosure"], "affected_assets": ["Operations Data Lake"]},
                {"id": "SKY-11", "title": "Weather or airport-feed manipulation", "description": "Manipulated external operational feeds can produce unsafe release or recovery decisions.", "severity": "High", "stride_categories": ["Tampering", "Denial of Service"], "affected_assets": ["Dispatch Release Service", "Weather Intelligence Provider"]},
                {"id": "SKY-12", "title": "Decision-record concealment by insiders", "description": "Investigative or retention systems can be abused to hide accountability after unsafe decisions.", "severity": "High", "stride_categories": ["Repudiation", "Elevation of Privilege"], "affected_assets": ["Safety Investigation Workspace", "Records Retention Vault"]},
            ],
            "expected_stride_coverage": ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
            "critical_assets": ["Dispatch Release Service", "Maintenance Control Service", "Turnaround Coordination Service", "EFB Sync Service", "Audit and Decision Log", "Records Retention Vault"],
            "critical_boundaries": ["Corporate Identity and Core Records Boundary", "Cloud Operations Platform Boundary", "Vendor Support and Security Boundary"],
            "top_severity_expectations": ["SKY-01", "SKY-02", "SKY-03", "SKY-06"],
            "must_not_hallucinate": [
                "In-flight consumer shopping cart",
                "Passenger loyalty social login",
                "Retail point-of-sale skimmer",
                "Hotel booking recommendation engine",
            ],
        },
        "must_not_hallucinate": [
            "consumer baggage-claim kiosk ad network",
            "in-flight entertainment DRM license server",
            "public social-media crisis console",
            "hotel or car-rental booking checkout flow",
        ],
        "delta_patch": {
            "add_nodes": [
                _node("1b9a8b23-8db4-45c7-8174-a1f6af8f5fe0", "process", "Irregular Operations Override Console", 1520, 220, trust_boundary_id="55ce2f2c-7bcb-4aa6-a892-3ac10c2b2dc3", properties={"uses_auth": True}),
                _node("af3bc2be-7ec9-4d7a-bc0f-881bb23bb6d2", "external_entity", "Remote Line Maintenance Tablet", 1760, 220, trust_boundary_id="f90b1662-bef5-4cac-8fb2-e80715f4d1b3", properties={"authenticated": True}),
            ],
            "add_edges": [
                _edge("3d0a6a3c-21cd-4eeb-8546-e8ef1cf03e76", "0c78242d-6f4e-4d5d-a731-1ef7533dd66a", "1b9a8b23-8db4-45c7-8174-a1f6af8f5fe0", "approved emergency support session"),
                _edge("f379d2af-4216-404d-acfc-68609cde6543", "1b9a8b23-8db4-45c7-8174-a1f6af8f5fe0", "bdc399df-f35e-4efa-8916-9e2bcfa085b1", "emergency legality override"),
                _edge("5ce773d6-e5a3-4d2f-b5e2-c44a328e393f", "af3bc2be-7ec9-4d7a-bc0f-881bb23bb6d2", "4b3a68ad-2c73-48f8-96c6-658cdd906cdc", "remote return-to-service acknowledgement"),
                _edge("d8d7fcec-b17a-4967-b6af-4c7d5b1e2ef7", "9fb81886-a52d-4f90-8527-b2785c7ebc4c", "c50bcaf5-b00d-4b4e-91d0-021295b7651e", "release replay and wrong-tail package revalidation"),
            ],
            "add_boundary_membership": {
                "Cloud Operations Platform Boundary": ["1b9a8b23-8db4-45c7-8174-a1f6af8f5fe0"],
                "Aircraft and Crew Edge Boundary": ["af3bc2be-7ec9-4d7a-bc0f-881bb23bb6d2"],
            },
        },
    },
}

SCENARIO_DEFINITIONS[AURORA_UTILITY_DER_SCENARIO["metadata"]["scenario_id"]] = AURORA_UTILITY_DER_SCENARIO


def _write_yaml(path: Path, data: dict | list) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _write_json(path: Path, data: dict | list) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _write_pdf(path: Path, title: str, body: str) -> None:
    document = fitz.open()
    page = document.new_page(width=595, height=842)
    page.insert_textbox(
        fitz.Rect(40, 40, 555, 90),
        title,
        fontsize=20,
        fontname="helv",
    )
    cursor_top = 100
    blocks = [block.strip() for block in body.split("\n\n") if block.strip()]
    for block in blocks:
        rect = fitz.Rect(40, cursor_top, 555, 790)
        written = page.insert_textbox(
            rect,
            block,
            fontsize=11,
            fontname="helv",
            lineheight=1.35,
            align=fitz.TEXT_ALIGN_LEFT,
        )
        if written < 0:
            page = document.new_page(width=595, height=842)
            cursor_top = 50
            rect = fitz.Rect(40, cursor_top, 555, 790)
            page.insert_textbox(
                rect,
                block,
                fontsize=11,
                fontname="helv",
                lineheight=1.35,
                align=fitz.TEXT_ALIGN_LEFT,
            )
            cursor_top = 50 + max(120, block.count("\n") * 16 + 80)
        else:
            cursor_top += max(110, block.count("\n") * 15 + 70)
            if cursor_top > 740:
                page = document.new_page(width=595, height=842)
                cursor_top = 50
    path.unlink(missing_ok=True)
    document.save(path)
    document.close()


def _normalize_ids(payload: dict) -> dict:
    """Validate UUIDs and return the payload unchanged on success."""
    for node in payload["nodes"]:
        UUID(node["id"])
        if node.get("trust_boundary_id"):
            UUID(node["trust_boundary_id"])
    for edge in payload["edges"]:
        UUID(edge["id"])
        UUID(edge["source_node_id"])
        UUID(edge["target_node_id"])
    for boundary in payload["trust_boundaries"]:
        UUID(boundary["id"])
        for node_id in boundary["node_ids"]:
            UUID(node_id)
    return payload


def ensure_scenarios_materialized(base_dir: Path | None = None) -> list[Path]:
    """Materialize the curated scenario pack under backend/tests/evals/scenarios."""
    if base_dir is None:
        base_dir = Path(__file__).resolve().parent / "scenarios"
    base_dir.mkdir(parents=True, exist_ok=True)

    created: list[Path] = []
    for scenario_id, scenario in SCENARIO_DEFINITIONS.items():
        scenario_dir = base_dir / scenario_id
        scenario_dir.mkdir(parents=True, exist_ok=True)

        metadata_path = scenario_dir / "metadata.yaml"
        threat_theme_path = scenario_dir / "gold_threat_themes.yaml"
        hallucination_path = scenario_dir / "must_not_hallucinate.yaml"
        gold_dfd_path = scenario_dir / "gold_dfd.json"
        narrative_pdf_path = scenario_dir / "narrative.pdf"
        structured_pdf_path = scenario_dir / "structured.pdf"
        delta_pdf_path = scenario_dir / "delta.pdf"
        tmac_path = scenario_dir / "threat_model.tmac.yaml"
        readme_path = scenario_dir / "README.md"

        _write_yaml(metadata_path, scenario["metadata"])
        _write_yaml(threat_theme_path, scenario["gold_threat_themes"])
        _write_yaml(hallucination_path, scenario["must_not_hallucinate"])
        _write_json(gold_dfd_path, _normalize_ids(scenario["gold_dfd"]))
        _write_pdf(narrative_pdf_path, scenario["metadata"]["title"] + " - Narrative", scenario["documents"]["narrative"])
        _write_pdf(structured_pdf_path, scenario["metadata"]["title"] + " - Structured Architecture", scenario["documents"]["structured"])
        _write_pdf(delta_pdf_path, scenario["metadata"]["title"] + " - Change Request Delta", scenario["documents"]["delta"])
        if "tmac" in scenario:
            _write_yaml(tmac_path, scenario["tmac"])
            created.append(tmac_path)
        if "readme" in scenario:
            readme_path.write_text(scenario["readme"], encoding="utf-8")
            created.append(readme_path)

        created.extend(
            [
                metadata_path,
                threat_theme_path,
                hallucination_path,
                gold_dfd_path,
                narrative_pdf_path,
                structured_pdf_path,
                delta_pdf_path,
            ]
        )
    return created


if __name__ == "__main__":
    for created_path in ensure_scenarios_materialized():
        print(created_path)
