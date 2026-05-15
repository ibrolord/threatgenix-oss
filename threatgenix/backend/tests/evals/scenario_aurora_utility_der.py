from __future__ import annotations

from copy import deepcopy
from textwrap import dedent
from uuid import NAMESPACE_URL, uuid5


SCENARIO_ID = "aurora_utility_der"
SCENARIO_NS = f"https://threatgenix.local/evals/{SCENARIO_ID}"


def _id(kind: str, key: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"{SCENARIO_NS}:{kind}:{key}"))


def _node(
    key: str,
    node_type: str,
    name: str,
    position_x: float,
    position_y: float,
    *,
    boundary: str | None = None,
    properties: dict | None = None,
) -> dict:
    payload = {
        "key": key,
        "id": _id("node", key),
        "node_type": node_type,
        "name": name,
        "position_x": position_x,
        "position_y": position_y,
        "trust_boundary_id": _id("boundary", boundary) if boundary else None,
        "properties": properties or {},
    }
    return payload


def _edge(
    key: str,
    source_key: str,
    target_key: str,
    label: str,
    *,
    properties: dict | None = None,
) -> dict:
    return {
        "key": key,
        "id": _id("edge", key),
        "source_node_id": _id("node", source_key),
        "target_node_id": _id("node", target_key),
        "label": label,
        "properties": properties or {},
    }


def _boundary(
    key: str,
    name: str,
    member_keys: list[str],
    *,
    position_x: float,
    position_y: float,
    width: float,
    height: float,
    boundary_type: str,
    parent: str | None = None,
) -> dict:
    return {
        "key": key,
        "id": _id("boundary", key),
        "name": name,
        "node_ids": [_id("node", member_key) for member_key in member_keys],
        "position_x": position_x,
        "position_y": position_y,
        "width": width,
        "height": height,
        "boundary_type": boundary_type,
        "parent_boundary_id": _id("boundary", parent) if parent else None,
    }


NODE_SPECS = [
    _node(
        "customer_mobile_app",
        "external_entity",
        "Customer Mobile App",
        0,
        30,
        properties={
            "entity_kind": "device",
            "entity_scope": "external",
            "trust_level": "semi_trusted",
            "handles_pii": True,
        },
    ),
    _node(
        "customer_web_portal",
        "external_entity",
        "Customer Web Portal",
        0,
        120,
        properties={
            "entity_kind": "system",
            "entity_scope": "external",
            "trust_level": "semi_trusted",
            "handles_pii": True,
        },
    ),
    _node(
        "der_aggregator_partner",
        "external_entity",
        "DER Aggregator Partner",
        0,
        220,
        properties={
            "entity_kind": "api",
            "entity_scope": "external",
            "authenticated": True,
            "trust_level": "contracted_market_partner",
        },
    ),
    _node(
        "weather_provider",
        "external_entity",
        "Weather Intelligence Provider",
        0,
        320,
        properties={
            "entity_kind": "api",
            "entity_scope": "external",
            "authenticated": True,
            "trust_level": "semi_trusted",
        },
    ),
    _node(
        "iso_market_operator",
        "external_entity",
        "ISO Market Operator API",
        0,
        420,
        boundary="coordination_exchange",
        properties={
            "entity_kind": "api",
            "entity_scope": "external",
            "authenticated": True,
            "trust_level": "regulated_operator",
        },
    ),
    _node(
        "municipal_eoc",
        "external_entity",
        "Municipal Emergency Operations Center",
        0,
        520,
        boundary="coordination_exchange",
        properties={
            "entity_kind": "human",
            "entity_scope": "external",
            "authenticated": True,
            "trust_level": "mutual_aid_authority",
        },
    ),
    _node(
        "field_technician_tablet",
        "human_actor",
        "Field Technician Tablet",
        320,
        560,
        boundary="field_mobile_edge",
        properties={
            "entity_scope": "internal",
            "authenticated": True,
            "trust_level": "trusted",
            "network_exposure": "mobile_utility_lte",
        },
    ),
    _node(
        "vendor_support_enclave",
        "external_entity",
        "Vendor Support Enclave",
        1250,
        470,
        boundary="vendor_support_enclave",
        properties={
            "entity_kind": "system",
            "entity_scope": "external",
            "authenticated": True,
            "trust_level": "vendor_limited",
        },
    ),
    _node(
        "ami_meter_mesh",
        "external_entity",
        "AMI Meter Mesh",
        890,
        560,
        boundary="ot_operations_zone",
        properties={
            "entity_kind": "device",
            "entity_scope": "external",
            "authenticated": True,
            "trust_level": "telemetry_only",
            "network_exposure": "dedicated_utility_backhaul",
        },
    ),
    _node(
        "identity_gateway",
        "api_gateway",
        "Identity Gateway",
        250,
        80,
        boundary="public_partner_edge",
        properties={
            "authentication_type": "oauth2",
            "authorization_model": "policy",
            "internet_facing": True,
            "uses_auth": True,
            "uses_encryption": True,
            "validates_input": True,
            "runtime_type": "gateway",
        },
    ),
    _node(
        "api_mediation_gateway",
        "api_gateway",
        "API Mediation Gateway",
        250,
        220,
        boundary="public_partner_edge",
        properties={
            "internet_facing": True,
            "uses_auth": True,
            "uses_encryption": True,
            "validates_input": True,
            "runtime_type": "gateway",
            "network_exposure": "internet",
        },
    ),
    _node(
        "public_status_publisher",
        "serverless",
        "Public Outage Status Publisher",
        250,
        340,
        boundary="public_partner_edge",
        properties={
            "component_template_id": _id("template", "outage_status_publisher"),
            "runtime_type": "function",
            "uses_encryption": True,
            "validates_input": True,
            "logging_level": "audit",
        },
    ),
    _node(
        "workforce_identity_directory",
        "managed_service",
        "Workforce Identity Directory",
        500,
        40,
        boundary="identity_corporate_core",
        properties={
            "authentication_type": "saml",
            "authorization_model": "rbac",
            "responsibility": "shared_cloud_provider",
            "service_name": "Enterprise IdP",
        },
    ),
    _node(
        "vendor_access_broker",
        "process",
        "Vendor Access Broker",
        500,
        160,
        boundary="identity_corporate_core",
        properties={
            "uses_auth": True,
            "uses_encryption": True,
            "privilege_level": "elevated",
            "logging_level": "audit",
        },
    ),
    _node(
        "outage_command_center",
        "process",
        "Outage Command Center",
        520,
        280,
        boundary="cloud_control_plane",
        properties={
            "handles_sensitive_data": True,
            "uses_encryption": True,
            "runtime_type": "service",
            "responsibility": "shared",
        },
    ),
    _node(
        "der_orchestration_engine",
        "process",
        "DER Orchestration Engine",
        760,
        240,
        boundary="cloud_control_plane",
        properties={
            "component_template_id": _id("template", "der_fleet_orchestrator"),
            "handles_sensitive_data": True,
            "uses_encryption": True,
            "runtime_type": "service",
            "network_exposure": "internal_cross_zone",
        },
    ),
    _node(
        "load_forecasting_service",
        "process",
        "Load Forecasting Service",
        760,
        120,
        boundary="cloud_control_plane",
        properties={
            "handles_sensitive_data": False,
            "uses_encryption": True,
            "runtime_type": "worker",
            "logging_level": "full",
        },
    ),
    _node(
        "work_order_dispatch_service",
        "process",
        "Work Order Dispatch Service",
        520,
        420,
        boundary="cloud_control_plane",
        properties={
            "handles_sensitive_data": True,
            "uses_encryption": True,
            "runtime_type": "service",
            "logging_level": "audit",
        },
    ),
    _node(
        "break_glass_dispatch_console",
        "process",
        "Break-Glass Dispatch Console",
        760,
        360,
        boundary="cloud_control_plane",
        properties={
            "component_template_id": _id("template", "break_glass_console"),
            "uses_auth": True,
            "uses_encryption": True,
            "privilege_level": "emergency_dispatch",
            "logging_level": "audit",
        },
    ),
    _node(
        "ami_ingestion_broker",
        "managed_service",
        "AMI Ingestion Broker",
        760,
        500,
        boundary="cloud_control_plane",
        properties={
            "service_name": "Telemetry Ingestion Bus",
            "runtime_type": "worker",
            "uses_encryption": True,
            "logging_level": "full",
        },
    ),
    _node(
        "scada_adms_interface",
        "process",
        "SCADA / ADMS Interface",
        1010,
        220,
        boundary="ot_operations_zone",
        properties={
            "handles_sensitive_data": True,
            "uses_encryption": True,
            "runtime_type": "service",
            "isolation_boundary": "ot_control_zone",
            "network_exposure": "internal_cross_zone",
        },
    ),
    _node(
        "substation_edge_gateway",
        "container",
        "Substation Edge Gateway",
        1010,
        360,
        boundary="ot_operations_zone",
        properties={
            "component_template_id": _id("template", "substation_gateway"),
            "runtime_type": "container",
            "uses_encryption": True,
            "isolation_boundary": "field_site_gateway",
            "network_exposure": "dedicated_utility_backhaul",
        },
    ),
    _node(
        "firmware_signing_service",
        "process",
        "Firmware Signing Service",
        1010,
        80,
        boundary="ot_operations_zone",
        properties={
            "uses_auth": True,
            "uses_encryption": True,
            "stores_secrets": True,
            "privilege_level": "admin",
            "logging_level": "audit",
        },
    ),
    _node(
        "grid_telemetry_historian",
        "data_store",
        "Grid Telemetry Historian",
        1250,
        180,
        boundary="ot_operations_zone",
        properties={
            "encrypted_at_rest": True,
            "has_backup": True,
            "data_classification": "Restricted",
            "store_type": "historian_cluster",
            "store_purpose": "topology and switching state",
            "integrity_controls": "append-only journals and signed snapshots",
        },
    ),
    _node(
        "customer_billing_data_hub",
        "data_store",
        "Customer and Billing Data Hub",
        1250,
        40,
        boundary="restricted_data_zone",
        properties={
            "encrypted_at_rest": True,
            "has_backup": True,
            "data_classification": "Restricted",
            "store_type": "customer_master",
            "store_purpose": "service points and billing context",
            "read_access_scope": "api and outage operations",
            "write_access_scope": "billing sync only",
        },
    ),
    _node(
        "market_settlement_ledger",
        "data_store",
        "Market Settlement Ledger",
        1250,
        300,
        boundary="restricted_data_zone",
        properties={
            "encrypted_at_rest": True,
            "has_backup": True,
            "data_classification": "Restricted",
            "store_type": "settlement_ledger",
            "store_purpose": "DER dispatch settlement and audit",
            "integrity_controls": "dual-ledger reconciliation",
        },
    ),
    _node(
        "audit_decision_vault",
        "data_store",
        "Audit and Decision Vault",
        1250,
        420,
        boundary="restricted_data_zone",
        properties={
            "encrypted_at_rest": True,
            "has_backup": True,
            "data_classification": "Restricted",
            "store_type": "immutable_audit",
            "store_purpose": "operator approvals and break-glass records",
            "integrity_controls": "WORM retention",
        },
    ),
    _node(
        "operations_data_lake",
        "data_store",
        "Operations Data Lake",
        1250,
        540,
        boundary="restricted_data_zone",
        properties={
            "encrypted_at_rest": True,
            "has_backup": True,
            "data_classification": "Confidential",
            "store_type": "analytics_lake",
            "store_purpose": "telemetry analytics and post-incident review",
        },
    ),
]


EDGE_SPECS = [
    _edge(
        "customer_mobile_auth",
        "customer_mobile_app",
        "identity_gateway",
        "mobile authentication request",
        properties={
            "protocol": "HTTPS",
            "auth_mechanism": "OAuth2 + device binding",
            "data_classification": "Restricted",
            "lifecycle_stage": "ingress",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "synchronous",
            "carries_pii": True,
            "tls_version": "tls_1_3",
        },
    ),
    _edge(
        "customer_web_auth",
        "customer_web_portal",
        "identity_gateway",
        "portal authentication request",
        properties={
            "protocol": "HTTPS",
            "auth_mechanism": "OAuth2",
            "data_classification": "Restricted",
            "lifecycle_stage": "ingress",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "synchronous",
            "carries_pii": True,
            "tls_version": "tls_1_3",
        },
    ),
    _edge(
        "identity_token_forward",
        "identity_gateway",
        "api_mediation_gateway",
        "signed customer session token",
        properties={
            "protocol": "mTLS gRPC",
            "auth_mechanism": "JWT",
            "data_classification": "Restricted",
            "lifecycle_stage": "processing",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
            "tls_version": "tls_1_3",
        },
    ),
    _edge(
        "workforce_directory_lookup",
        "identity_gateway",
        "workforce_identity_directory",
        "federated workforce directory lookup",
        properties={
            "protocol": "OIDC federation lookup",
            "auth_mechanism": "mTLS",
            "data_classification": "Internal",
            "lifecycle_stage": "processing",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "synchronous",
            "integrity_protected": True,
            "tls_version": "tls_1_3",
        },
    ),
    _edge(
        "aggregator_capacity_feed",
        "der_aggregator_partner",
        "api_mediation_gateway",
        "DER flexibility availability feed",
        properties={
            "protocol": "HTTPS webhook",
            "auth_mechanism": "mTLS + signed payload",
            "data_classification": "Confidential",
            "lifecycle_stage": "ingress",
            "encryption_in_transit": True,
            "directionality": "event",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
            "tls_version": "tls_1_3",
        },
    ),
    _edge(
        "weather_ingest",
        "weather_provider",
        "load_forecasting_service",
        "severe weather forecast ingest",
        properties={
            "protocol": "HTTPS API",
            "data_classification": "Internal",
            "lifecycle_stage": "ingress",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "batch",
            "tls_version": "tls_1_2",
        },
    ),
    _edge(
        "market_dispatch_schedule",
        "iso_market_operator",
        "der_orchestration_engine",
        "market dispatch and curtailment schedule",
        properties={
            "protocol": "HTTPS API",
            "auth_mechanism": "mTLS",
            "data_classification": "Confidential",
            "lifecycle_stage": "ingress",
            "encryption_in_transit": True,
            "directionality": "event",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
            "tls_version": "tls_1_3",
        },
    ),
    _edge(
        "emergency_priority_feed",
        "municipal_eoc",
        "outage_command_center",
        "emergency restoration priority request",
        properties={
            "protocol": "HTTPS API",
            "auth_mechanism": "signed request",
            "data_classification": "Confidential",
            "lifecycle_stage": "processing",
            "encryption_in_transit": True,
            "directionality": "event",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "field_sync_upload",
        "field_technician_tablet",
        "work_order_dispatch_service",
        "technician sync and status ack",
        properties={
            "protocol": "HTTPS",
            "auth_mechanism": "mutual device attestation",
            "data_classification": "Confidential",
            "lifecycle_stage": "ingress",
            "encryption_in_transit": True,
            "directionality": "bidirectional",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "field_work_package",
        "work_order_dispatch_service",
        "field_technician_tablet",
        "offline work package and switching steps",
        properties={
            "protocol": "HTTPS",
            "auth_mechanism": "JWT",
            "data_classification": "Restricted",
            "lifecycle_stage": "egress",
            "encryption_in_transit": True,
            "directionality": "response",
            "transfer_mode": "batch",
            "carries_pii": True,
            "integrity_protected": True,
        },
    ),
    _edge(
        "customer_outage_report",
        "api_mediation_gateway",
        "outage_command_center",
        "customer outage report and restoration query",
        properties={
            "protocol": "mTLS gRPC",
            "auth_mechanism": "JWT",
            "data_classification": "Restricted",
            "lifecycle_stage": "processing",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "carries_pii": True,
        },
    ),
    _edge(
        "premise_lookup",
        "api_mediation_gateway",
        "customer_billing_data_hub",
        "customer premise and service point lookup",
        properties={
            "protocol": "mTLS SQL proxy",
            "data_classification": "Restricted",
            "lifecycle_stage": "processing",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "synchronous",
            "carries_pii": True,
        },
    ),
    _edge(
        "public_status_update",
        "outage_command_center",
        "public_status_publisher",
        "outage status summary publish",
        properties={
            "protocol": "internal event",
            "data_classification": "Internal",
            "lifecycle_stage": "notification",
            "encryption_in_transit": True,
            "directionality": "event",
            "transfer_mode": "near_real_time",
        },
    ),
    _edge(
        "customer_notification",
        "public_status_publisher",
        "customer_mobile_app",
        "push outage notification",
        properties={
            "protocol": "push notification API",
            "data_classification": "Internal",
            "lifecycle_stage": "notification",
            "directionality": "event",
            "transfer_mode": "near_real_time",
        },
    ),
    _edge(
        "ami_telemetry_burst",
        "ami_meter_mesh",
        "ami_ingestion_broker",
        "meter telemetry burst",
        properties={
            "protocol": "MQTT",
            "auth_mechanism": "device certificate",
            "data_classification": "Confidential",
            "lifecycle_stage": "ingress",
            "encryption_in_transit": True,
            "directionality": "event",
            "transfer_mode": "streaming",
            "integrity_protected": True,
        },
    ),
    _edge(
        "normalized_telemetry",
        "ami_ingestion_broker",
        "load_forecasting_service",
        "normalized meter and DER telemetry",
        properties={
            "protocol": "Kafka",
            "data_classification": "Confidential",
            "lifecycle_stage": "processing",
            "encryption_in_transit": True,
            "directionality": "event",
            "transfer_mode": "streaming",
            "integrity_protected": True,
        },
    ),
    _edge(
        "forecast_recommendation",
        "load_forecasting_service",
        "der_orchestration_engine",
        "load shed and restoration recommendation",
        properties={
            "protocol": "gRPC",
            "data_classification": "Confidential",
            "lifecycle_stage": "analytics",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "dispatch_command",
        "der_orchestration_engine",
        "scada_adms_interface",
        "DER setpoint and feeder reconfiguration request",
        properties={
            "protocol": "IEC-104 gateway API",
            "auth_mechanism": "signed command token",
            "data_classification": "Restricted",
            "lifecycle_stage": "egress",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
            "carries_financial_data": False,
        },
    ),
    _edge(
        "field_command_bundle",
        "scada_adms_interface",
        "substation_edge_gateway",
        "signed field command bundle",
        properties={
            "protocol": "mTLS control channel",
            "auth_mechanism": "signed command package",
            "data_classification": "Restricted",
            "lifecycle_stage": "egress",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "vendor_maintenance_request",
        "vendor_support_enclave",
        "vendor_access_broker",
        "time-boxed maintenance request",
        properties={
            "protocol": "HTTPS",
            "auth_mechanism": "federated SSO",
            "data_classification": "Confidential",
            "lifecycle_stage": "ingress",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "synchronous",
            "integrity_protected": True,
        },
    ),
    _edge(
        "vendor_diagnostic_session",
        "vendor_access_broker",
        "scada_adms_interface",
        "approved vendor diagnostic session",
        properties={
            "protocol": "brokered bastion session",
            "auth_mechanism": "just-in-time session certificate",
            "data_classification": "Restricted",
            "lifecycle_stage": "processing",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "synchronous",
            "integrity_protected": True,
        },
    ),
    _edge(
        "break_glass_override",
        "break_glass_dispatch_console",
        "der_orchestration_engine",
        "emergency override command",
        properties={
            "protocol": "gRPC",
            "auth_mechanism": "dual-approval emergency token",
            "data_classification": "Restricted",
            "lifecycle_stage": "egress",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "break_glass_record",
        "break_glass_dispatch_console",
        "audit_decision_vault",
        "break-glass approval record",
        properties={
            "protocol": "append API",
            "data_classification": "Restricted",
            "lifecycle_stage": "notification",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "operator_decision_record",
        "der_orchestration_engine",
        "audit_decision_vault",
        "dispatch and load shed decision record",
        properties={
            "protocol": "append API",
            "data_classification": "Restricted",
            "lifecycle_stage": "notification",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "restoration_decision_record",
        "outage_command_center",
        "audit_decision_vault",
        "switching and restoration decision record",
        properties={
            "protocol": "append API",
            "data_classification": "Restricted",
            "lifecycle_stage": "notification",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "settlement_event",
        "der_orchestration_engine",
        "market_settlement_ledger",
        "dispatch and settlement event",
        properties={
            "protocol": "SQL proxy",
            "data_classification": "Restricted",
            "lifecycle_stage": "storage",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "synchronous",
            "carries_financial_data": True,
            "integrity_protected": True,
        },
    ),
    _edge(
        "participation_lookup",
        "der_orchestration_engine",
        "customer_billing_data_hub",
        "premise participation and tariff lookup",
        properties={
            "protocol": "SQL proxy",
            "data_classification": "Restricted",
            "lifecycle_stage": "processing",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "synchronous",
            "carries_pii": True,
        },
    ),
    _edge(
        "market_commitment_response",
        "der_orchestration_engine",
        "iso_market_operator",
        "committed flexibility response",
        properties={
            "protocol": "HTTPS API",
            "auth_mechanism": "mTLS",
            "data_classification": "Confidential",
            "lifecycle_stage": "egress",
            "encryption_in_transit": True,
            "directionality": "response",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
    _edge(
        "topology_snapshot",
        "scada_adms_interface",
        "grid_telemetry_historian",
        "control and topology snapshot",
        properties={
            "protocol": "historian write API",
            "data_classification": "Restricted",
            "lifecycle_stage": "storage",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "streaming",
            "integrity_protected": True,
        },
    ),
    _edge(
        "telemetry_replication",
        "grid_telemetry_historian",
        "operations_data_lake",
        "telemetry replication for analytics",
        properties={
            "protocol": "batch export",
            "data_classification": "Confidential",
            "lifecycle_stage": "analytics",
            "encryption_in_transit": True,
            "directionality": "request",
            "transfer_mode": "batch",
        },
    ),
    _edge(
        "firmware_package_release",
        "firmware_signing_service",
        "substation_edge_gateway",
        "signed firmware package",
        properties={
            "protocol": "artifact release",
            "auth_mechanism": "signed manifest",
            "data_classification": "Confidential",
            "lifecycle_stage": "egress",
            "directionality": "request",
            "transfer_mode": "batch",
            "integrity_protected": True,
        },
    ),
    _edge(
        "field_hazard_note",
        "field_technician_tablet",
        "outage_command_center",
        "crew hazard note and local isolation status",
        properties={
            "protocol": "HTTPS",
            "auth_mechanism": "device attestation",
            "data_classification": "Confidential",
            "lifecycle_stage": "notification",
            "encryption_in_transit": True,
            "directionality": "event",
            "transfer_mode": "near_real_time",
            "integrity_protected": True,
        },
    ),
]


BOUNDARY_SPECS = [
    _boundary(
        "public_partner_edge",
        "Public Customer and External Partner Edge",
        ["identity_gateway", "api_mediation_gateway", "public_status_publisher"],
        position_x=180,
        position_y=10,
        width=240,
        height=420,
        boundary_type="network",
    ),
    _boundary(
        "identity_corporate_core",
        "Utility Identity and Corporate Core",
        ["workforce_identity_directory", "vendor_access_broker"],
        position_x=430,
        position_y=0,
        width=210,
        height=240,
        boundary_type="organizational",
    ),
    _boundary(
        "cloud_control_plane",
        "Cloud Operations Control Plane",
        [
            "outage_command_center",
            "der_orchestration_engine",
            "load_forecasting_service",
            "work_order_dispatch_service",
            "break_glass_dispatch_console",
            "ami_ingestion_broker",
        ],
        position_x=440,
        position_y=90,
        width=470,
        height=500,
        boundary_type="cloud",
    ),
    _boundary(
        "ot_operations_zone",
        "OT Operations Zone",
        [
            "ami_meter_mesh",
            "scada_adms_interface",
            "substation_edge_gateway",
            "firmware_signing_service",
            "grid_telemetry_historian",
        ],
        position_x=910,
        position_y=40,
        width=420,
        height=590,
        boundary_type="ot_safety",
    ),
    _boundary(
        "restricted_data_zone",
        "Restricted Customer and Settlement Data Zone",
        [
            "customer_billing_data_hub",
            "market_settlement_ledger",
            "audit_decision_vault",
            "operations_data_lake",
        ],
        position_x=1180,
        position_y=0,
        width=360,
        height=640,
        boundary_type="regulatory",
    ),
    _boundary(
        "field_mobile_edge",
        "Field and Mobile Edge",
        ["field_technician_tablet"],
        position_x=260,
        position_y=500,
        width=250,
        height=150,
        boundary_type="organizational",
    ),
    _boundary(
        "vendor_support_enclave",
        "Vendor Support Enclave",
        ["vendor_support_enclave"],
        position_x=1200,
        position_y=440,
        width=260,
        height=150,
        boundary_type="privilege",
    ),
    _boundary(
        "coordination_exchange",
        "Regulatory and Emergency Coordination Exchange",
        ["iso_market_operator", "municipal_eoc"],
        position_x=-30,
        position_y=380,
        width=240,
        height=220,
        boundary_type="regulatory",
    ),
]


def _gold_dfd() -> dict:
    return {
        "nodes": [
            {
                "id": item["id"],
                "node_type": item["node_type"],
                "name": item["name"],
                "position_x": item["position_x"],
                "position_y": item["position_y"],
                "trust_boundary_id": item["trust_boundary_id"],
                "properties": deepcopy(item["properties"]),
            }
            for item in NODE_SPECS
        ],
        "edges": [
            {
                "id": item["id"],
                "source_node_id": item["source_node_id"],
                "target_node_id": item["target_node_id"],
                "label": item["label"],
            }
            for item in EDGE_SPECS
        ],
        "trust_boundaries": [
            {
                "id": item["id"],
                "name": item["name"],
                "node_ids": deepcopy(item["node_ids"]),
                "position_x": item["position_x"],
                "position_y": item["position_y"],
                "width": item["width"],
                "height": item["height"],
                "boundary_type": item["boundary_type"],
                "parent_boundary_id": item["parent_boundary_id"],
            }
            for item in BOUNDARY_SPECS
        ],
    }


def _root_dfd_for_tmac() -> dict:
    return {
        "nodes": [
            {
                "id": item["id"],
                "node_type": item["node_type"],
                "name": item["name"],
                "position_x": item["position_x"],
                "position_y": item["position_y"],
                "trust_boundary_id": item["trust_boundary_id"],
                "properties": deepcopy(item["properties"]),
                "security_controls": [],
            }
            for item in NODE_SPECS
        ],
        "edges": [
            {
                "id": item["id"],
                "source_node_id": item["source_node_id"],
                "target_node_id": item["target_node_id"],
                "label": item["label"],
                "properties": deepcopy(item["properties"]),
            }
            for item in EDGE_SPECS
        ],
        "trust_boundaries": [
            {
                "id": item["id"],
                "name": item["name"],
                "node_ids": deepcopy(item["node_ids"]),
                "position_x": item["position_x"],
                "position_y": item["position_y"],
                "width": item["width"],
                "height": item["height"],
                "boundary_type": item["boundary_type"],
                "parent_boundary_id": item["parent_boundary_id"],
            }
            for item in BOUNDARY_SPECS
        ],
    }


def _subset_graph(node_keys: list[str], edge_keys: list[str], boundary_keys: list[str]) -> dict:
    node_ids = {_id("node", key) for key in node_keys}
    edge_ids = {_id("edge", key) for key in edge_keys}
    boundary_ids = {_id("boundary", key) for key in boundary_keys}
    boundaries = []
    for item in _root_dfd_for_tmac()["trust_boundaries"]:
        if item["id"] not in boundary_ids:
            continue
        boundary = deepcopy(item)
        boundary["node_ids"] = [node_id for node_id in boundary["node_ids"] if node_id in node_ids]
        boundaries.append(boundary)
    return {
        "nodes": [item for item in _root_dfd_for_tmac()["nodes"] if item["id"] in node_ids],
        "edges": [item for item in _root_dfd_for_tmac()["edges"] if item["id"] in edge_ids],
        "trust_boundaries": boundaries,
    }


TMAC_THREATS = [
    {
        "id": _id("threat", "forged_der_capacity"),
        "display_id": "AUR-T001",
        "description": "Forged or replayed DER aggregator availability updates cause unsafe dispatch commitments during a storm restoration window.",
        "stride_category": "Spoofing",
        "threat_subtype": "partner callback trust failure",
        "severity": "Critical",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-01",
        "affected_node_ids": [_id("node", "der_aggregator_partner"), _id("node", "api_mediation_gateway"), _id("node", "der_orchestration_engine")],
        "affected_edge_ids": [_id("edge", "aggregator_capacity_feed"), _id("edge", "market_commitment_response")],
        "relevance_rationale": "The platform accepts partner flexibility signals under incident pressure and uses them to commit load relief into market and OT control paths.",
        "mitigation_plan": "Require deterministic payload signing with replay windows, enforce partner sequence numbers, and quarantine stale flexibility updates during incident mode.",
        "mitigation_owner": "DER Platform Lead",
        "due_date": "2026-06-15",
        "mitigation_notes": "Partner currently supports mTLS but not monotonic sequence enforcement.",
        "control_effectiveness": "partial",
        "residual_risk_level": "High",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "break_glass_override_abuse"),
        "display_id": "AUR-T002",
        "description": "An operator abuses emergency dispatch override to issue unreviewed load-shed or feeder reconfiguration commands.",
        "stride_category": "Elevation of Privilege",
        "threat_subtype": "break-glass misuse",
        "severity": "Critical",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-02",
        "affected_node_ids": [_id("node", "break_glass_dispatch_console"), _id("node", "der_orchestration_engine"), _id("node", "scada_adms_interface")],
        "affected_edge_ids": [_id("edge", "break_glass_override"), _id("edge", "dispatch_command")],
        "relevance_rationale": "Storm mode compresses approvals and explicitly introduces emergency privileges with real operational blast radius.",
        "mitigation_plan": "Enforce dual-control for emergency overrides, bind approvals to named events, and require post-action attestation within immutable audit.",
        "mitigation_owner": "Operations Security Manager",
        "due_date": "2026-05-31",
        "mitigation_notes": "Current console records approvals but does not prevent same-user initiate/approve.",
        "control_effectiveness": "partial",
        "residual_risk_level": "Critical",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "vendor_pivot_ot"),
        "display_id": "AUR-T003",
        "description": "A brokered vendor diagnostics session pivots into the OT control plane and reaches switching logic or firmware workflows.",
        "stride_category": "Tampering",
        "threat_subtype": "third-party support pivot",
        "severity": "Critical",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-03",
        "affected_node_ids": [_id("node", "vendor_support_enclave"), _id("node", "vendor_access_broker"), _id("node", "scada_adms_interface"), _id("node", "firmware_signing_service")],
        "affected_edge_ids": [_id("edge", "vendor_maintenance_request"), _id("edge", "vendor_diagnostic_session")],
        "relevance_rationale": "The vendor path is legitimate, privileged, and incident-driven, which makes it a high-value lateral-movement candidate.",
        "mitigation_plan": "Constrain vendor sessions to read-only diagnostics, force signed work orders, and separate firmware release authority from diagnostics.",
        "mitigation_owner": "OT Security Lead",
        "due_date": "2026-06-01",
        "mitigation_notes": "Vendor enclave is time-boxed but still reaches shared SCADA service accounts.",
        "control_effectiveness": "partial",
        "residual_risk_level": "High",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "field_replay"),
        "display_id": "AUR-T004",
        "description": "A stale offline work package is replayed from a field tablet after topology changed, causing unsafe switching guidance.",
        "stride_category": "Tampering",
        "threat_subtype": "offline replay",
        "severity": "High",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-04",
        "affected_node_ids": [_id("node", "field_technician_tablet"), _id("node", "work_order_dispatch_service"), _id("node", "outage_command_center")],
        "affected_edge_ids": [_id("edge", "field_work_package"), _id("edge", "field_hazard_note")],
        "relevance_rationale": "Offline-first field operations are essential during storms, but they create stale-authority risk and delayed consensus.",
        "mitigation_plan": "Add work package epoching, mandatory topology freshness checks, and local tablet invalidation on breaker-state drift.",
        "mitigation_owner": "Field Operations Product Owner",
        "due_date": "2026-06-20",
        "mitigation_notes": "Current packages can remain valid for four hours without revalidation.",
        "control_effectiveness": "none",
        "residual_risk_level": "High",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "telemetry_poisoning"),
        "display_id": "AUR-T005",
        "description": "Manipulated AMI telemetry drives incorrect load-shed recommendations and masks feeder stress in the forecasting pipeline.",
        "stride_category": "Information Disclosure",
        "threat_subtype": "telemetry poisoning",
        "severity": "Critical",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-05",
        "affected_node_ids": [_id("node", "ami_meter_mesh"), _id("node", "ami_ingestion_broker"), _id("node", "load_forecasting_service")],
        "affected_edge_ids": [_id("edge", "ami_telemetry_burst"), _id("edge", "normalized_telemetry"), _id("edge", "forecast_recommendation")],
        "relevance_rationale": "The platform treats telemetry as operational truth, so poisoned measurements create both safety and trust impacts.",
        "mitigation_plan": "Introduce anomaly scoring across feeder telemetry, signed meter batches, and dispatch hold conditions when telemetry confidence drops.",
        "mitigation_owner": "Analytics Engineering Manager",
        "due_date": "2026-07-01",
        "mitigation_notes": "Current validation focuses on message syntax, not cross-feeder plausibility.",
        "control_effectiveness": "partial",
        "residual_risk_level": "Critical",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "public_recon"),
        "display_id": "AUR-T006",
        "description": "The public outage experience leaks restoration sequencing, feeder naming, or critical-facility prioritization that improves attacker recon.",
        "stride_category": "Information Disclosure",
        "threat_subtype": "metadata leakage",
        "severity": "Medium",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-06",
        "affected_node_ids": [_id("node", "public_status_publisher"), _id("node", "outage_command_center")],
        "affected_edge_ids": [_id("edge", "public_status_update"), _id("edge", "customer_notification")],
        "relevance_rationale": "No direct compromise is required; over-shared public metadata can expose real operational priorities and timing.",
        "mitigation_plan": "Separate public incident summaries from internal feeder labels and suppress priority rationale for hospitals and shelters.",
        "mitigation_owner": "Digital Channels Manager",
        "due_date": "2026-05-15",
        "mitigation_notes": "Status publisher currently reuses internal feeder labels in some payloads.",
        "control_effectiveness": "partial",
        "residual_risk_level": "Medium",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "firmware_signing_abuse"),
        "display_id": "AUR-T007",
        "description": "Compromise or misuse of firmware signing authority deploys malicious or unstable packages to substation gateways.",
        "stride_category": "Elevation of Privilege",
        "threat_subtype": "signing chain compromise",
        "severity": "Critical",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-07",
        "affected_node_ids": [_id("node", "firmware_signing_service"), _id("node", "substation_edge_gateway"), _id("node", "vendor_access_broker")],
        "affected_edge_ids": [_id("edge", "firmware_package_release"), _id("edge", "vendor_diagnostic_session")],
        "relevance_rationale": "Firmware provenance is a concentrated trust anchor with broad blast radius across field assets.",
        "mitigation_plan": "Move release signing into dual-party HSM-backed workflow and require out-of-band attestation before field rollout.",
        "mitigation_owner": "Platform Engineering Director",
        "due_date": "2026-06-30",
        "mitigation_notes": "Signer custody exists but release approval is still single-admin.",
        "control_effectiveness": "partial",
        "residual_risk_level": "High",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "settlement_repudiation"),
        "display_id": "AUR-T008",
        "description": "Settlement records diverge from dispatch intent, enabling repudiation of energy commitments or customer compensation.",
        "stride_category": "Repudiation",
        "threat_subtype": "ledger inconsistency",
        "severity": "High",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-08",
        "affected_node_ids": [_id("node", "der_orchestration_engine"), _id("node", "market_settlement_ledger"), _id("node", "audit_decision_vault")],
        "affected_edge_ids": [_id("edge", "settlement_event"), _id("edge", "operator_decision_record")],
        "relevance_rationale": "The utility must prove who decided what, when, and on which telemetry basis across both market and public-restoration workflows.",
        "mitigation_plan": "Bind settlement writes to immutable decision records and perform hourly reconciliation between market commitments and field execution.",
        "mitigation_owner": "Market Operations Manager",
        "due_date": "2026-06-10",
        "mitigation_notes": "Audit data exists but is not yet cryptographically bound to settlement entries.",
        "control_effectiveness": "substantial",
        "residual_risk_level": "Medium",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "priority_tampering"),
        "display_id": "AUR-T009",
        "description": "Emergency restoration priorities are manipulated to favor non-critical feeders or partner interests over hospitals and shelters.",
        "stride_category": "Tampering",
        "threat_subtype": "priority queue abuse",
        "severity": "High",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-09",
        "affected_node_ids": [_id("node", "municipal_eoc"), _id("node", "outage_command_center"), _id("node", "work_order_dispatch_service")],
        "affected_edge_ids": [_id("edge", "emergency_priority_feed"), _id("edge", "field_work_package")],
        "relevance_rationale": "Priority manipulation is subtle, business-context-driven, and likely to happen during public scrutiny rather than through a noisy exploit.",
        "mitigation_plan": "Require critical-load registry corroboration and second-party sign-off before high-impact priority overrides propagate to field work.",
        "mitigation_owner": "Incident Command Lead",
        "due_date": "2026-05-25",
        "mitigation_notes": "EOC feed is trusted operationally but not always cross-checked against utility critical-load registry.",
        "control_effectiveness": "partial",
        "residual_risk_level": "High",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
    {
        "id": _id("threat", "historian_gap"),
        "display_id": "AUR-T010",
        "description": "Partial historian coverage or delayed telemetry replication hides unauthorized switching and weakens incident reconstruction.",
        "stride_category": "Denial of Service",
        "threat_subtype": "telemetry visibility gap",
        "severity": "High",
        "source": "Manual",
        "status": "Open",
        "rule_id": "AUR-10",
        "affected_node_ids": [_id("node", "grid_telemetry_historian"), _id("node", "operations_data_lake"), _id("node", "audit_decision_vault")],
        "affected_edge_ids": [_id("edge", "topology_snapshot"), _id("edge", "telemetry_replication")],
        "relevance_rationale": "Visibility failures create false confidence and make both operational recovery and root-cause analysis materially harder.",
        "mitigation_plan": "Alert on historian lag by feeder, capture last-known-good topology snapshots, and block sensitive closeouts when telemetry coverage is incomplete.",
        "mitigation_owner": "Operational Observability Lead",
        "due_date": "2026-06-05",
        "mitigation_notes": "Telemetry replication currently tolerates fifteen-minute lag without escalation.",
        "control_effectiveness": "none",
        "residual_risk_level": "High",
        "created_at": "2026-04-18T09:00:00Z",
        "updated_at": "2026-04-18T09:00:00Z",
    },
]


def _snapshot_threat(threat: dict) -> dict:
    return {
        "id": threat["id"],
        "display_id": threat["display_id"],
        "description": threat["description"],
        "severity": threat["severity"],
        "stride_category": threat["stride_category"],
        "status": threat["status"],
        "mitigation_plan": threat["mitigation_plan"],
        "mitigation_owner": threat["mitigation_owner"],
        "due_date": threat["due_date"],
        "mitigation_notes": threat["mitigation_notes"],
        "control_effectiveness": threat["control_effectiveness"],
        "residual_risk_level": threat["residual_risk_level"],
        "affected_node_ids": deepcopy(threat["affected_node_ids"]),
        "affected_edge_ids": deepcopy(threat["affected_edge_ids"]),
    }


def _tmac_document() -> dict:
    root_dfd = _root_dfd_for_tmac()
    restoration_nodes = [
        "municipal_eoc",
        "field_technician_tablet",
        "outage_command_center",
        "work_order_dispatch_service",
        "break_glass_dispatch_console",
        "der_orchestration_engine",
        "scada_adms_interface",
        "substation_edge_gateway",
        "audit_decision_vault",
    ]
    restoration_edges = [
        "emergency_priority_feed",
        "field_sync_upload",
        "field_work_package",
        "break_glass_override",
        "break_glass_record",
        "field_command_bundle",
        "restoration_decision_record",
        "field_hazard_note",
    ]
    restoration_boundaries = [
        "coordination_exchange",
        "field_mobile_edge",
        "cloud_control_plane",
        "ot_operations_zone",
        "restricted_data_zone",
    ]
    vendor_nodes = [
        "vendor_support_enclave",
        "vendor_access_broker",
        "firmware_signing_service",
        "scada_adms_interface",
        "substation_edge_gateway",
        "grid_telemetry_historian",
        "audit_decision_vault",
    ]
    vendor_edges = [
        "vendor_maintenance_request",
        "vendor_diagnostic_session",
        "firmware_package_release",
        "topology_snapshot",
    ]
    vendor_boundaries = [
        "vendor_support_enclave",
        "identity_corporate_core",
        "ot_operations_zone",
        "restricted_data_zone",
    ]
    return {
        "tmac_version": "1.0",
        "metadata": {
            "id": _id("tmac", "metadata"),
            "system_name": "Aurora Utility DER Orchestration and Storm Response Platform",
            "description": "Hybrid utility control and outage-response platform spanning customer channels, DER orchestration, OT switching, vendor support, field mobility, and immutable operational governance.",
            "data_classification": "Restricted",
            "regulatory_scope": ["NERC CIP", "NIST", "ISO 27001", "PCI DSS"],
            "deployment_model": "hybrid",
            "created_at": "2026-04-18T09:00:00Z",
            "updated_at": "2026-04-18T09:00:00Z",
        },
        "evidence": {
            "environment_context_summary": "Primary cloud control plane with OT integration, meter mesh telemetry, vendor diagnostics, emergency coordination feeds, and storm-restoration break-glass operations.",
        },
        "reporting": {"report_template": "default", "arch_diagrams": []},
        "dfd": root_dfd,
        "views": {
            "built_in_views": [
                {"id": _id("view", "context"), "view_type": "context", "name": "Context View", "layout_snapshot": {}},
                {"id": _id("view", "system"), "view_type": "container", "name": "System View", "layout_snapshot": {}},
                {"id": _id("view", "risky"), "view_type": "deep_dive", "name": "Risky Flows", "layout_snapshot": {}},
                {"id": _id("view", "sensitive"), "view_type": "data_lifecycle", "name": "Sensitive Data", "layout_snapshot": {}},
            ],
            "custom_views": [
                {
                    "id": _id("view", "restoration_workspace"),
                    "view_type": "workspace",
                    "name": "Storm Restoration Control",
                    "node_ids": [_id("node", key) for key in restoration_nodes],
                    "edge_ids": [_id("edge", key) for key in restoration_edges],
                    "boundary_ids": [_id("boundary", key) for key in restoration_boundaries],
                    "layout_snapshot": {},
                    "graph": _subset_graph(restoration_nodes, restoration_edges, restoration_boundaries),
                    "is_auto_generated": False,
                },
                {
                    "id": _id("view", "vendor_workspace"),
                    "view_type": "workspace",
                    "name": "Vendor Access Blast Radius",
                    "node_ids": [_id("node", key) for key in vendor_nodes],
                    "edge_ids": [_id("edge", key) for key in vendor_edges],
                    "boundary_ids": [_id("boundary", key) for key in vendor_boundaries],
                    "layout_snapshot": {},
                    "graph": _subset_graph(vendor_nodes, vendor_edges, vendor_boundaries),
                    "is_auto_generated": False,
                },
            ],
        },
        "threats": deepcopy(TMAC_THREATS),
        "assumptions": [
            {
                "id": _id("assumption", "field_epoching"),
                "title": "Field packages are revoked when topology epochs change materially.",
                "description": "ThreatGenix should challenge this assumption because tablet sync is intentionally degraded during storms.",
                "status": "open",
                "anchor_kind": "edge",
                "anchor_id": _id("edge", "field_work_package"),
                "anchor_label": "offline work package and switching steps",
                "created_at": "2026-04-18T09:00:00Z",
                "updated_at": "2026-04-18T09:00:00Z",
            },
            {
                "id": _id("assumption", "vendor_read_only"),
                "title": "Vendor diagnostics remain read-only in all storm modes.",
                "description": "Break-glass and emergency maintenance pressure can erode this assumption.",
                "status": "challenged",
                "anchor_kind": "node",
                "anchor_id": _id("node", "vendor_access_broker"),
                "anchor_label": "Vendor Access Broker",
                "created_at": "2026-04-18T09:00:00Z",
                "updated_at": "2026-04-18T09:00:00Z",
            },
            {
                "id": _id("assumption", "public_redaction"),
                "title": "Public outage content never exposes feeder identifiers or critical-load rationale.",
                "description": "The publisher is intended to redact internal details before customer release.",
                "status": "open",
                "anchor_kind": "node",
                "anchor_id": _id("node", "public_status_publisher"),
                "anchor_label": "Public Outage Status Publisher",
                "created_at": "2026-04-18T09:00:00Z",
                "updated_at": "2026-04-18T09:00:00Z",
            },
            {
                "id": _id("assumption", "meter_integrity"),
                "title": "Meter telemetry is trustworthy enough to drive dispatch recommendations without independent corroboration.",
                "description": "This assumption should be treated as fragile during outage or field-network degradation.",
                "status": "challenged",
                "anchor_kind": "edge",
                "anchor_id": _id("edge", "ami_telemetry_burst"),
                "anchor_label": "meter telemetry burst",
                "created_at": "2026-04-18T09:00:00Z",
                "updated_at": "2026-04-18T09:00:00Z",
            },
        ],
        "controls": [
            {
                "id": _id("control", "dual_control_break_glass"),
                "title": "Dual-control emergency override workflow",
                "description": "Break-glass requires a named incident, a second approver, and immutable operator attestation.",
                "category": "preventive",
                "status": "partial",
                "owner": "Operations Security Manager",
                "evidence": "Quarterly drill logs and broker attestation prototype",
                "mapped_threat_ids": [_id("threat", "break_glass_override_abuse"), _id("threat", "priority_tampering")],
                "updated_at": "2026-04-18T09:00:00Z",
            },
            {
                "id": _id("control", "partner_sequence_validation"),
                "title": "Partner feed signing and replay protection",
                "description": "DER and market feeds enforce signature validation, monotonic sequence numbers, and stale-window rejection.",
                "category": "preventive",
                "status": "implemented",
                "owner": "DER Platform Lead",
                "evidence": "API contract and signature validation tests",
                "mapped_threat_ids": [_id("threat", "forged_der_capacity")],
                "updated_at": "2026-04-18T09:00:00Z",
            },
            {
                "id": _id("control", "vendor_session_recorder"),
                "title": "Recorded just-in-time vendor diagnostics",
                "description": "Vendor sessions are brokered, recorded, and denied write access outside approved maintenance windows.",
                "category": "detective",
                "status": "partial",
                "owner": "OT Security Lead",
                "evidence": "Privileged session broker telemetry",
                "mapped_threat_ids": [_id("threat", "vendor_pivot_ot"), _id("threat", "firmware_signing_abuse")],
                "updated_at": "2026-04-18T09:00:00Z",
            },
            {
                "id": _id("control", "tablet_epoching"),
                "title": "Tablet work-package epoch and replay invalidation",
                "description": "Field packages carry topology epochs and are invalidated when outage topology changes.",
                "category": "corrective",
                "status": "planned",
                "owner": "Field Operations Product Owner",
                "evidence": "Backlog item OPS-441",
                "mapped_threat_ids": [_id("threat", "field_replay")],
                "updated_at": "2026-04-18T09:00:00Z",
            },
            {
                "id": _id("control", "telemetry_plausibility"),
                "title": "Cross-feeder telemetry plausibility checks",
                "description": "AMI bursts are cross-validated against historian state and dispatch expectations before high-impact actions.",
                "category": "detective",
                "status": "planned",
                "owner": "Analytics Engineering Manager",
                "evidence": "Pilot analytics notebook and anomaly thresholds",
                "mapped_threat_ids": [_id("threat", "telemetry_poisoning"), _id("threat", "historian_gap")],
                "updated_at": "2026-04-18T09:00:00Z",
            },
            {
                "id": _id("control", "public_status_redaction"),
                "title": "Public status redaction policy",
                "description": "Customer-facing outage updates strip feeder identifiers, crew routing data, and critical-load reasoning.",
                "category": "compensating",
                "status": "implemented",
                "owner": "Digital Channels Manager",
                "evidence": "Content policy and regression snapshot tests",
                "mapped_threat_ids": [_id("threat", "public_recon")],
                "updated_at": "2026-04-18T09:00:00Z",
            },
        ],
        "component_templates": [
            {
                "id": _id("template", "der_fleet_orchestrator"),
                "label": "DER Fleet Orchestrator",
                "description": "Control-plane service that converts market, telemetry, and emergency context into dispatch instructions.",
                "semantic_node_type": "process",
                "semantic_type_label": "DER Orchestrator",
                "shape": "gateway",
                "group": "Utility Control",
                "default_name": "DER Fleet Orchestrator",
                "default_properties": {"runtime_type": "service", "uses_encryption": True, "handles_sensitive_data": True},
                "ai_generated": False,
                "rationale": "Used repeatedly in utility and microgrid control models.",
            },
            {
                "id": _id("template", "substation_gateway"),
                "label": "Substation Telemetry Gateway",
                "description": "Field-edge gateway that brokers telemetry, diagnostics, and signed control bundles.",
                "semantic_node_type": "container",
                "semantic_type_label": "Substation Gateway",
                "shape": "stacked",
                "group": "Utility OT",
                "default_name": "Substation Gateway",
                "default_properties": {"runtime_type": "container", "network_exposure": "dedicated_utility_backhaul", "uses_encryption": True},
                "ai_generated": False,
                "rationale": "Critical edge pattern for utility OT and remote field sites.",
            },
            {
                "id": _id("template", "break_glass_console"),
                "label": "Emergency Dispatch Console",
                "description": "Privileged console used only during declared outage or safety incidents.",
                "semantic_node_type": "process",
                "semantic_type_label": "Emergency Console",
                "shape": "diamond",
                "group": "Utility Ops",
                "default_name": "Emergency Dispatch Console",
                "default_properties": {"privilege_level": "emergency_dispatch", "logging_level": "audit", "uses_auth": True},
                "ai_generated": False,
                "rationale": "Separates emergency-only operator tooling from routine operations tooling.",
            },
            {
                "id": _id("template", "outage_status_publisher"),
                "label": "Outage Status Publisher",
                "description": "Public-facing status fan-out component with redaction responsibilities.",
                "semantic_node_type": "serverless",
                "semantic_type_label": "Status Publisher",
                "shape": "cloud",
                "group": "Customer Experience",
                "default_name": "Outage Status Publisher",
                "default_properties": {"runtime_type": "function", "logging_level": "audit", "validates_input": True},
                "ai_generated": False,
                "rationale": "Captures the pattern where operational truth is transformed before public release.",
            },
        ],
        "property_options": [
            {
                "id": _id("property_option", "emergency_dispatch"),
                "field": "privilege_level",
                "label": "Emergency Dispatch",
                "canonical_value": "emergency_dispatch",
                "description": "Privilege level reserved for declared outage or safety events.",
                "ai_generated": False,
                "rationale": "Needed to distinguish exceptional control authority from standard admin privileges.",
            },
            {
                "id": _id("property_option", "dedicated_utility_backhaul"),
                "field": "network_exposure",
                "label": "Dedicated Utility Backhaul",
                "canonical_value": "dedicated_utility_backhaul",
                "description": "Private field network exposure used by utility OT and AMI devices.",
                "ai_generated": False,
                "rationale": "Helps model non-internet but still high-risk field communication paths.",
            },
            {
                "id": _id("property_option", "internal_cross_zone"),
                "field": "network_exposure",
                "label": "Internal Cross-Zone",
                "canonical_value": "internal_cross_zone",
                "description": "Internal traffic that still crosses material trust or safety zones.",
                "ai_generated": False,
                "rationale": "Captures high-risk east-west paths between cloud, identity, and OT zones.",
            },
            {
                "id": _id("property_option", "ot_control_zone"),
                "field": "isolation_boundary",
                "label": "OT Control Zone",
                "canonical_value": "ot_control_zone",
                "description": "Isolation class for systems that can influence field switching or feeder state.",
                "ai_generated": False,
                "rationale": "Separates operational-safety control assets from ordinary internal services.",
            },
            {
                "id": _id("property_option", "shared_cloud_provider"),
                "field": "responsibility",
                "label": "Shared with Cloud Provider",
                "canonical_value": "shared_cloud_provider",
                "description": "Control ownership is shared with the cloud provider rather than purely customer-managed.",
                "ai_generated": False,
                "rationale": "Useful for shared-responsibility reasoning in hybrid utility platforms.",
            },
            {
                "id": _id("property_option", "contracted_market_partner"),
                "field": "trust_level",
                "label": "Contracted Market Partner",
                "canonical_value": "contracted_market_partner",
                "description": "External party trusted for a narrow dispatch or market function, not for broad internal access.",
                "ai_generated": False,
                "rationale": "Distinguishes regulated market feeds from generic partners.",
            },
        ],
        "governance": {
            "model_snapshots": [
                {
                    "id": _id("snapshot", "baseline"),
                    "name": "Storm Restoration Baseline",
                    "description": "Pre-mutual-aid baseline before seasonal wildfire and contractor expansion.",
                    "created_at": "2026-04-18T09:00:00Z",
                    "created_by": "ops.architect@aurora.example",
                    "node_count": len(root_dfd["nodes"]),
                    "edge_count": len(root_dfd["edges"]),
                    "boundary_count": len(root_dfd["trust_boundaries"]),
                    "threat_count": 3,
                    "dfd": root_dfd,
                    "threats": [_snapshot_threat(item) for item in TMAC_THREATS[:3]],
                }
            ],
            "review_records": [
                {
                    "id": _id("review", "storm_board"),
                    "snapshot_id": _id("snapshot", "baseline"),
                    "title": "Storm Board Safety and Security Review",
                    "status": "pending",
                    "assignee": "grid.security.board@aurora.example",
                    "created_by": "ops.architect@aurora.example",
                    "created_at": "2026-04-18T09:00:00Z",
                    "updated_at": "2026-04-18T09:00:00Z",
                    "signed_off_at": None,
                    "comments": [
                        {
                            "id": _id("review_comment", "storm_board_initial"),
                            "author": "chief.dispatch@aurora.example",
                            "comment": "Safety review wants stronger evidence that break-glass cannot push unreviewed switching into field gateways.",
                            "created_at": "2026-04-18T09:00:00Z",
                        }
                    ],
                }
            ],
        },
        "collaboration": {
            "collaborators": [
                {
                    "id": _id("collaborator", "owner"),
                    "email": "ops.architect@aurora.example",
                    "role": "owner",
                    "status": "active",
                    "invited_by": "ops.architect@aurora.example",
                    "invited_at": "2026-04-18T09:00:00Z",
                    "updated_at": "2026-04-18T09:00:00Z",
                },
                {
                    "id": _id("collaborator", "reviewer"),
                    "email": "grid.security.board@aurora.example",
                    "role": "reviewer",
                    "status": "active",
                    "invited_by": "ops.architect@aurora.example",
                    "invited_at": "2026-04-18T09:00:00Z",
                    "updated_at": "2026-04-18T09:00:00Z",
                },
                {
                    "id": _id("collaborator", "vendor"),
                    "email": "vendor.access@relaygrid.example",
                    "role": "viewer",
                    "status": "invited",
                    "invited_by": "ops.architect@aurora.example",
                    "invited_at": "2026-04-18T09:00:00Z",
                    "updated_at": "2026-04-18T09:00:00Z",
                },
            ],
            "assignments": [
                {
                    "id": _id("assignment", "break_glass_fix"),
                    "title": "Harden emergency override approvals",
                    "description": "Implement dual-control and named-incident enforcement for break-glass dispatch.",
                    "assignee": "ops.security@aurora.example",
                    "priority": "critical",
                    "status": "open",
                    "due_date": "2026-05-31T00:00:00Z",
                    "threat_id": _id("threat", "break_glass_override_abuse"),
                    "review_id": None,
                    "anchor_kind": "threat",
                    "anchor_id": _id("threat", "break_glass_override_abuse"),
                    "anchor_label": "AUR-T002",
                    "created_by": "ops.architect@aurora.example",
                    "created_at": "2026-04-18T09:00:00Z",
                    "updated_at": "2026-04-18T09:00:00Z",
                    "comments": [],
                },
                {
                    "id": _id("assignment", "review_packet"),
                    "title": "Prepare storm board evidence pack",
                    "description": "Collect replay-protection evidence and vendor-session scoping artifacts for the pending board review.",
                    "assignee": "risk.program@aurora.example",
                    "priority": "high",
                    "status": "in_progress",
                    "due_date": "2026-05-10T00:00:00Z",
                    "threat_id": None,
                    "review_id": _id("review", "storm_board"),
                    "anchor_kind": "review",
                    "anchor_id": _id("review", "storm_board"),
                    "anchor_label": "Storm Board Safety and Security Review",
                    "created_by": "ops.architect@aurora.example",
                    "created_at": "2026-04-18T09:00:00Z",
                    "updated_at": "2026-04-18T09:00:00Z",
                    "comments": [],
                },
            ],
            "notifications": [
                {
                    "id": _id("notification", "review_requested"),
                    "type": "review_requested",
                    "title": "Storm board review requested",
                    "message": "Please review the pre-season DER storm-restoration model and focus on break-glass and vendor blast radius.",
                    "status": "unread",
                    "actor": "ops.architect@aurora.example",
                    "target_kind": "review",
                    "target_id": _id("review", "storm_board"),
                    "created_at": "2026-04-18T09:00:00Z",
                }
            ],
        },
    }


AURORA_UTILITY_DER_SCENARIO = {
    "metadata": {
        "scenario_id": SCENARIO_ID,
        "title": "Aurora Utility DER Orchestration and Storm Response Platform",
        "industry": "Electric utility / distributed energy",
        "difficulty": "extreme",
        "analyst_persona": "Principal grid security architect preparing a storm-restoration and safety-control review",
        "description": (
            "Hybrid utility control platform spanning customer outage channels, DER dispatch, "
            "OT switching, vendor diagnostics, field mobility, emergency coordination, and immutable records."
        ),
        "system_name": "Aurora Utility DER Orchestration and Storm Response Platform",
        "data_classification": "Restricted",
        "regulatory_scope": ["NERC CIP", "NIST", "ISO 27001", "PCI DSS"],
        "deployment_model": "hybrid",
        "critical_components": [
            "DER Orchestration Engine",
            "Outage Command Center",
            "SCADA / ADMS Interface",
            "Break-Glass Dispatch Console",
            "Vendor Access Broker",
            "Market Settlement Ledger",
            "Audit and Decision Vault",
        ],
        "critical_flows": [
            "DER Aggregator Partner -> API Mediation Gateway (DER flexibility availability feed)",
            "Load Forecasting Service -> DER Orchestration Engine (load shed and restoration recommendation)",
            "DER Orchestration Engine -> SCADA / ADMS Interface (DER setpoint and feeder reconfiguration request)",
            "Vendor Access Broker -> SCADA / ADMS Interface (approved vendor diagnostic session)",
            "Break-Glass Dispatch Console -> DER Orchestration Engine (emergency override command)",
        ],
        "critical_boundaries": [
            "Cloud Operations Control Plane",
            "OT Operations Zone",
            "Restricted Customer and Settlement Data Zone",
            "Vendor Support Enclave",
        ],
        "narrative_doc": "narrative.pdf",
        "structured_doc": "structured.pdf",
        "delta_doc": "delta.pdf",
    },
    "documents": {
        "narrative": dedent(
            """
            Aurora Utility is consolidating outage management, distributed energy resource dispatch,
            field work coordination, and external emergency coordination into a single storm response
            platform. Customer channels, DER partner integrations, and analytics run in a cloud control
            plane, while switching authority, telemetry historians, and firmware release remain tied to
            operational-technology zones and field gateways.

            The platform serves customers checking outage status, municipal emergency operators
            prioritizing critical facilities, distribution operators dispatching load relief, field crews
            working from tablets with intermittent connectivity, vendor engineers collecting diagnostics,
            and market operators coordinating capacity commitments. During severe weather, these users
            interact under intense time pressure and incomplete information.

            Aurora depends on DER aggregator feeds, meter telemetry, weather forecasts, and ISO dispatch
            schedules to decide whether to curtail load, island microgrids, or reprioritize field work.
            Field tablets can operate offline for hours and later resynchronize work packages and hazard
            notes. Vendor access is allowed only through a brokered enclave, but the same shared services
            that support diagnostics also sit close to SCADA adapters and firmware signing workflows.

            Break-glass dispatch is the defining high-risk path. It exists so the utility can move quickly
            during wildfire, ice storm, or feeder instability events, but it also creates a legitimate
            mechanism to bypass ordinary reviews. The audit vault is supposed to make those actions
            provable, yet operators and reviewers already suspect that telemetry gaps, offline replay, and
            partner trust assumptions could let a determined attacker or pressured insider make unsafe
            decisions look operationally justified.
            """
        ).strip(),
        "structured": dedent(
            """
            System: Aurora Utility DER Orchestration and Storm Response Platform
            Classification: Restricted
            Deployment: Hybrid cloud plus OT control zones
            Regulatory Scope: NERC CIP, NIST, ISO 27001, PCI DSS

            Trust Boundary: Public Customer and External Partner Edge
            Contains:
            - Identity Gateway [api_gateway]
            - API Mediation Gateway [api_gateway]
            - Public Outage Status Publisher [serverless]

            Trust Boundary: Utility Identity and Corporate Core
            Contains:
            - Workforce Identity Directory [managed_service]
            - Vendor Access Broker [process]

            Trust Boundary: Cloud Operations Control Plane
            Contains:
            - Outage Command Center [process]
            - DER Orchestration Engine [process]
            - Load Forecasting Service [process]
            - Work Order Dispatch Service [process]
            - Break-Glass Dispatch Console [process]
            - AMI Ingestion Broker [managed_service]

            Trust Boundary: OT Operations Zone
            Contains:
            - AMI Meter Mesh [external_entity]
            - SCADA / ADMS Interface [process]
            - Substation Edge Gateway [container]
            - Firmware Signing Service [process]
            - Grid Telemetry Historian [data_store]

            Trust Boundary: Restricted Customer and Settlement Data Zone
            Contains:
            - Customer and Billing Data Hub [data_store]
            - Market Settlement Ledger [data_store]
            - Audit and Decision Vault [data_store]
            - Operations Data Lake [data_store]

            Trust Boundary: Field and Mobile Edge
            Contains:
            - Field Technician Tablet [human_actor]

            Trust Boundary: Vendor Support Enclave
            Contains:
            - Vendor Support Enclave [external_entity]

            Trust Boundary: Regulatory and Emergency Coordination Exchange
            Contains:
            - ISO Market Operator API [external_entity]
            - Municipal Emergency Operations Center [external_entity]

            Critical flows:
            - DER Aggregator Partner -> API Mediation Gateway: DER flexibility availability feed
            - ISO Market Operator API -> DER Orchestration Engine: market dispatch and curtailment schedule
            - AMI Meter Mesh -> AMI Ingestion Broker: meter telemetry burst
            - Load Forecasting Service -> DER Orchestration Engine: load shed and restoration recommendation
            - DER Orchestration Engine -> SCADA / ADMS Interface: DER setpoint and feeder reconfiguration request
            - Vendor Access Broker -> SCADA / ADMS Interface: approved vendor diagnostic session
            - Break-Glass Dispatch Console -> DER Orchestration Engine: emergency override command
            - Break-Glass Dispatch Console -> Audit and Decision Vault: break-glass approval record
            - Work Order Dispatch Service -> Field Technician Tablet: offline work package and switching steps
            - Public Outage Status Publisher -> Customer Mobile App: push outage notification
            """
        ).strip(),
        "delta": dedent(
            """
            Change Request: wildfire season mutual-aid expansion

            Aurora is introducing three changes ahead of the next wildfire season:
            1. Mutual-aid contractors will receive temporary field access to accelerate restoration.
            2. Drone inspection imagery will be ingested to prioritize damaged feeders.
            3. Satellite failover sync will be enabled for field tablets when terrestrial backhaul is unavailable.

            New or changed components:
            - Mutual Aid Contractor Console [external_entity]
            - Drone Inspection Relay [serverless]
            - Satellite Failover Gateway [managed_service]

            New or changed flows:
            - Mutual Aid Contractor Console -> Vendor Access Broker: temporary contractor onboarding request
            - Drone Inspection Relay -> Operations Data Lake: wildfire imagery upload
            - Drone Inspection Relay -> Outage Command Center: asset damage alert
            - Field Technician Tablet -> Satellite Failover Gateway: degraded field sync
            - Satellite Failover Gateway -> Work Order Dispatch Service: low-bandwidth work package sync

            Why risk changes:
            - Temporary mutual-aid access expands the privileged identity surface under crisis conditions.
            - Drone imagery adds new sensitive infrastructure reconnaissance and supply-chain trust concerns.
            - Satellite failover introduces a second sync path that can bypass assumptions built around the primary mobile channel.
            """
        ).strip(),
    },
    "gold_dfd": _gold_dfd(),
    "gold_threat_themes": {
        "critical_themes": [
            {
                "id": "AUR-01",
                "title": "Forged DER partner capacity feed",
                "description": "Partner flexibility data is spoofed or replayed, leading to unsafe dispatch commitments and false restoration confidence.",
                "severity": "Critical",
                "stride_categories": ["Spoofing", "Tampering"],
                "affected_assets": ["API Mediation Gateway", "DER Orchestration Engine", "ISO Market Operator API"],
            },
            {
                "id": "AUR-02",
                "title": "Break-glass dispatch override abuse",
                "description": "Emergency dispatch privileges bypass ordinary approvals and allow high-impact control actions.",
                "severity": "Critical",
                "stride_categories": ["Elevation of Privilege", "Tampering", "Repudiation"],
                "affected_assets": ["Break-Glass Dispatch Console", "DER Orchestration Engine", "SCADA / ADMS Interface"],
            },
            {
                "id": "AUR-03",
                "title": "Vendor diagnostics pivot into OT",
                "description": "Brokered vendor support is abused to reach switching logic, firmware release, or field gateways.",
                "severity": "Critical",
                "stride_categories": ["Elevation of Privilege", "Tampering"],
                "affected_assets": ["Vendor Access Broker", "SCADA / ADMS Interface", "Firmware Signing Service"],
            },
            {
                "id": "AUR-04",
                "title": "Offline field replay creates unsafe switching",
                "description": "Stale work packages or hazard notes are replayed after topology changes.",
                "severity": "High",
                "stride_categories": ["Tampering", "Repudiation"],
                "affected_assets": ["Field Technician Tablet", "Work Order Dispatch Service", "Outage Command Center"],
            },
            {
                "id": "AUR-05",
                "title": "Telemetry poisoning drives wrong load-shed decisions",
                "description": "Manipulated AMI events or forged edge telemetry are treated as operational truth.",
                "severity": "Critical",
                "stride_categories": ["Tampering", "Information Disclosure", "Denial of Service"],
                "affected_assets": ["AMI Meter Mesh", "AMI Ingestion Broker", "Load Forecasting Service"],
            },
            {
                "id": "AUR-06",
                "title": "Firmware signing misuse at field gateways",
                "description": "Compromised signing authority or unreviewed vendor packages deploy malicious edge software.",
                "severity": "Critical",
                "stride_categories": ["Elevation of Privilege", "Tampering"],
                "affected_assets": ["Firmware Signing Service", "Substation Edge Gateway"],
            },
            {
                "id": "AUR-07",
                "title": "Emergency priority manipulation",
                "description": "Restoration priorities are silently biased away from actual critical loads or mutual-aid obligations.",
                "severity": "High",
                "stride_categories": ["Tampering", "Repudiation"],
                "affected_assets": ["Municipal Emergency Operations Center", "Outage Command Center", "Work Order Dispatch Service"],
            },
            {
                "id": "AUR-08",
                "title": "Historian and audit gaps hide unauthorized switching",
                "description": "Incomplete telemetry or delayed replication prevents trustworthy reconstruction of field actions.",
                "severity": "High",
                "stride_categories": ["Denial of Service", "Repudiation"],
                "affected_assets": ["Grid Telemetry Historian", "Operations Data Lake", "Audit and Decision Vault"],
            },
        ],
        "important_themes": [
            {
                "id": "AUR-09",
                "title": "Public outage experience leaks operational metadata",
                "description": "Customer-facing status channels expose feeder naming, timing, or critical-load prioritization.",
                "severity": "Medium",
                "stride_categories": ["Information Disclosure"],
                "affected_assets": ["Public Outage Status Publisher"],
            },
            {
                "id": "AUR-10",
                "title": "Settlement and audit records diverge",
                "description": "DER dispatch commitments cannot be cleanly reconciled to immutable operator intent.",
                "severity": "High",
                "stride_categories": ["Repudiation", "Tampering"],
                "affected_assets": ["Market Settlement Ledger", "Audit and Decision Vault"],
            },
            {
                "id": "AUR-11",
                "title": "Identity boundary drift during mutual aid",
                "description": "Temporary identities and contractor onboarding weaken separation between utility and vendor trust.",
                "severity": "High",
                "stride_categories": ["Spoofing", "Elevation of Privilege"],
                "affected_assets": ["Workforce Identity Directory", "Vendor Access Broker"],
            },
            {
                "id": "AUR-12",
                "title": "Meter burst flood degrades control plane",
                "description": "Legitimate-looking telemetry floods overwhelm ingestion and forecasting during incidents.",
                "severity": "High",
                "stride_categories": ["Denial of Service"],
                "affected_assets": ["AMI Ingestion Broker", "Load Forecasting Service"],
            },
            {
                "id": "AUR-13",
                "title": "Critical-load lookup leaks customer context",
                "description": "Restoration workflows reveal customer, premise, or shelter designation data beyond intended audiences.",
                "severity": "Medium",
                "stride_categories": ["Information Disclosure"],
                "affected_assets": ["Customer and Billing Data Hub", "Outage Command Center"],
            },
        ],
        "expected_stride_coverage": [
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege",
        ],
        "critical_assets": [
            "DER Orchestration Engine",
            "SCADA / ADMS Interface",
            "Break-Glass Dispatch Console",
            "Market Settlement Ledger",
            "Audit and Decision Vault",
            "Substation Edge Gateway",
        ],
        "critical_boundaries": [
            "Cloud Operations Control Plane",
            "OT Operations Zone",
            "Restricted Customer and Settlement Data Zone",
            "Vendor Support Enclave",
        ],
        "top_severity_expectations": ["AUR-01", "AUR-02", "AUR-03", "AUR-05", "AUR-06"],
        "must_not_hallucinate": [
            "nuclear reactor safety system",
            "consumer card-present payment terminal estate",
            "aircraft maintenance dispatch",
            "hospital radiology archive",
        ],
    },
    "must_not_hallucinate": [
        "consumer social media login",
        "crypto token bridge",
        "nuclear plant PLC",
        "airline passenger reservation system",
    ],
    "delta_patch": {
        "add_nodes": [
            _node(
                "mutual_aid_contractor_console",
                "external_entity",
                "Mutual Aid Contractor Console",
                220,
                660,
                properties={"entity_kind": "human", "entity_scope": "external", "authenticated": True, "trust_level": "mutual_aid_authority"},
            ),
            _node(
                "drone_inspection_relay",
                "serverless",
                "Drone Inspection Relay",
                900,
                660,
                boundary="cloud_control_plane",
                properties={"runtime_type": "function", "uses_encryption": True, "logging_level": "audit"},
            ),
            _node(
                "satellite_failover_gateway",
                "managed_service",
                "Satellite Failover Gateway",
                520,
                660,
                boundary="cloud_control_plane",
                properties={"service_name": "Resilient Field Sync", "uses_encryption": True, "network_exposure": "dedicated_utility_backhaul"},
            ),
        ],
        "add_edges": [
            _edge("mutual_aid_onboarding", "mutual_aid_contractor_console", "vendor_access_broker", "temporary contractor onboarding request"),
            _edge("drone_imagery_upload", "drone_inspection_relay", "operations_data_lake", "wildfire imagery upload"),
            _edge("drone_damage_alert", "drone_inspection_relay", "outage_command_center", "asset damage alert"),
            _edge("satellite_field_sync", "field_technician_tablet", "satellite_failover_gateway", "degraded field sync"),
            _edge("satellite_work_package", "satellite_failover_gateway", "work_order_dispatch_service", "low-bandwidth work package sync"),
        ],
        "add_boundary_membership": {
            "Cloud Operations Control Plane": [
                _id("node", "drone_inspection_relay"),
                _id("node", "satellite_failover_gateway"),
            ],
        },
    },
    "tmac": _tmac_document(),
    "readme": dedent(
        """
        # Aurora Utility DER Benchmark

        This scenario is the long-lived stress fixture for mixed IT/OT threat modeling in ThreatGenix.

        It is intentionally harder than the bank, healthcare, OT, and airline baselines because it combines:

        - customer-facing outage workflows
        - DER market dispatch and settlement
        - safety-relevant feeder and restoration decisions
        - offline field operations
        - vendor diagnostics near OT control paths
        - break-glass dispatch authority
        - governance, collaboration, and immutable decision evidence

        Files in this directory:

        - `metadata.yaml`: scenario metadata used by the eval harness
        - `gold_threat_themes.yaml`: benchmark threat themes and expected coverage
        - `must_not_hallucinate.yaml`: themes that should not appear
        - `gold_dfd.json`: gold DFD fixture
        - `threat_model.tmac.yaml`: full Threat Model as Code fixture for direct import into ThreatGenix
        - `narrative.pdf`: architecture narrative
        - `structured.pdf`: structured architecture brief
        - `delta.pdf`: change request that shifts the threat landscape

        Recommended uses:

        - TMAC validation/import regression
        - DFD quality-gate benchmarking
        - assistant threat-modeling evals
        - browser smoke tests against a dense, nuanced model
        - future scenario expansion for wildfire, mutual-aid, or satellite-failover changes
        """
    ).strip()
    + "\n",
}
