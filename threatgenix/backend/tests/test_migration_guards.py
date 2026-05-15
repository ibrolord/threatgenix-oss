from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest


MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations" / "versions"


def _load_migration_module(filename: str) -> ModuleType:
    path = MIGRATIONS_DIR / filename
    spec = spec_from_file_location(f"migration_{filename.replace('.py', '')}", path)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeInspector:
    def __init__(
        self,
        existing_columns: dict[str, list[str]],
        existing_tables: list[str] | None = None,
    ) -> None:
        self.existing_columns = existing_columns
        self.existing_tables = existing_tables or list(existing_columns)

    def get_columns(self, table_name: str):
        return [
            {"name": column_name}
            for column_name in self.existing_columns.get(table_name, [])
        ]

    def get_table_names(self):
        return list(self.existing_tables)

    def get_indexes(self, table_name: str):
        return []

    def get_foreign_keys(self, table_name: str):
        return []

    def get_unique_constraints(self, table_name: str):
        return []

    def get_check_constraints(self, table_name: str):
        return []


@pytest.mark.parametrize(
    ("filename", "existing_columns", "expected_added"),
    [
        (
            "001_add_regulatory_scope_deployment_model.py",
            {"threat_models": ["regulatory_scope"]},
            [("threat_models", "deployment_model")],
        ),
        (
            "002_add_relevance_rationale_to_threats.py",
            {"threats": ["relevance_rationale"]},
            [],
        ),
        (
            "004_add_environment_evidence_columns.py",
            {"threat_models": ["cloud_scan_evidence"]},
            [
                ("threat_models", "repository_evidence"),
                ("threat_models", "environment_context_summary"),
            ],
        ),
        (
            "005_add_report_customization.py",
            {"threat_models": ["report_logo_base64", "report_template"]},
            [("threat_models", "report_watermark_text")],
        ),
        (
            "008_add_arch_diagrams.py",
            {"threat_models": ["arch_diagrams"]},
            [],
        ),
        (
            "027_add_report_templates.py",
            {"threat_models": ["report_templates"]},
            [],
        ),
        (
            "029_add_user_report_template_library.py",
            {"users": ["report_template_library"]},
            [],
        ),
        (
            "064_repair_threat_model_report_attestation_columns.py",
            {"threat_models": ["analyst_name"]},
            [
                ("threat_models", "analyst_attestation"),
                ("threat_models", "next_review_date"),
                ("threat_models", "out_of_scope_statement"),
            ],
        ),
    ],
)
def test_column_guarded_migrations_only_add_missing_columns(
    filename: str,
    existing_columns: dict[str, list[str]],
    expected_added: list[tuple[str, str]],
):
    module = _load_migration_module(filename)
    added_columns: list[tuple[str, str]] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.sa.inspect = Mock(return_value=_FakeInspector(existing_columns))

    module.upgrade()

    assert added_columns == expected_added


def test_schema_updates_migration_skips_existing_snapshot_column():
    module = _load_migration_module("003_weeks5_8_schema_updates.py")
    added_columns: list[tuple[str, str]] = []

    existing_column_rows = {
        "framework": None,
        "control_id": None,
        "control_name": None,
        "nist_control_id": None,
    }

    class _FakeResult:
        def __init__(self, value):
            self._value = value

        def fetchone(self):
            return self._value

    class _FakeConnection:
        def execute(self, statement):
            sql = str(statement)
            for column_name, row in existing_column_rows.items():
                if f"column_name = '{column_name}'" in sql:
                    return _FakeResult(row)
            if "table_name = 'threat_audit_logs'" in sql:
                return _FakeResult(None)
            # Constraint existence checks — return None so migration proceeds to create
            if "table_constraints" in sql:
                return _FakeResult(None)
            # DDL-style statements (DROP CONSTRAINT, ALTER TABLE) return no rows
            if "ALTER TABLE" in sql or "DROP CONSTRAINT" in sql:
                return _FakeResult(None)

    module.op.get_bind = Mock(return_value=_FakeConnection())
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.op.drop_constraint = Mock()
    module.op.create_unique_constraint = Mock()
    module.op.create_check_constraint = Mock()
    module.op.create_table = Mock()
    module.op.create_index = Mock()
    module.sa.inspect = Mock(
        return_value=_FakeInspector({"threat_models": ["last_analyzed_threats"]})
    )

    module.upgrade()

    assert ("threat_models", "last_analyzed_threats") not in added_columns


def test_arch_diagrams_migration_declares_revision_metadata():
    module = _load_migration_module("008_add_arch_diagrams.py")

    assert module.revision == "008"
    assert module.down_revision == "007"


def test_organization_template_migration_creates_table_and_link_column_when_missing():
    module = _load_migration_module("030_add_organizations_for_report_templates.py")
    created_tables: list[str] = []
    added_columns: list[tuple[str, str]] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []
    created_foreign_keys: list[tuple[str, str, str]] = []

    class _FakeRows:
        def mappings(self):
            return []

    module.op.get_bind = Mock(return_value=Mock(execute=Mock(return_value=_FakeRows())))
    module.op.create_table = Mock(
        side_effect=lambda table_name, *columns, **kwargs: created_tables.append(
            table_name
        )
    )
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )
    module.op.create_foreign_key = Mock(
        side_effect=lambda name,
        source,
        referent,
        local_cols,
        remote_cols,
        **kwargs: created_foreign_keys.append((name, source, referent))
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector({"users": []}, existing_tables=["users"])
    )

    module.upgrade()

    assert created_tables == ["organizations"]
    assert added_columns == [("users", "organization_id")]
    assert created_indexes == [
        ("ix_users_organization_id", "users", ("organization_id",))
    ]
    assert created_foreign_keys == [
        ("fk_users_organization_id", "users", "organizations")
    ]


def test_scan_execution_artifacts_migration_creates_metadata_table_once():
    module = _load_migration_module("037_add_scan_execution_artifacts.py")
    created_tables: list[str] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []

    module.op.create_table = Mock(
        side_effect=lambda table_name, *columns, **kwargs: created_tables.append(
            table_name
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )
    module.op.get_bind = Mock(return_value=object())
    module.sa.inspect = Mock(
        return_value=_FakeInspector({}, existing_tables=["scan_jobs"])
    )

    module.upgrade()

    assert created_tables == ["scan_execution_artifacts"]
    assert created_indexes == [
        (
            "ix_scan_execution_artifacts_scan_job_id",
            "scan_execution_artifacts",
            ("scan_job_id",),
        )
    ]


def test_validation_tool_limit_migration_refreshes_current_constraints():
    module = _load_migration_module("041_limit_validation_tools_to_current_set.py")
    executed_sql: list[str] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector(
            {}, existing_tables=["scan_jobs", "validation_schedules"]
        )
    )

    module.upgrade()

    assert any(
        "UPDATE scan_jobs SET tool_name = 'nuclei'" in sql for sql in executed_sql
    )
    assert any(
        "UPDATE validation_schedules SET target_type = 'url'" in sql
        for sql in executed_sql
    )
    assert any("ADD CONSTRAINT ck_scan_jobs_tool_name" in sql for sql in executed_sql)
    assert any(
        "ADD CONSTRAINT ck_validation_schedules_target_type" in sql
        for sql in executed_sql
    )
    tool_constraint_sql = [
        sql for sql in executed_sql if "ADD CONSTRAINT" in sql and "tool_name" in sql
    ]
    assert all(
        "CHECK (tool_name IN ('nuclei','semgrep','osv-scanner','trivy','checkov'))"
        in sql
        for sql in tool_constraint_sql
    )


def test_auth_recovery_migration_creates_missing_auth_tables_and_email_flag():
    module = _load_migration_module("048_add_auth_recovery_tables.py")
    added_columns: list[tuple[str, str]] = []
    created_tables: list[str] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []

    module.op.get_bind = Mock(return_value=object())
    module.sa.inspect = Mock(
        return_value=_FakeInspector({"users": []}, existing_tables=["users"])
    )
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.op.create_table = Mock(
        side_effect=lambda table_name, *columns, **kwargs: created_tables.append(
            table_name
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )

    module.upgrade()

    assert added_columns == [("users", "email_verified")]
    assert created_tables == ["email_verifications", "password_reset_tokens"]
    assert created_indexes == [
        ("ix_email_verifications_user_id", "email_verifications", ("user_id",)),
        ("ix_password_reset_tokens_user_id", "password_reset_tokens", ("user_id",)),
    ]


def test_owner_not_null_migration_creates_disabled_sentinel_owner_before_backfill():
    module = _load_migration_module("047_owner_id_not_null.py")
    executed: list[tuple[str, dict | None]] = []

    class _FakeBind:
        def execute(self, statement, params=None):
            executed.append((str(statement), params))

    class _FakeBatch:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def alter_column(self, *args, **kwargs):
            executed.append((f"alter_column:{args[0]}", kwargs))

    module.op.get_bind = Mock(return_value=_FakeBind())
    module.sa.inspect = Mock(
        return_value=_FakeInspector(
            {
                "users": [
                    "id",
                    "email",
                    "hashed_password",
                    "full_name",
                    "role",
                    "is_active",
                    "email_verified",
                    "organization_id",
                ],
                "organizations": ["id", "name", "subscription_tier", "is_active"],
                "threat_models": ["owner_id"],
            },
            existing_tables=["users", "organizations", "threat_models"],
        )
    )
    module.op.execute = Mock(
        side_effect=lambda statement: executed.append((str(statement), None))
    )
    module.op.batch_alter_table = Mock(return_value=_FakeBatch())

    module.upgrade()

    sql = "\n".join(item[0] for item in executed)
    assert "INSERT INTO organizations" in sql
    assert "INSERT INTO users" in sql
    assert "UPDATE threat_models SET owner_id" in sql
    assert any(
        params and params.get("id") == module.SENTINEL_OWNER_UUID
        for _, params in executed
    )


def test_saas_auth_repair_migration_restores_missing_columns_and_tables():
    module = _load_migration_module("057_repair_saas_auth_columns.py")
    added_columns: list[tuple[str, str]] = []
    created_tables: list[str] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []

    module.op.get_bind = Mock(return_value=object())
    module.sa.inspect = Mock(
        return_value=_FakeInspector(
            {
                "organizations": ["id", "name"],
                "users": ["id", "email"],
            },
            existing_tables=["organizations", "users"],
        )
    )
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.op.create_table = Mock(
        side_effect=lambda table_name, *columns, **kwargs: created_tables.append(
            table_name
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )

    module.upgrade()

    assert added_columns == [
        ("organizations", "subscription_tier"),
        ("organizations", "is_active"),
        ("users", "email_verified"),
    ]
    assert created_tables == ["email_verifications", "password_reset_tokens"]
    assert created_indexes == [
        ("ix_email_verifications_user_id", "email_verifications", ("user_id",)),
        ("ix_password_reset_tokens_user_id", "password_reset_tokens", ("user_id",)),
    ]


def test_stamped_saas_auth_repair_migration_uses_idempotent_sql():
    module = _load_migration_module("058_repair_stamped_saas_auth_schema.py")
    executed_sql: list[str] = []

    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )

    module.upgrade()

    sql = "\n".join(executed_sql)
    assert "ADD COLUMN IF NOT EXISTS subscription_tier" in sql
    assert "ADD COLUMN IF NOT EXISTS is_active" in sql
    assert "ADD COLUMN IF NOT EXISTS email_verified" in sql
    assert "CREATE TABLE IF NOT EXISTS email_verifications" in sql
    assert "CREATE TABLE IF NOT EXISTS password_reset_tokens" in sql
    assert "CREATE INDEX IF NOT EXISTS ix_email_verifications_user_id" in sql
    assert "CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_user_id" in sql


def test_external_evidence_import_migration_extends_scan_job_tool_constraint():
    module = _load_migration_module("042_add_external_evidence_import_sources.py")
    executed_sql: list[str] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector({}, existing_tables=["scan_jobs"])
    )

    module.upgrade()

    constraint_sql = " ".join(executed_sql)
    assert "ADD CONSTRAINT ck_scan_jobs_tool_name" in constraint_sql
    assert "external-report" in constraint_sql
    assert "pentest-report" in constraint_sql


def test_trufflehog_validation_tool_migration_refreshes_runner_constraints():
    module = _load_migration_module("050_add_trufflehog_validation_tool.py")
    executed_sql: list[str] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector(
            {}, existing_tables=["scan_jobs", "validation_schedules"]
        )
    )

    module.upgrade()

    constraint_sql = " ".join(executed_sql)
    assert "ADD CONSTRAINT ck_scan_jobs_tool_name" in constraint_sql
    assert "ADD CONSTRAINT ck_validation_schedules_tool_name" in constraint_sql
    assert "trufflehog" in constraint_sql
    assert "external-report" in constraint_sql
    assert "pentest-report" in constraint_sql
    assert "zap-baseline" not in constraint_sql
    assert "promptfoo" not in constraint_sql


def test_trufflehog_schedule_constraint_repair_refreshes_runner_constraints():
    module = _load_migration_module(
        "065_repair_trufflehog_validation_schedule_constraint.py"
    )
    executed_sql: list[str] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector(
            {}, existing_tables=["scan_jobs", "validation_schedules"]
        )
    )

    module.upgrade()

    constraint_sql = " ".join(executed_sql)
    assert "ADD CONSTRAINT ck_scan_jobs_tool_name" in constraint_sql
    assert "ADD CONSTRAINT ck_validation_schedules_tool_name" in constraint_sql
    assert "trufflehog" in constraint_sql
    assert "external-report" in constraint_sql
    assert "pentest-report" in constraint_sql


def test_validation_target_bundle_migration_creates_table_and_indexes_once():
    module = _load_migration_module("066_add_validation_target_bundles.py")
    created_tables: list[str] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.create_table = Mock(
        side_effect=lambda table_name, *columns, **kwargs: created_tables.append(
            table_name
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector({}, existing_tables=["scan_jobs"])
    )

    module.upgrade()

    assert created_tables == ["validation_target_bundles"]
    assert created_indexes == [
        (
            "ix_validation_target_bundles_threat_model_created",
            "validation_target_bundles",
            ("threat_model_id", "created_at"),
        ),
        (
            "ix_validation_target_bundles_owner",
            "validation_target_bundles",
            ("owner_id",),
        ),
    ]


def test_validation_target_bundle_migration_skips_existing_table_and_indexes():
    module = _load_migration_module("066_add_validation_target_bundles.py")

    class _Inspector(_FakeInspector):
        def get_indexes(self, table_name: str):
            assert table_name == "validation_target_bundles"
            return [
                {"name": "ix_validation_target_bundles_threat_model_created"},
                {"name": "ix_validation_target_bundles_owner"},
            ]

    module.op.get_bind = Mock(return_value=object())
    module.op.create_table = Mock()
    module.op.create_index = Mock()
    module.sa.inspect = Mock(
        return_value=_Inspector({}, existing_tables=["validation_target_bundles"])
    )

    module.upgrade()

    module.op.create_table.assert_not_called()
    module.op.create_index.assert_not_called()


def test_remediation_webhook_nonce_migration_creates_table_and_index_once():
    module = _load_migration_module("071_add_remediation_webhook_nonces.py")
    created_tables: list[str] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.create_table = Mock(
        side_effect=lambda table_name, *columns, **kwargs: created_tables.append(
            table_name
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )
    module.sa.inspect = Mock(return_value=_FakeInspector({}, existing_tables=[]))

    module.upgrade()

    assert created_tables == ["remediation_webhook_nonces"]
    assert created_indexes == [
        (
            "ix_remediation_webhook_nonces_expires_at",
            "remediation_webhook_nonces",
            ("expires_at",),
        )
    ]


def test_application_review_lifecycle_migration_refreshes_status_constraint():
    module = _load_migration_module("072_expand_application_review_lifecycle_statuses.py")
    executed_sql: list[str] = []
    created_checks: list[tuple[str, str, str]] = []

    module.op.get_bind = Mock(return_value=object())
    module.sa.inspect = Mock(
        return_value=_FakeInspector({}, existing_tables=["application_security_reviews"])
    )
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )
    module.op.create_check_constraint = Mock(
        side_effect=lambda name, table_name, condition: created_checks.append(
            (name, table_name, condition)
        )
    )

    module.upgrade()

    joined = " ".join(executed_sql)
    assert "DROP CONSTRAINT IF EXISTS ck_application_security_reviews_status" in joined
    assert "ALTER COLUMN status TYPE VARCHAR(32)" in joined
    assert "WHEN 'pending' THEN 'created'" in joined
    assert "WHEN 'running' THEN 'scanning'" in joined
    assert created_checks == [
        (
            "ck_application_security_reviews_status",
            "application_security_reviews",
            (
                "status IN ('created','intake_required','bundle_required',"
                "'bundle_received','scanning','extracting_context','indexing',"
                "'building_graph','deciding','explaining','completed',"
                "'blocked_by_policy','blocked_by_permission','failed_retryable',"
                "'failed_terminal','cancelled')"
            ),
        )
    ]


def test_application_review_bundle_integrity_migration_adds_metadata_and_active_index():
    module = _load_migration_module("073_harden_application_review_bundles.py")
    added_columns: list[tuple[str, str]] = []
    created_checks: list[tuple[str, str, str]] = []
    created_indexes: list[tuple[str, str, tuple[str, ...], bool, object]] = []
    executed_sql: list[str] = []

    module.op.get_bind = Mock(return_value=object())
    module.sa.inspect = Mock(
        return_value=_FakeInspector({}, existing_tables=["application_review_bundles"])
    )
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )
    module.op.create_check_constraint = Mock(
        side_effect=lambda name, table_name, condition: created_checks.append(
            (name, table_name, condition)
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns), kwargs.get("unique", False), kwargs.get("postgresql_where"))
        )
    )

    module.upgrade()

    assert added_columns == [
        ("application_review_bundles", "redaction_report"),
        ("application_review_bundles", "integrity"),
        ("application_review_bundles", "storage_backend"),
        ("application_review_bundles", "encryption_status"),
        ("application_review_bundles", "retention_expires_at"),
        ("application_review_bundles", "legal_hold"),
    ]
    assert "DROP CONSTRAINT IF EXISTS ck_application_review_bundles_kind" in " ".join(executed_sql)
    assert (
        "ck_application_review_bundles_kind",
        "application_review_bundles",
        "bundle_kind IN ('diff','snapshot','metadata','existing_evidence')",
    ) in created_checks
    assert (
        "ck_application_review_bundles_status",
        "application_review_bundles",
        "status IN ('ready','superseded','deleted')",
    ) in created_checks
    assert created_indexes[0][0:4] == (
        "ix_application_review_bundles_one_ready",
        "application_review_bundles",
        ("tenant_key", "review_id"),
        True,
    )


def test_evidence_graph_migration_creates_projection_tables_and_indexes():
    module = _load_migration_module("051_add_evidence_graph.py")
    created_tables: list[str] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.create_table = Mock(
        side_effect=lambda table_name, *columns, **kwargs: created_tables.append(
            table_name
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector({}, existing_tables=["threat_models", "users"])
    )

    module.upgrade()

    assert created_tables == [
        "evidence_sources",
        "evidence_items",
        "evidence_entities",
        "evidence_observations",
        "evidence_relationships",
        "evidence_findings",
        "evidence_finding_links",
    ]
    assert (
        "ix_evidence_sources_threat_model_type",
        "evidence_sources",
        ("threat_model_id", "source_type"),
    ) in created_indexes
    assert (
        "ix_evidence_entities_threat_model_type",
        "evidence_entities",
        ("threat_model_id", "entity_type"),
    ) in created_indexes
    assert (
        "ix_evidence_findings_threat_model_status",
        "evidence_findings",
        ("threat_model_id", "status"),
    ) in created_indexes


def test_orchestration_migration_creates_job_task_event_tables():
    module = _load_migration_module("052_add_orchestration_jobs.py")
    created_tables: list[str] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.create_table = Mock(
        side_effect=lambda table_name, *columns, **kwargs: created_tables.append(
            table_name
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector(
            {},
            existing_tables=["threat_models", "users"],
        )
    )

    module.upgrade()

    assert created_tables == [
        "orchestration_jobs",
        "orchestration_tasks",
        "orchestration_events",
    ]
    assert (
        "ix_orchestration_jobs_threat_model_status",
        "orchestration_jobs",
        ("threat_model_id", "status"),
    ) in created_indexes
    assert (
        "ix_orchestration_tasks_job_status",
        "orchestration_tasks",
        ("job_id", "status"),
    ) in created_indexes
    assert (
        "ix_orchestration_events_job_created",
        "orchestration_events",
        ("job_id", "created_at"),
    ) in created_indexes


def test_threat_model_tenant_migration_backfills_and_indexes_organization_id():
    module = _load_migration_module("056_add_threat_model_tenant_id.py")
    added_columns: list[tuple[str, str]] = []
    created_indexes: list[tuple[str, str, tuple[str, ...]]] = []
    created_foreign_keys: list[
        tuple[str, str, str, tuple[str, ...], tuple[str, ...]]
    ] = []
    executed_sql: list[str] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns))
        )
    )
    module.op.create_foreign_key = Mock(
        side_effect=lambda name,
        source,
        target,
        local_cols,
        remote_cols,
        **kwargs: created_foreign_keys.append(
            (name, source, target, tuple(local_cols), tuple(remote_cols))
        )
    )
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector(
            {
                "threat_models": ["id", "owner_id"],
                "users": ["id", "organization_id"],
                "organizations": ["id"],
            },
            existing_tables=["threat_models", "users", "organizations"],
        )
    )

    module.upgrade()

    assert added_columns == [("threat_models", "organization_id")]
    assert (
        "ix_threat_models_organization_id",
        "threat_models",
        ("organization_id",),
    ) in created_indexes
    assert (
        "fk_threat_models_organization_id",
        "threat_models",
        "organizations",
        ("organization_id",),
        ("id",),
    ) in created_foreign_keys
    assert "UPDATE threat_models" in " ".join(executed_sql)


def test_validation_worker_version_text_migration_uses_idempotent_do_block():
    module = _load_migration_module("062_force_validation_worker_version_text.py")
    executed_sql: list[str] = []
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )

    module.upgrade()

    joined = " ".join(executed_sql)
    assert "validation_worker_heartbeats" in joined
    assert "ALTER COLUMN version TYPE TEXT" in joined
    assert "information_schema.columns" in joined


def test_integrity_hardening_migration_adds_model_scoped_constraints():
    module = _load_migration_module("053_harden_evidence_orchestration_integrity.py")
    added_columns: list[tuple[str, str]] = []
    unique_constraints: list[tuple[str, str, tuple[str, ...]]] = []
    foreign_keys: list[tuple[str, str, str, tuple[str, ...], tuple[str, ...]]] = []
    check_constraints: list[tuple[str, str]] = []
    created_indexes: list[tuple[str, str, tuple[str, ...], bool]] = []

    tables = [
        "evidence_sources",
        "evidence_items",
        "evidence_entities",
        "evidence_observations",
        "evidence_relationships",
        "evidence_findings",
        "evidence_finding_links",
        "orchestration_jobs",
        "orchestration_tasks",
        "orchestration_events",
    ]
    existing_columns = {table_name: ["id", "threat_model_id"] for table_name in tables}
    existing_columns["orchestration_jobs"] = ["id", "threat_model_id", "owner_id"]

    module.op.get_bind = Mock(return_value=object())
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.op.create_unique_constraint = Mock(
        side_effect=lambda name, table_name, columns: unique_constraints.append(
            (name, table_name, tuple(columns))
        )
    )
    module.op.create_foreign_key = Mock(
        side_effect=lambda name,
        table_name,
        ref_table,
        columns,
        ref_columns,
        **kwargs: foreign_keys.append(
            (name, table_name, ref_table, tuple(columns), tuple(ref_columns))
        )
    )
    module.op.create_check_constraint = Mock(
        side_effect=lambda name, table_name, condition: check_constraints.append(
            (name, table_name)
        )
    )
    module.op.create_index = Mock(
        side_effect=lambda name, table_name, columns, **kwargs: created_indexes.append(
            (name, table_name, tuple(columns), bool(kwargs.get("unique")))
        )
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector(existing_columns, existing_tables=tables)
    )

    module.upgrade()

    assert added_columns == [("orchestration_jobs", "idempotency_key")]
    assert (
        "uq_evidence_sources_id_model",
        "evidence_sources",
        ("id", "threat_model_id"),
    ) in unique_constraints
    assert (
        "fk_evidence_items_source_model",
        "evidence_items",
        "evidence_sources",
        ("source_id", "threat_model_id"),
        ("id", "threat_model_id"),
    ) in foreign_keys
    assert (
        "fk_orchestration_tasks_job_model",
        "orchestration_tasks",
        "orchestration_jobs",
        ("job_id", "threat_model_id"),
        ("id", "threat_model_id"),
    ) in foreign_keys
    assert (
        "ck_orchestration_tasks_attempt_bounds",
        "orchestration_tasks",
    ) in check_constraints
    assert (
        "ix_orchestration_jobs_idempotency",
        "orchestration_jobs",
        ("threat_model_id", "owner_id", "idempotency_key"),
        True,
    ) in created_indexes


def test_mitigation_migration_skips_existing_columns_and_refreshes_constraint():
    module = _load_migration_module("006_add_mitigation_fields.py")
    added_columns: list[tuple[str, str]] = []
    executed_sql: list[str] = []

    module.op.get_bind = Mock(return_value=object())
    module.op.add_column = Mock(
        side_effect=lambda table_name, column: added_columns.append(
            (table_name, column.name)
        )
    )
    module.op.execute = Mock(
        side_effect=lambda statement: executed_sql.append(str(statement))
    )
    module.sa.inspect = Mock(
        return_value=_FakeInspector(
            {"threats": ["mitigation_plan", "mitigation_owner", "closed_at"]}
        )
    )

    module.upgrade()

    assert added_columns == [
        ("threats", "due_date"),
        ("threats", "mitigation_notes"),
    ]
    assert any(
        "DROP CONSTRAINT IF EXISTS ck_threats_status" in sql for sql in executed_sql
    )
    assert any("ADD CONSTRAINT ck_threats_status" in sql for sql in executed_sql)
