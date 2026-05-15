from app.seed import (
    BOOTSTRAP_SCHEMA_REPAIRS,
    THREAT_MODEL_JSONB_REPAIRS,
    VECTOR_THREAT_INTEL_TABLES,
    get_bootstrap_table_names,
    repair_runtime_schema,
    repair_threat_model_schema,
)


def test_get_bootstrap_table_names_skips_vector_tables_without_pgvector():
    table_names = get_bootstrap_table_names(pgvector_enabled=False)

    assert VECTOR_THREAT_INTEL_TABLES.isdisjoint(table_names)
    assert {"users", "threat_models", "documents", "cri_mappings", "kev_entries", "threat_intel_syncs"} <= table_names


def test_get_bootstrap_table_names_includes_vector_tables_with_pgvector():
    table_names = get_bootstrap_table_names(pgvector_enabled=True)

    assert VECTOR_THREAT_INTEL_TABLES <= table_names


def test_repair_threat_model_schema_adds_missing_jsonb_columns():
    statements = []

    class FakeSyncConn:
        def execute(self, statement):
            statements.append(str(statement))

    repair_threat_model_schema(FakeSyncConn())

    for column_name, _column_type in THREAT_MODEL_JSONB_REPAIRS:
        assert any(
            f"ADD COLUMN IF NOT EXISTS {column_name}" in statement
            for statement in statements
        )


def test_repair_runtime_schema_backfills_threat_citations_column():
    statements = []

    class FakeSyncConn:
        def execute(self, statement):
            statements.append(str(statement))

    repair_runtime_schema(FakeSyncConn())

    assert ("threats", "citations", "JSONB NOT NULL DEFAULT '[]'::jsonb") in BOOTSTRAP_SCHEMA_REPAIRS
    assert any(
        "ALTER TABLE IF EXISTS threats ADD COLUMN IF NOT EXISTS citations JSONB NOT NULL DEFAULT '[]'::jsonb"
        in statement
        for statement in statements
    )


def test_repair_runtime_schema_backfills_sandbox_artifact_columns():
    statements = []

    class FakeSyncConn:
        def execute(self, statement):
            statements.append(str(statement))

    repair_runtime_schema(FakeSyncConn())

    assert ("scan_execution_artifacts", "sandbox_mode", "VARCHAR(30)") in BOOTSTRAP_SCHEMA_REPAIRS
    assert any(
        "ALTER TABLE IF EXISTS scan_execution_artifacts ADD COLUMN IF NOT EXISTS resource_limits JSONB NOT NULL DEFAULT '{}'::jsonb"
        in statement
        for statement in statements
    )
