"""Level 0: Can it start?"""
import subprocess
import pytest
from conftest import BACKEND_BASE, FRONTEND_DIR


@pytest.mark.order(0)
class TestSmoke:

    def test_backend_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_db_connection(self, db_conn):
        cur = db_conn.cursor()
        cur.execute("SELECT 1")
        assert cur.fetchone()[0] == 1
        cur.close()

    def test_db_tables_exist(self, db_conn):
        expected = {
            "threat_models", "documents", "dfd_nodes", "dfd_edges",
            "trust_boundaries", "threats", "compliance_mappings",
        }
        cur = db_conn.cursor()
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public'"
        )
        tables = {row[0] for row in cur.fetchall()}
        cur.close()
        missing = expected - tables
        assert not missing, f"Missing tables: {missing}"

    def test_frontend_typecheck(self):
        import os
        env = os.environ.copy()
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + env.get("PATH", "")
        result = subprocess.run(
            ["npx", "tsc", "--noEmit"],
            cwd=str(FRONTEND_DIR),
            capture_output=True, timeout=120,
            env=env,
        )
        assert result.returncode == 0, f"TypeScript errors:\n{result.stdout.decode()}\n{result.stderr.decode()}"

    def test_frontend_builds(self):
        import os
        env = os.environ.copy()
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + env.get("PATH", "")
        result = subprocess.run(
            ["npm", "run", "build"],
            cwd=str(FRONTEND_DIR),
            capture_output=True, timeout=120,
            env=env,
        )
        assert result.returncode == 0, f"Build failed:\n{result.stdout.decode()}\n{result.stderr.decode()}"
