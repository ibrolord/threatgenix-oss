"""Live HTTP regression for tenant-scoped threat CSV export."""

from __future__ import annotations

import csv
import io

import httpx

from conftest import BACKEND_BASE


EXPECTED_HEADERS = [
    "ID",
    "Description",
    "STRIDE Category",
    "Severity",
    "Status",
    "Control Effectiveness",
    "Residual Risk",
    "Source",
    "Rule ID",
    "Dismiss Reason",
    "Mitigation Plan",
    "Mitigation Owner",
    "Due Date",
    "Relevance Rationale",
    "Compliance Controls",
    "Created At",
    "Closed At",
    "AI Enhanced",
]


def test_threat_csv_export_headers_rows_and_owner_scope(
    client: httpx.Client,
    factories,
    make_auth_headers,
):
    model = factories.create_report_ready_model(system_name="CSV Export Scope App")
    threats = factories.generate_threats(model["id"])

    response = client.get(f"/api/threat-models/{model['id']}/threats/export.csv")

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    assert f"threats-{model['id']}.csv" in response.headers["content-disposition"]

    reader = csv.DictReader(io.StringIO(response.text))
    rows = list(reader)
    assert reader.fieldnames == EXPECTED_HEADERS
    assert len(rows) == len(threats)
    assert {row["ID"] for row in rows} == {threat["display_id"] for threat in threats}
    assert {row["Source"] for row in rows} == {"Rules"}
    assert all(row["Residual Risk"] for row in rows)

    isolated_headers = make_auth_headers("qa-csv-owner")
    with httpx.Client(
        base_url=BACKEND_BASE,
        timeout=30,
        headers=isolated_headers,
    ) as isolated_client:
        isolated_model = isolated_client.post(
            "/api/threat-models",
            json={
                "system_name": "Other Tenant CSV App",
                "description": "Owned by another e2e org",
                "data_classification": "Internal",
            },
        )
    assert isolated_model.status_code == 201, isolated_model.text

    blocked = client.get(
        f"/api/threat-models/{isolated_model.json()['id']}/threats/export.csv"
    )
    assert blocked.status_code == 403
