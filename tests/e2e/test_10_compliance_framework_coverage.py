"""Live HTTP regression for compliance coverage by STRIDE category."""

from __future__ import annotations

import httpx


EXPECTED_FRAMEWORKS = {
    "NIST 800-53",
    "OSFI B-13",
    "PCI DSS 4.0",
    "ISO 27001",
}

STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]


def test_compliance_mappings_cover_each_stride_category(client: httpx.Client):
    for category in STRIDE_CATEGORIES:
        response = client.get(f"/api/compliance-mappings/by-stride/{category}")

        assert response.status_code == 200, response.text
        mappings = response.json()
        assert mappings, f"{category} should have seeded compliance mappings"
        assert {item["framework"] for item in mappings} >= EXPECTED_FRAMEWORKS
        assert all(item["control_id"] for item in mappings)
        assert all(item["control_name"] for item in mappings)
