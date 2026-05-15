"""Tests for the Nuclei scan worker output parser."""
from __future__ import annotations

import uuid


from app.services.scan_worker import _nuclei_available, _parse_nuclei_finding


def test_parse_valid_nuclei_finding():
    """Parse a realistic Nuclei v3 JSON output line."""
    data = {
        "template-id": "CVE-2021-44228-log4j-rce",
        "info": {
            "name": "Log4j RCE",
            "severity": "critical",
            "tags": ["cve", "rce", "log4j"],
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cvss-score": 10.0,
            },
        },
        "matched-at": "https://api.example.com/search",
        "extracted-results": ["jndi:ldap://attacker.com/"],
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.template_id == "CVE-2021-44228-log4j-rce"
    assert finding.severity == "critical"
    assert "CVE-2021-44228" in finding.cve_ids
    assert finding.cvss_score == 10.0
    assert "cve" in finding.tags
    assert finding.matched_at == "https://api.example.com/search"


def test_parse_finding_missing_template_id_returns_none():
    data = {"info": {"name": "something", "severity": "high"}, "matched-at": "http://x.com"}
    assert _parse_nuclei_finding(uuid.uuid4(), data) is None


def test_parse_finding_empty_template_id_returns_none():
    data = {
        "template-id": "",
        "info": {"name": "something", "severity": "high"},
        "matched-at": "http://x.com",
    }
    assert _parse_nuclei_finding(uuid.uuid4(), data) is None


def test_parse_finding_handles_string_cve_ids():
    """Some older templates return cve-id as a string, not list."""
    data = {
        "template-id": "heartbleed",
        "info": {
            "name": "Heartbleed",
            "severity": "high",
            "tags": ["cve", "ssl"],
            "classification": {"cve-id": "CVE-2014-0160"},
        },
        "matched-at": "https://host:443",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert "CVE-2014-0160" in finding.cve_ids


def test_parse_finding_handles_string_tags():
    """Tags may come as comma-separated string in some templates."""
    data = {
        "template-id": "xss-template",
        "info": {
            "name": "XSS",
            "severity": "medium",
            "tags": "xss,owasp,injection",
        },
        "matched-at": "https://app.example.com/search",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert "xss" in finding.tags
    assert "owasp" in finding.tags


def test_parse_finding_handles_missing_classification():
    data = {
        "template-id": "exposure-test",
        "info": {"name": "Exposure", "severity": "low", "tags": ["exposure"]},
        "matched-at": "https://api.example.com/.env",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.cve_ids == []
    assert finding.cvss_score is None


def test_nuclei_available_returns_bool():
    result = _nuclei_available()
    assert isinstance(result, bool)


def test_parse_finding_stores_raw_output():
    """raw_output should hold the full original dict."""
    data = {
        "template-id": "test-id",
        "info": {"name": "Test", "severity": "info"},
        "matched-at": "https://example.com",
        "extra-field": "should-be-preserved",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.raw_output == data


def test_parse_finding_severity_unknown_fallback():
    """Unrecognised severity values fall back to 'unknown'."""
    data = {
        "template-id": "test-id",
        "info": {"name": "Test", "severity": "extreme"},
        "matched-at": "https://example.com",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.severity == "unknown"


def test_parse_finding_severity_case_insensitive():
    """Severity string should be normalised regardless of case from Nuclei output."""
    data = {
        "template-id": "test-id",
        "info": {"name": "Test", "severity": "CRITICAL"},
        "matched-at": "https://example.com",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.severity == "critical"


def test_parse_finding_extracted_results_joined():
    """List of extracted-results is joined into a single string."""
    data = {
        "template-id": "test-id",
        "info": {"name": "Test", "severity": "high"},
        "matched-at": "https://example.com",
        "extracted-results": ["value1", "value2"],
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert "value1" in finding.extracted_results
    assert "value2" in finding.extracted_results


def test_parse_finding_no_extracted_results_is_none():
    data = {
        "template-id": "test-id",
        "info": {"name": "Test", "severity": "high"},
        "matched-at": "https://example.com",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.extracted_results is None


def test_parse_finding_template_name_falls_back_to_id():
    """When info.name is missing, template_name should default to template_id."""
    data = {
        "template-id": "my-template-id",
        "info": {"severity": "low"},
        "matched-at": "https://example.com",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.template_name == "my-template-id"


def test_parse_finding_scan_job_id_preserved():
    """The scan_job_id on the returned finding must match what was passed in."""
    job_id = uuid.uuid4()
    data = {
        "template-id": "test-id",
        "info": {"name": "Test", "severity": "info"},
        "matched-at": "https://example.com",
    }
    finding = _parse_nuclei_finding(job_id, data)
    assert finding is not None
    assert finding.scan_job_id == job_id


def test_parse_finding_host_fallback_for_matched_at():
    """When matched-at is absent, host field should be used as fallback."""
    data = {
        "template-id": "test-id",
        "info": {"name": "Test", "severity": "info"},
        "host": "https://fallback.example.com",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.matched_at == "https://fallback.example.com"


def test_parse_finding_none_classification_handled():
    """classification: null in JSON should not crash the parser."""
    data = {
        "template-id": "test-id",
        "info": {
            "name": "Test",
            "severity": "medium",
            "classification": None,
        },
        "matched-at": "https://example.com",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.cve_ids == []
    assert finding.cvss_score is None


def test_parse_finding_none_info_handled():
    """info: null should not crash the parser."""
    data = {
        "template-id": "test-id",
        "info": None,
        "matched-at": "https://example.com",
    }
    finding = _parse_nuclei_finding(uuid.uuid4(), data)
    assert finding is not None
    assert finding.severity == "unknown"
