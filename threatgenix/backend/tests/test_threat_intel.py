"""Tests for the threat intelligence pipeline.

Covers: parsing, embedding text builders, CRI service, KEV service,
ThreatIntelContext, AI enhancement v2.0 citations, and seed data validation.

All tests are pure unit tests -- no network calls, no database, all mocked.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.threat_intel.ingest_attack import (
    _extract_tactic,
    _extract_technique_id,
    _extract_url,
)
from app.services.threat_intel.ingest_capec import _parse_capec_xml
from app.services.threat_intel.ingest_cccs import (
    ATTACK_PATTERN as CCCS_ATTACK_PATTERN,
    CVE_PATTERN as CCCS_CVE_PATTERN,
    _extract_advisory_id,
)
from app.services.threat_intel.ingest_cri import CRI_SEED_MAPPINGS
from app.services.threat_intel.ingest_cwe import (
    CWE_TOP_25_2025,
    FINANCIAL_RELEVANT_CWES,
    _parse_cwe_xml,
)
from app.services.threat_intel.ingest_kev import _parse_date
from app.services.threat_intel.embeddings import (
    build_embedding_text_advisory,
    build_embedding_text_attack,
    build_embedding_text_capec,
    build_embedding_text_cwe,
)
from app.services.threat_intel.retrieval import ThreatIntelContext, retrieve_threat_intel
from app.services.cri_service import extract_attack_ids_from_description
from app.services.kev_service import extract_cve_ids
from app.services.ai_enhancement import _parse_enhancement_response


# ===================================================================
# 1. XML/JSON Parsing Tests
# ===================================================================


class TestExtractTechniqueId:
    """Tests for _extract_technique_id from STIX external_references."""

    def test_extracts_technique_id_from_mitre_attack_source(self):
        refs = [{"source_name": "mitre-attack", "external_id": "T1078", "url": "https://example.com"}]
        assert _extract_technique_id(refs) == "T1078"

    def test_returns_none_when_no_mitre_attack_source(self):
        refs = [{"source_name": "capec", "external_id": "CAPEC-100"}]
        assert _extract_technique_id(refs) is None

    def test_returns_none_for_empty_references(self):
        assert _extract_technique_id([]) is None

    def test_extracts_subtechnique_id(self):
        refs = [{"source_name": "mitre-attack", "external_id": "T1078.001"}]
        assert _extract_technique_id(refs) == "T1078.001"

    def test_picks_first_mitre_attack_entry(self):
        refs = [
            {"source_name": "other", "external_id": "X123"},
            {"source_name": "mitre-attack", "external_id": "T1566"},
        ]
        assert _extract_technique_id(refs) == "T1566"


class TestExtractTactic:
    """Tests for _extract_tactic from kill_chain_phases."""

    def test_extracts_tactic_from_mitre_attack_kill_chain(self):
        phases = [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
        assert _extract_tactic(phases) == "initial-access"

    def test_returns_unknown_for_empty_phases(self):
        assert _extract_tactic([]) == "unknown"

    def test_returns_unknown_when_no_mitre_attack_chain(self):
        phases = [{"kill_chain_name": "lockheed-martin", "phase_name": "delivery"}]
        assert _extract_tactic(phases) == "unknown"

    def test_returns_unknown_when_phase_name_missing(self):
        phases = [{"kill_chain_name": "mitre-attack"}]
        assert _extract_tactic(phases) == "unknown"


class TestExtractUrl:
    """Tests for _extract_url from STIX external_references."""

    def test_extracts_url_from_mitre_attack_source(self):
        refs = [
            {"source_name": "mitre-attack", "external_id": "T1078", "url": "https://attack.mitre.org/techniques/T1078"}
        ]
        assert _extract_url(refs) == "https://attack.mitre.org/techniques/T1078"

    def test_returns_none_when_no_mitre_attack_source(self):
        refs = [{"source_name": "capec", "url": "https://capec.mitre.org"}]
        assert _extract_url(refs) is None


class TestParseCapecXml:
    """Tests for _parse_capec_xml with sample XML bytes."""

    SAMPLE_CAPEC_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3"
                        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Attack_Patterns>
    <Attack_Pattern ID="151" Name="Identity Spoofing" Status="Draft">
      <Description>An adversary crafts messages exploiting lack of authentication.</Description>
      <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
      <Typical_Severity>Medium</Typical_Severity>
      <Prerequisites>
        <Prerequisite>The target accepts unauthenticated requests.</Prerequisite>
      </Prerequisites>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="287"/>
        <Related_Weakness CWE_ID="290"/>
      </Related_Weaknesses>
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="ATTACK - ATT&amp;CK">
          <Entry_ID>T1078</Entry_ID>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
    </Attack_Pattern>
    <Attack_Pattern ID="999" Name="Deprecated Pattern" Status="Deprecated">
      <Description>This should be skipped.</Description>
    </Attack_Pattern>
    <Attack_Pattern ID="200" Name="No Extras" Status="Stable">
      <Description>A minimal pattern with no related items.</Description>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>"""

    def test_parses_capec_id(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        assert result[0]["capec_id"] == "CAPEC-151"

    def test_parses_name(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        assert result[0]["name"] == "Identity Spoofing"

    def test_parses_description(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        assert "lack of authentication" in result[0]["description"]

    def test_parses_likelihood(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        assert result[0]["likelihood"] == "High"

    def test_parses_severity(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        assert result[0]["severity"] == "Medium"

    def test_parses_related_cwe_ids(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        assert result[0]["related_cwe_ids"] == ["CWE-287", "CWE-290"]

    def test_parses_related_attack_ids(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        assert result[0]["related_attack_ids"] == ["T1078"]

    def test_skips_deprecated_patterns(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        ids = [p["capec_id"] for p in result]
        assert "CAPEC-999" not in ids

    def test_returns_correct_count_excluding_deprecated(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        assert len(result) == 2

    def test_handles_pattern_with_no_related_items(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        minimal = [p for p in result if p["capec_id"] == "CAPEC-200"][0]
        assert minimal["related_cwe_ids"] == []

    def test_handles_pattern_with_no_related_attacks(self):
        result = _parse_capec_xml(self.SAMPLE_CAPEC_XML)
        minimal = [p for p in result if p["capec_id"] == "CAPEC-200"][0]
        assert minimal["related_attack_ids"] == []


class TestParseCweXml:
    """Tests for _parse_cwe_xml with sample XML bytes."""

    SAMPLE_CWE_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Weaknesses>
    <Weakness ID="287" Name="Improper Authentication" Status="Draft">
      <Description>Missing or improper authentication.</Description>
      <Extended_Description>Extended info here.</Extended_Description>
      <Common_Consequences>
        <Consequence>
          <Scope>Access Control</Scope>
          <Impact>Bypass Protection Mechanism</Impact>
        </Consequence>
      </Common_Consequences>
      <Potential_Mitigations>
        <Potential_Mitigation>
          <Phase>Architecture and Design</Phase>
          <Description>Use strong authentication mechanisms.</Description>
        </Potential_Mitigation>
      </Potential_Mitigations>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern CAPEC_ID="151"/>
      </Related_Attack_Patterns>
    </Weakness>
    <Weakness ID="9999" Name="Not Priority" Status="Draft">
      <Description>Not in top 25 or financial list.</Description>
    </Weakness>
    <Weakness ID="79" Name="XSS" Status="Deprecated">
      <Description>This is deprecated and should be skipped.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>"""

    def test_parses_priority_cwe(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert len(result) == 1

    def test_parses_cwe_id(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert result[0]["cwe_id"] == "CWE-287"

    def test_parses_name(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert result[0]["name"] == "Improper Authentication"

    def test_parses_description(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert "improper authentication" in result[0]["description"].lower()

    def test_parses_extended_description(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert "Extended info" in result[0]["extended_description"]

    def test_parses_consequences(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert "Access Control: Bypass Protection Mechanism" in result[0]["consequences"]

    def test_parses_mitigations(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert "Architecture and Design" in result[0]["mitigations"]

    def test_parses_related_capec_ids(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert result[0]["related_capec_ids"] == ["CAPEC-151"]

    def test_marks_top_25_correctly(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        assert result[0]["is_top_25"] is True

    def test_skips_non_priority_cwe(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        ids = [w["cwe_id"] for w in result]
        assert "CWE-9999" not in ids

    def test_skips_deprecated_cwe(self):
        result = _parse_cwe_xml(self.SAMPLE_CWE_XML)
        ids = [w["cwe_id"] for w in result]
        assert "CWE-79" not in ids


class TestParseDateKev:
    """Tests for _parse_date from KEV date parsing."""

    def test_parses_valid_date(self):
        result = _parse_date("2024-06-15")
        assert result == datetime(2024, 6, 15, tzinfo=timezone.utc)

    def test_returns_none_for_none_input(self):
        assert _parse_date(None) is None

    def test_returns_none_for_empty_string(self):
        assert _parse_date("") is None

    def test_returns_none_for_invalid_format(self):
        assert _parse_date("15/06/2024") is None

    def test_returns_none_for_garbage_string(self):
        assert _parse_date("not-a-date") is None

    def test_parsed_date_has_utc_timezone(self):
        result = _parse_date("2025-01-01")
        assert result.tzinfo == timezone.utc


class TestExtractAdvisoryId:
    """Tests for _extract_advisory_id from CCCS URLs."""

    def test_extracts_av_advisory_id(self):
        url = "https://www.cyber.gc.ca/en/alerts-advisories/AV25-123"
        assert _extract_advisory_id(url, "Some title") == "AV25-123"

    def test_extracts_al_advisory_id(self):
        url = "https://www.cyber.gc.ca/en/alerts-advisories/AL24-456"
        assert _extract_advisory_id(url, "Some title") == "AL24-456"

    def test_falls_back_to_hash_for_unknown_url_format(self):
        url = "https://www.cyber.gc.ca/en/some-other-page"
        result = _extract_advisory_id(url, "Test Title")
        assert result.startswith("CCCS-")

    def test_fallback_id_has_12_char_hex_suffix(self):
        url = "https://example.com/no-advisory-id"
        result = _extract_advisory_id(url, "Test")
        suffix = result.replace("CCCS-", "")
        assert len(suffix) == 12


class TestCccsPatterns:
    """Tests for CVE and ATT&CK pattern extraction from CCCS advisory text."""

    def test_cve_pattern_matches_standard_cve(self):
        matches = CCCS_CVE_PATTERN.findall("Affected by CVE-2024-12345 and CVE-2023-9876")
        assert "CVE-2024-12345" in matches

    def test_cve_pattern_matches_multiple_cves(self):
        matches = CCCS_CVE_PATTERN.findall("CVE-2024-12345 CVE-2023-9876")
        assert len(matches) == 2

    def test_cve_pattern_no_match_on_partial(self):
        matches = CCCS_CVE_PATTERN.findall("CVE-123-45")
        assert len(matches) == 0

    def test_attack_pattern_matches_technique_id(self):
        matches = CCCS_ATTACK_PATTERN.findall("Uses technique T1078 for access")
        assert "T1078" in matches

    def test_attack_pattern_matches_subtechnique(self):
        matches = CCCS_ATTACK_PATTERN.findall("T1078.001 is used")
        assert "T1078.001" in matches

    def test_attack_pattern_no_match_on_short_id(self):
        matches = CCCS_ATTACK_PATTERN.findall("T12 is not valid")
        assert len(matches) == 0


# ===================================================================
# 2. Embedding Text Builder Tests
# ===================================================================


class TestBuildEmbeddingTextAttack:
    """Tests for build_embedding_text_attack."""

    def test_format_contains_technique_id(self):
        result = build_embedding_text_attack("T1078", "Valid Accounts", "Desc here", "persistence")
        assert "T1078" in result

    def test_format_contains_tactic(self):
        result = build_embedding_text_attack("T1078", "Valid Accounts", "Desc here", "persistence")
        assert "persistence" in result

    def test_format_contains_name(self):
        result = build_embedding_text_attack("T1078", "Valid Accounts", "Desc here", "persistence")
        assert "Valid Accounts" in result

    def test_format_starts_with_attack_prefix(self):
        result = build_embedding_text_attack("T1078", "Valid Accounts", "Desc here", "persistence")
        assert result.startswith("ATT&CK")

    def test_truncates_description_at_2000(self):
        long_desc = "x" * 3000
        result = build_embedding_text_attack("T1078", "Name", long_desc, "tactic")
        assert len(result) < 2100


class TestBuildEmbeddingTextCapec:
    """Tests for build_embedding_text_capec."""

    def test_format_contains_capec_id(self):
        result = build_embedding_text_capec("CAPEC-151", "Identity Spoofing", "Desc")
        assert "CAPEC-151" in result

    def test_format_starts_with_attack_pattern_prefix(self):
        result = build_embedding_text_capec("CAPEC-151", "Identity Spoofing", "Desc")
        assert result.startswith("Attack Pattern")

    def test_format_contains_name(self):
        result = build_embedding_text_capec("CAPEC-151", "Identity Spoofing", "Desc")
        assert "Identity Spoofing" in result


class TestBuildEmbeddingTextCwe:
    """Tests for build_embedding_text_cwe."""

    def test_format_contains_cwe_id(self):
        result = build_embedding_text_cwe("CWE-287", "Improper Authentication", "Desc")
        assert "CWE-287" in result

    def test_format_starts_with_weakness_prefix(self):
        result = build_embedding_text_cwe("CWE-287", "Improper Authentication", "Desc")
        assert result.startswith("Weakness")

    def test_format_contains_name(self):
        result = build_embedding_text_cwe("CWE-287", "Improper Authentication", "Desc")
        assert "Improper Authentication" in result


class TestBuildEmbeddingTextAdvisory:
    """Tests for build_embedding_text_advisory."""

    def test_format_contains_advisory_id(self):
        result = build_embedding_text_advisory("AV25-100", "Critical Vuln", "Summary text")
        assert "AV25-100" in result

    def test_format_starts_with_advisory_prefix(self):
        result = build_embedding_text_advisory("AV25-100", "Critical Vuln", "Summary text")
        assert result.startswith("Advisory")

    def test_format_contains_title(self):
        result = build_embedding_text_advisory("AV25-100", "Critical Vuln", "Summary text")
        assert "Critical Vuln" in result

    def test_truncates_summary_at_2000(self):
        long_summary = "y" * 3000
        result = build_embedding_text_advisory("AV25-100", "Title", long_summary)
        assert len(result) < 2100


# ===================================================================
# 3. CRI Service Tests
# ===================================================================


class TestExtractAttackIdsFromDescription:
    """Tests for extract_attack_ids_from_description."""

    def test_extracts_single_technique_id(self):
        result = extract_attack_ids_from_description("Threat uses T1078 for access")
        assert "T1078" in result

    def test_extracts_subtechnique_id(self):
        result = extract_attack_ids_from_description("Uses T1078.001 and T1078.002")
        assert "T1078.001" in result

    def test_extracts_multiple_technique_ids(self):
        result = extract_attack_ids_from_description("T1566 phishing leads to T1059 execution")
        assert len(result) == 2

    def test_returns_empty_for_no_attack_ids(self):
        result = extract_attack_ids_from_description("No ATT&CK references here")
        assert result == []

    def test_deduplicates_repeated_ids(self):
        result = extract_attack_ids_from_description("T1078 is repeated T1078 twice")
        assert result.count("T1078") == 1

    def test_handles_empty_string(self):
        result = extract_attack_ids_from_description("")
        assert result == []

    def test_extracts_from_citation_reference_format(self):
        result = extract_attack_ids_from_description("[References: T1657, CAPEC-151, CWE-287]")
        assert "T1657" in result


# ===================================================================
# 4. KEV Service Tests
# ===================================================================


class TestExtractCveIds:
    """Tests for extract_cve_ids."""

    def test_extracts_single_cve(self):
        result = extract_cve_ids("Vulnerability CVE-2024-12345 is critical")
        assert "CVE-2024-12345" in result

    def test_extracts_multiple_cves(self):
        result = extract_cve_ids("CVE-2024-1234 and CVE-2023-56789 are affected")
        assert len(result) == 2

    def test_returns_empty_for_no_cves(self):
        result = extract_cve_ids("No vulnerabilities mentioned here")
        assert result == []

    def test_deduplicates_cve_ids(self):
        result = extract_cve_ids("CVE-2024-1234 is the same as CVE-2024-1234")
        assert result.count("CVE-2024-1234") == 1

    def test_handles_empty_string(self):
        result = extract_cve_ids("")
        assert result == []

    def test_extracts_cve_with_long_number(self):
        result = extract_cve_ids("CVE-2024-123456 has 6 digits")
        assert "CVE-2024-123456" in result

    def test_does_not_match_short_cve_number(self):
        result = extract_cve_ids("CVE-2024-123 has only 3 digits")
        assert len(result) == 0


# ===================================================================
# 5. ThreatIntelContext.to_prompt_context Tests
# ===================================================================


class TestThreatIntelContextToPromptContext:
    """Tests for ThreatIntelContext.to_prompt_context."""

    def test_returns_empty_string_when_no_data(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[], weaknesses=[],
            advisories=[], kev_matches=[], cri_controls=[],
        )
        assert ctx.to_prompt_context() == ""

    def test_formats_attack_techniques_section(self):
        ctx = ThreatIntelContext(
            attack_techniques=[{
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials.",
                "tactic": "persistence",
                "url": "https://attack.mitre.org/techniques/T1078",
                "distance": 0.15,
            }],
            attack_patterns=[], weaknesses=[],
            advisories=[], kev_matches=[], cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "T1078" in result

    def test_formats_attack_patterns_section(self):
        ctx = ThreatIntelContext(
            attack_techniques=[],
            attack_patterns=[{
                "capec_id": "CAPEC-151",
                "name": "Identity Spoofing",
                "description": "Crafting messages",
                "severity": "Medium",
                "related_cwe_ids": ["CWE-287"],
                "distance": 0.2,
            }],
            weaknesses=[], advisories=[], kev_matches=[], cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "CAPEC-151" in result

    def test_formats_weaknesses_section(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[],
            weaknesses=[{
                "cwe_id": "CWE-287",
                "name": "Improper Authentication",
                "description": "Missing authentication",
                "is_top_25": True,
                "consequences": "Access Control: Bypass",
                "distance": 0.1,
            }],
            advisories=[], kev_matches=[], cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "CWE-287" in result

    def test_top_25_tag_appears_in_weakness_output(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[],
            weaknesses=[{
                "cwe_id": "CWE-287",
                "name": "Improper Authentication",
                "description": "Missing authentication",
                "is_top_25": True,
                "consequences": None,
                "distance": 0.1,
            }],
            advisories=[], kev_matches=[], cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "[TOP 25]" in result

    def test_no_top_25_tag_when_not_top_25(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[],
            weaknesses=[{
                "cwe_id": "CWE-311",
                "name": "Missing Encryption",
                "description": "Data not encrypted",
                "is_top_25": False,
                "consequences": None,
                "distance": 0.2,
            }],
            advisories=[], kev_matches=[], cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "[TOP 25]" not in result

    def test_formats_advisories_section(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[], weaknesses=[],
            advisories=[{
                "advisory_id": "AV25-100",
                "title": "Critical Advisory",
                "summary": "Important security update",
                "referenced_cves": ["CVE-2025-1234"],
                "distance": 0.3,
            }],
            kev_matches=[], cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "AV25-100" in result

    def test_formats_kev_section(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[], weaknesses=[], advisories=[],
            kev_matches=[{
                "cve_id": "CVE-2024-55555",
                "vulnerability_name": "Remote Code Execution",
                "vendor_project": "Apache",
                "product": "Tomcat",
                "known_ransomware_use": "Known",
            }],
            cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "CVE-2024-55555" in result

    def test_ransomware_tag_appears_for_known_ransomware(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[], weaknesses=[], advisories=[],
            kev_matches=[{
                "cve_id": "CVE-2024-55555",
                "vulnerability_name": "RCE",
                "vendor_project": "Vendor",
                "product": "Product",
                "known_ransomware_use": "Known",
            }],
            cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "[RANSOMWARE]" in result

    def test_no_ransomware_tag_for_unknown(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[], weaknesses=[], advisories=[],
            kev_matches=[{
                "cve_id": "CVE-2024-55555",
                "vulnerability_name": "RCE",
                "vendor_project": "Vendor",
                "product": "Product",
                "known_ransomware_use": "Unknown",
            }],
            cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "[RANSOMWARE]" not in result

    def test_formats_cri_controls_section(self):
        ctx = ThreatIntelContext(
            attack_techniques=[], attack_patterns=[], weaknesses=[], advisories=[],
            kev_matches=[],
            cri_controls=[{
                "cri_control_id": "PR.AA-01",
                "cri_control_name": "Identities and credentials are managed",
                "cri_function": "Protect",
                "attack_technique_id": "T1078",
                "mapping_type": "mitigates",
            }],
        )
        result = ctx.to_prompt_context()
        assert "PR.AA-01" in result

    def test_partial_data_only_includes_populated_sections(self):
        ctx = ThreatIntelContext(
            attack_techniques=[{
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "description": "Desc",
                "tactic": "persistence",
                "url": None,
                "distance": 0.1,
            }],
            attack_patterns=[], weaknesses=[],
            advisories=[], kev_matches=[], cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "CAPEC" not in result

    def test_all_sections_populated_produces_all_headers(self):
        ctx = ThreatIntelContext(
            attack_techniques=[{
                "technique_id": "T1078", "name": "N", "description": "D",
                "tactic": "t", "url": None, "distance": 0.1,
            }],
            attack_patterns=[{
                "capec_id": "CAPEC-151", "name": "N", "description": "D",
                "severity": "High", "related_cwe_ids": [], "distance": 0.2,
            }],
            weaknesses=[{
                "cwe_id": "CWE-287", "name": "N", "description": "D",
                "is_top_25": False, "consequences": None, "distance": 0.1,
            }],
            advisories=[{
                "advisory_id": "AV25-1", "title": "T", "summary": "S",
                "referenced_cves": [], "distance": 0.3,
            }],
            kev_matches=[{
                "cve_id": "CVE-2024-1", "vulnerability_name": "V",
                "vendor_project": "P", "product": "P",
                "known_ransomware_use": "Unknown",
            }],
            cri_controls=[{
                "cri_control_id": "PR.AA-01", "cri_control_name": "C",
                "cri_function": "Protect", "attack_technique_id": "T1078",
                "mapping_type": "mitigates",
            }],
        )
        result = ctx.to_prompt_context()
        assert "## Relevant MITRE ATT&CK Techniques" in result
        assert "## Relevant CAPEC Attack Patterns" in result
        assert "## Relevant CWE Weaknesses" in result
        assert "## Recent CCCS Advisories" in result
        assert "## Actively Exploited Vulnerabilities (CISA KEV)" in result
        assert "## CRI Profile Controls (Financial Sector)" in result

    def test_prompt_context_contains_instruction_header(self):
        ctx = ThreatIntelContext(
            attack_techniques=[{
                "technique_id": "T1078", "name": "N", "description": "D",
                "tactic": "t", "url": None, "distance": 0.1,
            }],
            attack_patterns=[], weaknesses=[],
            advisories=[], kev_matches=[], cri_controls=[],
        )
        result = ctx.to_prompt_context()
        assert "Threat Intelligence Context" in result


@pytest.mark.asyncio
async def test_retrieve_threat_intel_skips_when_pgvector_unavailable():
    """retrieve_threat_intel should degrade cleanly when pgvector is unavailable."""
    scalar_result = MagicMock()
    scalar_result.scalar.return_value = False

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=scalar_result)

    with patch(
        "app.services.threat_intel.retrieval.generate_embedding"
    ) as mock_generate_embedding:
        result = await retrieve_threat_intel(mock_db, "payments api")

    assert result.attack_techniques == []
    assert result.attack_patterns == []
    assert result.weaknesses == []
    assert result.advisories == []
    assert result.kev_matches == []
    assert result.cri_controls == []
    mock_generate_embedding.assert_not_called()


@pytest.mark.asyncio
async def test_retrieve_threat_intel_releases_probe_connection_before_embedding():
    """retrieve_threat_intel should not hold a DB connection during embedding calls."""
    mock_db = AsyncMock()

    with (
        patch(
            "app.services.threat_intel.retrieval._vector_search_available",
            new_callable=AsyncMock,
            return_value=(True, None),
        ),
        patch(
            "app.services.threat_intel.retrieval.generate_embedding",
            side_effect=RuntimeError("embedding provider unavailable"),
        ) as mock_generate_embedding,
    ):
        result = await retrieve_threat_intel(mock_db, "payments api")

    mock_db.commit.assert_awaited_once()
    mock_generate_embedding.assert_called_once()
    assert result.attack_techniques == []
    assert result.unavailable_reason == "embedding generation failed: RuntimeError"


@pytest.mark.asyncio
async def test_retrieve_threat_intel_runs_semantic_and_control_lookups_when_vector_ready():
    """retrieve_threat_intel should combine semantic RAG rows with deterministic CRI/KEV lookups."""
    mock_db = AsyncMock()

    with (
        patch("app.services.threat_intel.retrieval._vector_search_available", new_callable=AsyncMock, return_value=(True, None)),
        patch("app.services.threat_intel.retrieval.generate_embedding", return_value=[0.1] * 1024) as mock_generate_embedding,
        patch(
            "app.services.threat_intel.retrieval._search_attack",
            new_callable=AsyncMock,
            return_value=[
                {
                    "technique_id": "T1556",
                    "name": "Modify Authentication Process",
                    "description": "Adversaries may modify authentication mechanisms.",
                    "tactic": "credential-access",
                    "url": "https://attack.mitre.org/techniques/T1556/",
                    "distance": 0.11,
                }
            ],
        ),
        patch("app.services.threat_intel.retrieval._search_capec", new_callable=AsyncMock, return_value=[]),
        patch(
            "app.services.threat_intel.retrieval._search_cwe",
            new_callable=AsyncMock,
            return_value=[
                {
                    "cwe_id": "CWE-287",
                    "name": "Improper Authentication",
                    "description": "Authentication weakness.",
                    "is_top_25": False,
                    "consequences": "Bypass access control",
                    "distance": 0.09,
                }
            ],
        ),
        patch("app.services.threat_intel.retrieval._search_cccs", new_callable=AsyncMock, return_value=[]),
        patch(
            "app.services.threat_intel.retrieval._lookup_kev",
            new_callable=AsyncMock,
            return_value=[
                {
                    "cve_id": "CVE-2026-3020",
                    "vendor_project": "Vendor",
                    "product": "Diagnostics",
                    "vulnerability_name": "Auth bypass",
                }
            ],
        ),
        patch(
            "app.services.threat_intel.retrieval._lookup_cri",
            new_callable=AsyncMock,
            return_value=[
                {
                    "cri_control_id": "PR.AA-01",
                    "cri_control_name": "Identity management",
                    "cri_function": "Protect",
                    "attack_technique_id": "T1556",
                    "mapping_type": "mitigates",
                }
            ],
        ),
    ):
        result = await retrieve_threat_intel(
            mock_db,
            "Vendor diagnostics session route lacks authorization on an internet-facing API.",
            technology_keywords=["Diagnostics"],
        )

    mock_generate_embedding.assert_called_once()
    mock_db.commit.assert_awaited_once()
    assert result.unavailable_reason is None
    assert result.attack_techniques[0]["technique_id"] == "T1556"
    assert result.weaknesses[0]["cwe_id"] == "CWE-287"
    assert result.kev_matches[0]["cve_id"] == "CVE-2026-3020"
    assert result.cri_controls[0]["attack_technique_id"] == "T1556"


# ===================================================================
# 6. AI Enhancement v2.0 Citation Parsing Tests
# ===================================================================


class TestParseEnhancementResponseCitations:
    """Tests for citation handling in _parse_enhancement_response."""

    def test_appends_attack_technique_citations(self):
        tool_output = {
            "new_threats": [{
                "title": "Credential Abuse",
                "stride_category": "Spoofing",
                "severity": "High",
                "description": "Adversary uses stolen credentials",
                "affected_node_names": ["API"],
                "rationale": "reason",
                "relevance_rationale": "relevance",
                "attack_technique_ids": ["T1078"],
                "capec_ids": [],
                "cwe_ids": [],
            }],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert "[References: T1078]" in threats[0].description

    def test_appends_capec_citations(self):
        tool_output = {
            "new_threats": [{
                "title": "Spoofing Attack",
                "stride_category": "Spoofing",
                "severity": "High",
                "description": "Identity spoofing via crafted messages",
                "affected_node_names": ["Gateway"],
                "rationale": "reason",
                "relevance_rationale": "relevance",
                "attack_technique_ids": [],
                "capec_ids": ["CAPEC-151"],
                "cwe_ids": [],
            }],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert "CAPEC-151" in threats[0].description

    def test_appends_cwe_citations(self):
        tool_output = {
            "new_threats": [{
                "title": "Auth Bypass",
                "stride_category": "Spoofing",
                "severity": "Critical",
                "description": "Authentication bypass",
                "affected_node_names": ["Login"],
                "rationale": "reason",
                "relevance_rationale": "relevance",
                "attack_technique_ids": [],
                "capec_ids": [],
                "cwe_ids": ["CWE-287"],
            }],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert "CWE-287" in threats[0].description

    def test_appends_combined_citations(self):
        tool_output = {
            "new_threats": [{
                "title": "Combined Threat",
                "stride_category": "Tampering",
                "severity": "High",
                "description": "Complex attack scenario",
                "affected_node_names": ["DB"],
                "rationale": "reason",
                "relevance_rationale": "relevance",
                "attack_technique_ids": ["T1657"],
                "capec_ids": ["CAPEC-151"],
                "cwe_ids": ["CWE-287"],
            }],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert "[References: T1657, CAPEC-151, CWE-287]" in threats[0].description

    def test_no_references_tag_when_no_citations(self):
        tool_output = {
            "new_threats": [{
                "title": "No Citations",
                "stride_category": "Spoofing",
                "severity": "Low",
                "description": "Generic threat",
                "affected_node_names": ["X"],
                "rationale": "reason",
                "relevance_rationale": "relevance",
            }],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert "[References:" not in threats[0].description

    def test_missing_citation_fields_handled_gracefully(self):
        tool_output = {
            "new_threats": [{
                "title": "Minimal Threat",
                "stride_category": "Denial of Service",
                "severity": "Medium",
                "description": "DoS attack",
                "affected_node_names": ["Server"],
                "rationale": "reason",
                "relevance_rationale": "relevance",
                # Intentionally omitting attack_technique_ids, capec_ids, cwe_ids
            }],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert len(threats) == 1

    def test_description_includes_title_prefix(self):
        tool_output = {
            "new_threats": [{
                "title": "My Threat Title",
                "stride_category": "Tampering",
                "severity": "High",
                "description": "The detailed description",
                "affected_node_names": ["Node"],
                "rationale": "reason",
                "relevance_rationale": "relevance",
            }],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert threats[0].description.startswith("My Threat Title: The detailed description")


# ===================================================================
# 7. CRI Seed Data Validation Tests
# ===================================================================


class TestCriSeedDataValidation:
    """Validate the CRI_SEED_MAPPINGS constant has correct data."""

    def test_all_attack_technique_ids_have_valid_format(self):
        pattern = re.compile(r"^T\d{4}(?:\.\d{3})?$")
        for _, _, _, attack_id, _ in CRI_SEED_MAPPINGS:
            assert pattern.match(attack_id), f"Invalid ATT&CK ID format: {attack_id}"

    def test_all_cri_functions_are_valid(self):
        valid_functions = {"Govern", "Identify", "Protect", "Detect", "Respond", "Recover"}
        for _, _, cri_function, _, _ in CRI_SEED_MAPPINGS:
            assert cri_function in valid_functions, f"Invalid CRI function: {cri_function}"

    def test_no_duplicate_control_technique_pairs(self):
        pairs = set()
        for cri_id, _, _, attack_id, _ in CRI_SEED_MAPPINGS:
            pair = (cri_id, attack_id)
            assert pair not in pairs, f"Duplicate pair: {pair}"
            pairs.add(pair)

    def test_all_mapping_types_are_valid(self):
        valid_types = {"mitigates", "detects"}
        for _, _, _, _, mapping_type in CRI_SEED_MAPPINGS:
            assert mapping_type in valid_types, f"Invalid mapping type: {mapping_type}"

    def test_seed_data_is_not_empty(self):
        assert len(CRI_SEED_MAPPINGS) > 0

    def test_all_cri_control_ids_have_dot_notation(self):
        for cri_id, _, _, _, _ in CRI_SEED_MAPPINGS:
            assert "." in cri_id, f"CRI control ID missing dot notation: {cri_id}"

    def test_all_entries_are_5_tuples(self):
        for entry in CRI_SEED_MAPPINGS:
            assert len(entry) == 5


# ===================================================================
# 8. CWE Priority List Validation Tests
# ===================================================================


class TestCwePriorityListValidation:
    """Validate CWE priority lists."""

    def test_top_25_has_exactly_25_entries(self):
        assert len(CWE_TOP_25_2025) == 25

    def test_all_top_25_ids_follow_cwe_format(self):
        pattern = re.compile(r"^CWE-\d+$")
        for cwe_id in CWE_TOP_25_2025:
            assert pattern.match(cwe_id), f"Invalid CWE ID format: {cwe_id}"

    def test_financial_cwes_dont_overlap_with_top_25(self):
        overlap = CWE_TOP_25_2025 & FINANCIAL_RELEVANT_CWES
        assert len(overlap) == 0, f"Overlapping CWEs: {overlap}"

    def test_all_financial_ids_follow_cwe_format(self):
        pattern = re.compile(r"^CWE-\d+$")
        for cwe_id in FINANCIAL_RELEVANT_CWES:
            assert pattern.match(cwe_id), f"Invalid CWE ID format: {cwe_id}"

    def test_financial_list_is_not_empty(self):
        assert len(FINANCIAL_RELEVANT_CWES) > 0

    def test_top_25_contains_known_entries(self):
        assert "CWE-79" in CWE_TOP_25_2025

    def test_financial_contains_known_entries(self):
        assert "CWE-311" in FINANCIAL_RELEVANT_CWES
