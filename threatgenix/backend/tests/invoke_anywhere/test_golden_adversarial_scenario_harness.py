from __future__ import annotations

from pathlib import Path

from app.services.application_review_scenario_harness import (
    load_decision_scenarios,
    run_decision_scenario_suite,
)


FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "golden_adversarial_review_scenarios.json"
)

REQUIRED_SCENARIO_IDS = {
    "clean_app_pass",
    "public_pii_export_missing_authz_blocks",
    "pii_export_after_authz_fix_passes",
    "scanner_only_false_positive_unreachable_verify",
    "sensitive_route_missing_cloud_exposure_verify",
    "metadata_only_gather_evidence",
    "webhook_missing_signature_fix",
    "iac_public_admin_blocks",
    "active_accepted_risk_monitored",
    "expired_accepted_risk_reopened",
    "conflicting_docs_code_verify",
    "unsupported_framework_gather",
    "prompt_injection_canary_ignored",
    "malicious_sarif_spoofing_downgraded",
    "oversized_malicious_bundle_rejected",
    "mid_scan_cancellation_no_corrupt_evidence",
}


def test_loads_required_golden_and_adversarial_scenarios():
    scenarios = load_decision_scenarios(FIXTURE_PATH)

    assert {scenario.id for scenario in scenarios} == REQUIRED_SCENARIO_IDS
    assert len(scenarios) == 16
    assert sum(1 for scenario in scenarios if scenario.kind == "adversarial") == 4
    assert any(scenario.safety_critical for scenario in scenarios)


def test_golden_and_adversarial_scenario_suite_passes_accuracy_gate():
    scenarios = load_decision_scenarios(FIXTURE_PATH)

    result = run_decision_scenario_suite(scenarios)

    assert result.passed is True, [
        (item.id, item.actual_decision, item.failures) for item in result.results if not item.passed
    ]
    assert result.scenario_count == 16
    assert result.safety_critical_failed_count == 0
    assert result.false_positive_count == 0
    assert result.false_negative_count == 0
    assert all(item.required_evidence_present for item in result.results)
    assert all(item.forbidden_output_absent for item in result.results)
    assert all(item.explanation_quality == "pass" for item in result.results)
    assert all(item.confidence in {"high", "medium", "low"} for item in result.results)
    assert all(item.fix_plan_usefulness != "fail" for item in result.results)
    assert all(
        item.confidence in {"high", "medium"}
        for item in result.results
        if item.safety_critical
    )


def test_harness_blocks_supported_pii_export_but_does_not_block_adversarial_canaries():
    scenarios = load_decision_scenarios(FIXTURE_PATH)
    result = run_decision_scenario_suite(scenarios)
    by_id = {item.id: item for item in result.results}

    assert by_id["public_pii_export_missing_authz_blocks"].actual_decision == "block"
    assert by_id["prompt_injection_canary_ignored"].actual_decision == "pass"
    assert by_id["malicious_sarif_spoofing_downgraded"].actual_decision == "verify"
    assert "SYSTEM_OVERRIDE_SHOULD_NOT_LEAK" not in by_id["prompt_injection_canary_ignored"].reason
