from __future__ import annotations

from app.intake_mapping import threat_model_fields_from_intake
from app.schemas.review_intake import IntakeValidationRequest
from app.services.review_intake import INTAKE_VERSION, get_intake_questions, validate_intake_answers


def _valid_diff_answers() -> dict[str, object]:
    return {
        "business_purpose": "Exports customer data for support operations.",
        "data_classification": "restricted",
        "sensitive_data_types": ["pii"],
        "changed_security_surface": ["sensitive_data", "authz"],
        "scanner_permissions": ["static_code", "dependencies", "secrets"],
        "upload_permission": True,
        "out_of_scope": ["production database contents"],
    }


def test_question_bank_has_stable_unique_ids_and_explicit_scanner_permissions():
    bank = get_intake_questions("diff")
    ids = [question.id for question in bank.questions]

    assert bank.version == INTAKE_VERSION
    assert len(ids) == len(set(ids))
    assert {"workspace", "app_name", "app_description", "scanner_permissions", "upload_permission"} <= set(ids)
    scanner_question = next(question for question in bank.questions if question.id == "scanner_permissions")
    scanner_options = {option.value for option in scanner_question.options}
    assert "external_active" in scanner_options


def test_diff_question_bank_has_fewer_required_questions_than_snapshot():
    diff_bank = get_intake_questions("diff")
    snapshot_bank = get_intake_questions("snapshot")
    diff_required = {
        question.id for question in diff_bank.questions if "diff" in question.required_for
    }
    snapshot_required = {
        question.id for question in snapshot_bank.questions if "snapshot" in question.required_for
    }

    assert len(diff_required) < len(snapshot_required)
    assert "changed_security_surface" in {question.id for question in diff_bank.questions}
    assert "entry_points" in {question.id for question in snapshot_bank.questions}


def test_validate_diff_answers_normalizes_and_passes():
    result = validate_intake_answers(
        IntakeValidationRequest(
            version=INTAKE_VERSION,
            review_type="diff",
            answers={**_valid_diff_answers(), "out_of_scope": [" production database contents "]},
        )
    )

    assert result.valid is True
    assert result.errors == []
    assert result.missing_required == []
    assert "missing_intake:authn_authz_model" in result.evidence_gaps
    assert [question.id for question in result.adaptive_followups] == ["authn_authz_model"]
    assert result.normalized_answers["out_of_scope"] == ["production database contents"]


def test_public_api_change_adaptively_requests_entry_points():
    result = validate_intake_answers(
        IntakeValidationRequest(
            version=INTAKE_VERSION,
            review_type="diff",
            answers={
                **_valid_diff_answers(),
                "changed_security_surface": ["public_api"],
                "sensitive_data_types": ["none"],
            },
        )
    )

    assert result.valid is True
    assert [question.id for question in result.adaptive_followups] == ["entry_points"]
    assert "missing_intake:entry_points" in result.evidence_gaps


def test_snapshot_missing_required_answers_become_evidence_gaps():
    result = validate_intake_answers(
        IntakeValidationRequest(
            version=INTAKE_VERSION,
            review_type="snapshot",
            answers={
                "business_purpose": "Customer portal.",
                "data_classification": "internal",
                "sensitive_data_types": ["none"],
                "scanner_permissions": ["static_code"],
                "upload_permission": True,
                "out_of_scope": ["production secrets"],
            },
        )
    )

    assert result.valid is False
    assert "workspace" in result.missing_required
    assert "app_name" in result.missing_required
    assert "missing_intake:workspace" in result.evidence_gaps
    assert "missing_intake:app_name" in result.evidence_gaps


def test_intake_answers_map_to_threat_model_fields():
    fields = threat_model_fields_from_intake(
        {
            **_valid_diff_answers(),
            "app_name": "ExampleApp",
            "app_description": "FastAPI export workflow.",
            "regulatory_scope": ["soc2"],
            "deployment_model": "aws",
        },
        fallback_app_name="Fallback",
    )

    assert fields == {
        "system_name": "ExampleApp",
        "description": "FastAPI export workflow.",
        "data_classification": "Restricted",
        "regulatory_scope": ["soc2"],
        "deployment_model": "cloud",
        "out_of_scope_statement": "production database contents",
    }


def test_validate_rejects_missing_required_out_of_scope():
    answers = _valid_diff_answers()
    answers.pop("out_of_scope")

    result = validate_intake_answers(
        IntakeValidationRequest(
            version=INTAKE_VERSION,
            review_type="diff",
            answers=answers,
        )
    )

    assert result.valid is False
    assert "out_of_scope" in result.missing_required


def test_validate_rejects_unknown_question_id():
    result = validate_intake_answers(
        IntakeValidationRequest(
            version=INTAKE_VERSION,
            review_type="diff",
            answers={**_valid_diff_answers(), "made_up": "nope"},
        )
    )

    assert result.valid is False
    assert "Unknown intake answer: made_up" in result.errors


def test_validate_rejects_unsupported_select_option():
    result = validate_intake_answers(
        IntakeValidationRequest(
            version=INTAKE_VERSION,
            review_type="diff",
            answers={**_valid_diff_answers(), "data_classification": "top_secret"},
        )
    )

    assert result.valid is False
    assert "data_classification has unsupported option: top_secret" in result.errors


def test_validate_rejects_combining_none_with_sensitive_data():
    result = validate_intake_answers(
        IntakeValidationRequest(
            version=INTAKE_VERSION,
            review_type="diff",
            answers={**_valid_diff_answers(), "sensitive_data_types": ["none", "pii"]},
        )
    )

    assert result.valid is False
    assert "sensitive_data_types cannot combine none with other options" in result.errors


def test_validate_rejects_unsupported_version():
    result = validate_intake_answers(
        IntakeValidationRequest(
            version="future",
            review_type="diff",
            answers=_valid_diff_answers(),
        )
    )

    assert result.valid is False
    assert result.version == INTAKE_VERSION
    assert result.errors == ["Unsupported intake version: future"]
