"""Canonical intake questions and validators for invoke-anywhere reviews."""

from __future__ import annotations

from app.schemas.review_intake import (
    IntakeQuestion,
    IntakeQuestionBankResponse,
    IntakeQuestionOption,
    IntakeValidationRequest,
    IntakeValidationResponse,
    ReviewInputKind,
)

INTAKE_VERSION = "threatgenix_appsec_v1"
def _option(value: str, label: str) -> IntakeQuestionOption:
    return IntakeQuestionOption(value=value, label=label)


QUESTION_BANK: tuple[IntakeQuestion, ...] = (
    IntakeQuestion(
        id="workspace",
        label="Which workspace or tenant owns this application?",
        description="Use the workspace name the authenticated tenant expects.",
        answer_type="text",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
        max_length=160,
    ),
    IntakeQuestion(
        id="app_name",
        label="What is the application or system name?",
        answer_type="text",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
        max_length=255,
    ),
    IntakeQuestion(
        id="app_description",
        label="Describe the application architecture in one paragraph.",
        answer_type="textarea",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
        max_length=1600,
    ),
    IntakeQuestion(
        id="business_purpose",
        label="What does this application do for the business?",
        description="Short business and user outcome. Avoid secrets or customer records.",
        answer_type="textarea",
        required_for=["diff", "snapshot", "metadata"],
        max_length=1200,
    ),
    IntakeQuestion(
        id="data_classification",
        label="What is the highest data classification in scope?",
        answer_type="single_select",
        required_for=["diff", "snapshot", "metadata"],
        options=[
            _option("public", "Public"),
            _option("internal", "Internal"),
            _option("confidential", "Confidential"),
            _option("restricted", "Restricted"),
        ],
    ),
    IntakeQuestion(
        id="sensitive_data_types",
        label="Which sensitive data types are in scope?",
        answer_type="multi_select",
        required_for=["diff", "snapshot", "metadata"],
        options=[
            _option("pii", "PII"),
            _option("payment", "Payment data"),
            _option("health", "Health data"),
            _option("credentials", "Credentials/secrets"),
            _option("financial", "Financial records"),
            _option("none", "None"),
        ],
    ),
    IntakeQuestion(
        id="regulatory_scope",
        label="Which regulatory or customer security obligations apply?",
        answer_type="multi_select",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
        options=[
            _option("osfi_b13", "OSFI B-13"),
            _option("pci_dss", "PCI DSS"),
            _option("pipeda", "PIPEDA"),
            _option("soc2", "SOC 2"),
            _option("hipaa", "HIPAA"),
            _option("none", "None"),
            _option("unknown", "Unknown"),
        ],
    ),
    IntakeQuestion(
        id="deployment_model",
        label="Where does this application run?",
        answer_type="single_select",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
        options=[
            _option("aws", "AWS"),
            _option("azure", "Azure"),
            _option("gcp", "GCP"),
            _option("vercel", "Vercel"),
            _option("on_prem", "On-prem"),
            _option("hybrid", "Hybrid"),
            _option("unknown", "Unknown"),
        ],
    ),
    IntakeQuestion(
        id="internet_facing",
        label="Is any part of this application reachable from the internet?",
        answer_type="boolean",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
    ),
    IntakeQuestion(
        id="entry_points",
        label="What are the externally reachable entry points?",
        answer_type="string_list",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
        max_length=500,
    ),
    IntakeQuestion(
        id="authn_authz_model",
        label="How does authentication and authorization work?",
        answer_type="textarea",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
        max_length=1600,
    ),
    IntakeQuestion(
        id="multi_tenant",
        label="Does the application separate multiple customers, teams, or tenants?",
        answer_type="single_select",
        required_for=["snapshot", "metadata"],
        optional_for=["diff"],
        options=[
            _option("yes", "Yes"),
            _option("no", "No"),
            _option("unknown", "Unknown"),
        ],
    ),
    IntakeQuestion(
        id="changed_security_surface",
        label="What security-sensitive surface changed?",
        answer_type="multi_select",
        required_for=["diff"],
        options=[
            _option("authn", "Authentication"),
            _option("authz", "Authorization"),
            _option("sensitive_data", "Sensitive data access"),
            _option("public_api", "Public API"),
            _option("dependency", "Dependency"),
            _option("iac", "IaC/cloud config"),
            _option("unknown", "Unknown"),
        ],
    ),
    IntakeQuestion(
        id="scanner_permissions",
        label="Which managed scanner permissions are approved?",
        description="External active scanning must be explicitly approved.",
        answer_type="multi_select",
        required_for=["diff", "snapshot", "metadata"],
        options=[
            _option("static_code", "Static code scanning"),
            _option("dependencies", "Dependency scanning"),
            _option("secrets", "Secret scanning"),
            _option("iac", "IaC/cloud config scanning"),
            _option("external_passive", "Passive external checks"),
            _option("external_active", "Active external scanning"),
        ],
    ),
    IntakeQuestion(
        id="upload_permission",
        label="May ThreatGenix receive the allowed diff or manifest snapshot for this review?",
        answer_type="boolean",
        required_for=["diff", "snapshot", "metadata"],
    ),
    IntakeQuestion(
        id="github_permission",
        label="May ThreatGenix connect to GitHub for this application?",
        answer_type="boolean",
        optional_for=["diff", "snapshot", "metadata"],
    ),
    IntakeQuestion(
        id="out_of_scope",
        label="What is explicitly out of scope?",
        answer_type="string_list",
        required_for=["diff", "snapshot", "metadata"],
        max_length=500,
    ),
)


def get_intake_questions(review_type: ReviewInputKind) -> IntakeQuestionBankResponse:
    questions = [
        question
        for question in QUESTION_BANK
        if review_type in question.required_for or review_type in question.optional_for
    ]
    return IntakeQuestionBankResponse(
        version=INTAKE_VERSION,
        review_type=review_type,
        questions=questions,
    )


def validate_intake_answers(request: IntakeValidationRequest) -> IntakeValidationResponse:
    if request.version != INTAKE_VERSION:
        return IntakeValidationResponse(
            version=INTAKE_VERSION,
            review_type=request.review_type,
            valid=False,
            evidence_gaps=["missing_intake:version"],
            errors=[f"Unsupported intake version: {request.version}"],
        )

    question_bank = get_intake_questions(request.review_type)
    questions_by_id = {question.id: question for question in question_bank.questions}
    normalized: dict[str, object] = {}
    errors: list[str] = []
    missing: list[str] = []

    for answer_id in request.answers:
        if answer_id not in questions_by_id:
            errors.append(f"Unknown intake answer: {answer_id}")

    for question in question_bank.questions:
        raw_value = request.answers.get(question.id)
        is_required = request.review_type in question.required_for
        if _is_blank(raw_value):
            if is_required:
                missing.append(question.id)
            continue
        normalized_value, question_errors = _normalize_answer(question, raw_value)
        if question_errors:
            errors.extend(question_errors)
            continue
        normalized[question.id] = normalized_value

    adaptive_followups = _adaptive_followups(question_bank.questions, normalized, request.answers)
    adaptive_gap_ids = [
        question.id for question in adaptive_followups if question.id not in normalized
    ]
    evidence_gaps = [f"missing_intake:{question_id}" for question_id in [*missing, *adaptive_gap_ids]]

    return IntakeValidationResponse(
        version=INTAKE_VERSION,
        review_type=request.review_type,
        valid=not errors and not missing,
        normalized_answers=normalized,
        missing_required=missing,
        evidence_gaps=evidence_gaps,
        adaptive_followups=adaptive_followups,
        errors=errors,
    )


def _is_blank(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, list):
        return len(value) == 0
    return False


def _normalize_answer(question: IntakeQuestion, value: object) -> tuple[object | None, list[str]]:
    if question.answer_type in {"text", "textarea"}:
        if not isinstance(value, str):
            return None, [f"{question.id} must be a string"]
        normalized = value.strip()
        if question.max_length is not None and len(normalized) > question.max_length:
            return None, [f"{question.id} exceeds maximum length"]
        return normalized, []

    if question.answer_type == "boolean":
        if not isinstance(value, bool):
            return None, [f"{question.id} must be a boolean"]
        return value, []

    if question.answer_type == "string_list":
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            return None, [f"{question.id} must be a list of strings"]
        normalized_items = [item.strip() for item in value if item.strip()]
        if not normalized_items:
            return None, [f"{question.id} must include at least one value"]
        if question.max_length is not None:
            too_long = [item for item in normalized_items if len(item) > question.max_length]
            if too_long:
                return None, [f"{question.id} contains an item that exceeds maximum length"]
        return list(dict.fromkeys(normalized_items)), []

    allowed_values = {option.value for option in question.options}
    if question.answer_type == "single_select":
        if not isinstance(value, str):
            return None, [f"{question.id} must be a string option"]
        normalized = value.strip()
        if normalized not in allowed_values:
            return None, [f"{question.id} has unsupported option: {normalized}"]
        return normalized, []

    if question.answer_type == "multi_select":
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            return None, [f"{question.id} must be a list of options"]
        normalized_values = list(dict.fromkeys(item.strip() for item in value if item.strip()))
        unsupported = [item for item in normalized_values if item not in allowed_values]
        if unsupported:
            return None, [f"{question.id} has unsupported option: {unsupported[0]}"]
        if "none" in normalized_values and len(normalized_values) > 1:
            return None, [f"{question.id} cannot combine none with other options"]
        return normalized_values, []

    return None, [f"{question.id} uses unsupported question type"]


def _adaptive_followups(
    questions: list[IntakeQuestion],
    normalized: dict[str, object],
    raw_answers: dict[str, object],
) -> list[IntakeQuestion]:
    questions_by_id = {question.id: question for question in questions}
    followups: list[IntakeQuestion] = []

    def add(question_id: str) -> None:
        question = questions_by_id.get(question_id)
        if question is not None and question_id not in normalized:
            followups.append(question)

    sensitive_data = normalized.get("sensitive_data_types")
    if isinstance(sensitive_data, list) and "none" not in sensitive_data:
        add("authn_authz_model")

    changed_surface = normalized.get("changed_security_surface")
    if isinstance(changed_surface, list) and "public_api" in changed_surface:
        add("entry_points")

    if normalized.get("internet_facing") is True:
        add("entry_points")

    scanner_permissions = normalized.get("scanner_permissions")
    if isinstance(scanner_permissions, list) and "external_active" in scanner_permissions:
        add("internet_facing")

    del raw_answers
    return list({question.id: question for question in followups}.values())
