from __future__ import annotations

import pytest

from app.services.rules.loader import LoadedRule, load_rules

VALID_STRIDE_CATEGORIES = {
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}

VALID_CONDITION_TYPES = {"tuple", "standalone", "boundary"}


@pytest.fixture(scope="module")
def rules() -> list[LoadedRule]:
    return load_rules()


def test_all_rules_loaded(rules: list[LoadedRule]) -> None:
    assert len(rules) == 49  # 21 original + 20 property-dependent (F-07+) + 5 cloud (C-01→C-05) + 3 TLS (T-TLS-01, T-TLS-02, I-TLS-01)


def test_each_rule_has_callable_condition(rules: list[LoadedRule]) -> None:
    for rule in rules:
        assert callable(rule.condition_function), (
            f"{rule.rule_id} condition_function is not callable"
        )


def test_stride_categories_are_valid(rules: list[LoadedRule]) -> None:
    for rule in rules:
        assert rule.stride_category in VALID_STRIDE_CATEGORIES, (
            f"{rule.rule_id} has invalid STRIDE category: {rule.stride_category}"
        )


def test_severities_are_valid(rules: list[LoadedRule]) -> None:
    for rule in rules:
        assert rule.severity in VALID_SEVERITIES, (
            f"{rule.rule_id} has invalid severity: {rule.severity}"
        )


def test_condition_types_are_valid(rules: list[LoadedRule]) -> None:
    for rule in rules:
        assert rule.condition_type in VALID_CONDITION_TYPES, (
            f"{rule.rule_id} has invalid condition_type: {rule.condition_type}"
        )


def test_no_duplicate_rule_ids(rules: list[LoadedRule]) -> None:
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids)), f"Duplicate rule_ids found: {ids}"


def test_all_stride_categories_represented(rules: list[LoadedRule]) -> None:
    categories = {r.stride_category for r in rules}
    assert categories == VALID_STRIDE_CATEGORIES


def test_rule_ids_follow_naming_convention(rules: list[LoadedRule]) -> None:
    """Rule IDs should follow the pattern X-NN or X-XXX-NN where X is a STRIDE letter or C for cloud rules."""
    import re

    for rule in rules:
        assert re.match(r"^[STRIDEC]-(?:[A-Z]+-\d{2}|\d{2})$", rule.rule_id), (
            f"Rule ID {rule.rule_id} does not match expected pattern"
        )
