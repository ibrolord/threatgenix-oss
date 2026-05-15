from app.services.residual_risk import (
    build_residual_risk_summary,
    derive_residual_risk_level,
    normalize_control_effectiveness,
    normalize_residual_risk_level,
)


def test_normalize_control_effectiveness_defaults_to_none():
    assert normalize_control_effectiveness(None) == "none"
    assert normalize_control_effectiveness("bogus") == "none"
    assert normalize_control_effectiveness("partial") == "partial"


def test_normalize_residual_risk_level_filters_invalid_values():
    assert normalize_residual_risk_level(None) is None
    assert normalize_residual_risk_level("Unknown") is None
    assert normalize_residual_risk_level("High") == "High"


def test_derive_residual_risk_level_uses_matrix():
    assert derive_residual_risk_level("Critical", "none") == "Critical"
    assert derive_residual_risk_level("Critical", "full") == "Low"
    assert derive_residual_risk_level("High", "partial") == "Medium"
    assert derive_residual_risk_level("Medium", "full") == "Negligible"
    assert derive_residual_risk_level("Low", "substantial") == "Negligible"


def test_derive_residual_risk_level_falls_back_for_unknown_severity():
    assert derive_residual_risk_level("Unknown", "none") == "Medium"


def test_build_residual_risk_summary_counts_only_valid_levels():
    assert build_residual_risk_summary(
        ["Critical", "High", None, "High", "Negligible", "Invalid"]
    ) == {
        "Critical": 1,
        "High": 2,
        "Medium": 0,
        "Low": 0,
        "Negligible": 1,
    }
