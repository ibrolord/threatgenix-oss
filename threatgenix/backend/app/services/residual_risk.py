from __future__ import annotations

from collections import Counter

CONTROL_EFFECTIVENESS_LEVELS = ("none", "partial", "substantial", "full")
RESIDUAL_RISK_LEVELS = ("Critical", "High", "Medium", "Low", "Negligible")

_RESIDUAL_RISK_MATRIX: dict[str, dict[str, str]] = {
    "Critical": {
        "none": "Critical",
        "partial": "High",
        "substantial": "Medium",
        "full": "Low",
    },
    "High": {
        "none": "High",
        "partial": "Medium",
        "substantial": "Low",
        "full": "Negligible",
    },
    "Medium": {
        "none": "Medium",
        "partial": "Low",
        "substantial": "Low",
        "full": "Negligible",
    },
    "Low": {
        "none": "Low",
        "partial": "Low",
        "substantial": "Negligible",
        "full": "Negligible",
    },
}


def normalize_control_effectiveness(value: str | None) -> str:
    if value in CONTROL_EFFECTIVENESS_LEVELS:
        return value
    return "none"


def normalize_residual_risk_level(value: str | None) -> str | None:
    if value in RESIDUAL_RISK_LEVELS:
        return value
    return None


def derive_residual_risk_level(
    severity: str,
    control_effectiveness: str | None = None,
) -> str:
    effective_control = normalize_control_effectiveness(control_effectiveness)
    severity_map = _RESIDUAL_RISK_MATRIX.get(severity)
    if severity_map is None:
        return "Medium"
    return severity_map[effective_control]


def build_residual_risk_summary(
    residual_levels: list[str | None],
) -> dict[str, int]:
    counts = Counter(
        level for level in residual_levels if normalize_residual_risk_level(level) is not None
    )
    return {level: counts.get(level, 0) for level in RESIDUAL_RISK_LEVELS}
