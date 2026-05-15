from __future__ import annotations

import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from app.services.rules import conditions


@dataclass
class LoadedRule:
    rule_id: str
    stride_category: str
    threat_subtype: str
    description_template: str
    severity: str
    condition_function: Callable[..., bool]
    condition_type: str  # "tuple", "standalone", "boundary"
    requires_boundary_crossing: bool
    priority: int = 100


def load_rules() -> list[LoadedRule]:
    """Load rules from YAML and resolve condition functions.

    Raises ``AttributeError`` if a ``condition_function`` referenced in the
    YAML does not exist in the ``conditions`` module.
    """
    yaml_path = Path(__file__).parent / "rule_definitions.yaml"
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    loaded: list[LoadedRule] = []
    for rule in data["rules"]:
        func = getattr(conditions, rule["condition_function"])
        loaded.append(
            LoadedRule(
                rule_id=rule["rule_id"],
                stride_category=rule["stride_category"],
                threat_subtype=rule["threat_subtype"],
                description_template=rule["description_template"],
                severity=rule["severity"],
                condition_function=func,
                condition_type=rule["condition_type"],
                requires_boundary_crossing=rule["requires_boundary_crossing"],
                priority=int(rule.get("priority", 100)),
            )
        )
    return loaded
