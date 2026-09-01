from __future__ import annotations

import re
from collections.abc import Iterable

from .models import Event

ALLOWED_SEVERITIES = {'low', 'medium', 'high', 'critical'}
ALLOWED_MATCH_OPERATORS = {'field_equals', 'contains', 'regex'}
EVENT_FIELDS = set(Event.__dataclass_fields__)
REQUIRED_FIELDS = {'rule_id', 'name', 'severity', 'confidence', 'tactic', 'technique'}


def _require_nonempty_string(rule: dict, field: str) -> None:
    value = rule.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"detection rule requires non-empty string field '{field}'")


def _validate_event_field(field: object, rule_id: str) -> str:
    if not isinstance(field, str) or field not in EVENT_FIELDS:
        raise ValueError(f"{rule_id}: unknown event field '{field}'")
    return field


def _validate_match_map(rule: dict, operator: str) -> None:
    rule_id = str(rule.get('rule_id') or '<unknown>')
    mapping = rule.get(operator)
    if mapping is None:
        return
    if not isinstance(mapping, dict):
        raise ValueError(f'{rule_id}: {operator} must be an object')

    for field, value in mapping.items():
        _validate_event_field(field, rule_id)
        if operator == 'field_equals':
            if isinstance(value, (dict, list, tuple, set)):
                raise ValueError(f'{rule_id}: field_equals values must be scalar')
            continue

        if not isinstance(value, list) or not value:
            raise ValueError(f'{rule_id}: {operator}.{field} must be a non-empty list')
        if not all(isinstance(item, str) and item for item in value):
            raise ValueError(f'{rule_id}: {operator}.{field} entries must be non-empty strings')
        if operator == 'regex':
            for pattern in value:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(f'{rule_id}: invalid regex for {field}: {exc}') from exc


def validate_rule(rule: dict) -> dict:
    if not isinstance(rule, dict):
        raise ValueError('detection rule must be an object')

    for field in REQUIRED_FIELDS:
        _require_nonempty_string(rule, field) if field != 'confidence' else None

    rule_id = rule['rule_id']
    if rule['severity'] not in ALLOWED_SEVERITIES:
        raise ValueError(f"{rule_id}: unsupported severity '{rule['severity']}'")

    confidence = rule.get('confidence')
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        raise ValueError(f'{rule_id}: confidence must be between 0 and 1')

    for operator in ALLOWED_MATCH_OPERATORS:
        _validate_match_map(rule, operator)

    threshold = rule.get('threshold', 1)
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError(f'{rule_id}: threshold must be a positive integer')

    window = rule.get('time_window_minutes', 1)
    if not isinstance(window, (int, float)) or isinstance(window, bool) or window <= 0:
        raise ValueError(f'{rule_id}: time_window_minutes must be positive')

    group_by = rule.get('group_by', [])
    if not isinstance(group_by, list):
        raise ValueError(f'{rule_id}: group_by must be a list')
    for field in group_by:
        _validate_event_field(field, rule_id)

    distinct_field = rule.get('distinct_field')
    if distinct_field is not None:
        _validate_event_field(distinct_field, rule_id)
        if distinct_field in group_by:
            raise ValueError(f'{rule_id}: distinct_field must not also appear in group_by')

    if not any(rule.get(operator) for operator in ALLOWED_MATCH_OPERATORS):
        raise ValueError(f'{rule_id}: rule must define at least one match condition')

    return rule


def validate_rules(rules: Iterable[dict]) -> list[dict]:
    validated: list[dict] = []
    seen_ids: set[str] = set()
    for rule in rules:
        validate_rule(rule)
        rule_id = rule['rule_id']
        if rule_id in seen_ids:
            raise ValueError(f"duplicate detection rule id '{rule_id}'")
        seen_ids.add(rule_id)
        validated.append(rule)
    if not validated:
        raise ValueError('at least one detection rule is required')
    return validated
