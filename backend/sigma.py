from __future__ import annotations

import hashlib
from typing import Any

import yaml

MAX_SIGMA_DOCUMENT_BYTES = 128 * 1024
MAX_SIGMA_RULES_PER_IMPORT = 50
ALLOWED_LEVELS = {'critical', 'high', 'medium', 'low', 'informational'}
FIELD_MAP = {
    'eventid': 'event_id',
    'event_id': 'event_id',
    'eventtype': 'event_type',
    'event_type': 'event_type',
    'image': 'process_name',
    'processname': 'process_name',
    'process_name': 'process_name',
    'commandline': 'command_line',
    'command_line': 'command_line',
    'scriptblocktext': 'command_line',
    'host': 'asset',
    'hostname': 'asset',
    'computer': 'asset',
    'user': 'user',
    'username': 'user',
    'sourceip': 'src_ip',
    'src_ip': 'src_ip',
    'destinationip': 'dst_ip',
    'dst_ip': 'dst_ip',
    'status': 'status',
    'source': 'source',
    'message': 'message',
}
INVERSE_FIELD_MAP = {value: key for key, value in FIELD_MAP.items()}


class SigmaRuleError(ValueError):
    pass


def _bounded_text(value: Any, field: str, limit: int = 1024) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SigmaRuleError(f'{field} must be a non-empty string')
    value = value.strip()
    if len(value) > limit:
        raise SigmaRuleError(f'{field} exceeds {limit} characters')
    return value


def _rule_id(sigma_id: str) -> str:
    return f"SIGMA-{hashlib.sha256(sigma_id.encode('utf-8')).hexdigest()[:12].upper()}"


def _level(value: Any) -> str:
    level = str(value or 'medium').strip().lower()
    if level not in ALLOWED_LEVELS:
        raise SigmaRuleError(f'unsupported Sigma level: {level}')
    return 'low' if level == 'informational' else level


def _field_name(value: Any) -> str:
    raw = str(value or '').strip().lower().replace('-', '_')
    if raw not in FIELD_MAP:
        raise SigmaRuleError(f'unsupported Sigma field: {value}')
    return FIELD_MAP[raw]


def _as_values(value: Any, field: str) -> list[str]:
    values = value if isinstance(value, list) else [value]
    if not values or len(values) > 50:
        raise SigmaRuleError(f'{field} must contain between 1 and 50 values')
    return [_bounded_text(str(item), field, 2048) for item in values]


def _tags(document: dict[str, Any]) -> tuple[str, str]:
    tactic = str(document.get('x_ai_siem_tactic') or '').strip()
    technique = str(document.get('x_ai_siem_technique') or '').strip()
    for tag in document.get('tags') or []:
        value = str(tag).strip()
        lowered = value.lower()
        if lowered.startswith('attack.t') and not technique:
            technique = value.split('.', 1)[1].upper()
        elif lowered.startswith('attack.') and not tactic:
            tactic = value.split('.', 1)[1].replace('_', ' ').title()
    return tactic or 'Unmapped', technique or 'Unmapped'


def _standard_detection(document: dict[str, Any]) -> dict[str, Any]:
    detection = document.get('detection')
    if not isinstance(detection, dict) or not detection:
        raise SigmaRuleError('detection must be a non-empty mapping')
    condition = str(detection.get('condition') or '').strip()
    selections = [key for key in detection if key != 'condition']
    if len(selections) != 1 or condition not in selections:
        raise SigmaRuleError('only one selection with an exact condition is supported')
    selection = detection[selections[0]]
    if not isinstance(selection, dict) or not selection:
        raise SigmaRuleError('the Sigma selection must be a non-empty mapping')
    field_equals: dict[str, str] = {}
    contains: dict[str, list[str]] = {}
    for key, value in selection.items():
        field = _field_name(key)
        values = _as_values(value, key)
        if len(values) == 1 and '*' not in values[0] and field in {
            'event_id', 'event_type', 'source', 'status', 'asset', 'user', 'src_ip', 'dst_ip'
        }:
            field_equals[field] = values[0]
        else:
            contains[field] = [item.strip('*') for item in values]
    return {'field_equals': field_equals, 'contains': contains}


def normalize_sigma_rule(document: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise SigmaRuleError('Sigma document must be a mapping')
    sigma_id = _bounded_text(document.get('id'), 'id', 128)
    title = _bounded_text(document.get('title'), 'title', 256)
    status = str(document.get('status') or 'stable').strip().lower()
    if status not in {'experimental', 'test', 'stable', 'deprecated'}:
        raise SigmaRuleError(f'unsupported Sigma status: {status}')
    standard = _standard_detection(document)
    extension = document.get('x_ai_siem') or {}
    if not isinstance(extension, dict):
        raise SigmaRuleError('x_ai_siem must be a mapping when present')
    rule = {
        'rule_id': _rule_id(sigma_id),
        'sigma_id': sigma_id,
        'name': title,
        'description': str(document.get('description') or '')[:2048],
        'status': status,
        'severity': _level(document.get('level')),
        'confidence': float(extension.get('confidence', 0.70)),
        'tactic': _tags(document)[0],
        'technique': _tags(document)[1],
        'field_equals': {**standard['field_equals'], **dict(extension.get('field_equals') or {})},
        'contains': {**standard['contains'], **dict(extension.get('contains') or {})},
        'regex': dict(extension.get('regex') or {}),
        'threshold': int(extension.get('threshold', 1)),
        'time_window_minutes': int(extension.get('time_window_minutes', 1)),
        'group_by': list(extension.get('group_by') or []),
    }
    distinct_field = extension.get('distinct_field')
    if distinct_field:
        rule['distinct_field'] = str(distinct_field)
    if not 0 <= rule['confidence'] <= 1:
        raise SigmaRuleError('x_ai_siem.confidence must be between 0 and 1')
    if not 1 <= rule['threshold'] <= 100000 or not 1 <= rule['time_window_minutes'] <= 1440:
        raise SigmaRuleError('threshold or time_window_minutes is outside the supported range')
    if len(rule['group_by']) > 10:
        raise SigmaRuleError('x_ai_siem.group_by has too many fields')
    return rule


def import_sigma(text: str | bytes) -> list[dict[str, Any]]:
    raw = text.decode('utf-8') if isinstance(text, bytes) else str(text)
    if len(raw.encode('utf-8')) > MAX_SIGMA_DOCUMENT_BYTES:
        raise SigmaRuleError(f'Sigma document exceeds {MAX_SIGMA_DOCUMENT_BYTES} bytes')
    documents: list[dict[str, Any]] = []
    try:
        for document in yaml.safe_load_all(raw):
            if isinstance(document, dict) and isinstance(document.get('rules'), list):
                documents.extend(document['rules'])
            elif document is not None:
                documents.append(document)
    except yaml.YAMLError as exc:
        raise SigmaRuleError(f'invalid Sigma YAML: {exc}') from exc
    if not documents or len(documents) > MAX_SIGMA_RULES_PER_IMPORT:
        raise SigmaRuleError(f'import must contain between 1 and {MAX_SIGMA_RULES_PER_IMPORT} rules')
    return [normalize_sigma_rule(document) for document in documents]


def _export_rule(rule: dict[str, Any]) -> dict[str, Any]:
    tags = []
    if rule.get('tactic') and rule['tactic'] != 'Unmapped':
        tags.append(f"attack.{str(rule['tactic']).lower().replace(' ', '_')}")
    if rule.get('technique') and rule['technique'] != 'Unmapped':
        tags.append(f"attack.{rule['technique'].lower()}")
    selection = {}
    for field, value in rule.get('field_equals', {}).items():
        selection[INVERSE_FIELD_MAP.get(field, field)] = value
    for field, values in rule.get('contains', {}).items():
        selection[INVERSE_FIELD_MAP.get(field, field)] = [f'*{item}*' for item in values]
    return {
        'title': rule.get('name', rule.get('rule_id', 'AI-SIEM Rule')),
        'id': rule.get('sigma_id') or rule.get('rule_id'),
        'status': rule.get('status', 'stable'),
        'description': rule.get('description', ''),
        'logsource': {'product': 'ai-siem'},
        'detection': {'selection': selection, 'condition': 'selection'},
        'level': rule.get('severity', 'medium'),
        'tags': tags,
        'x_ai_siem_tactic': rule.get('tactic', 'Unmapped'),
        'x_ai_siem_technique': rule.get('technique', 'Unmapped'),
        'x_ai_siem': {
            'confidence': rule.get('confidence', 0.70),
            'field_equals': rule.get('field_equals', {}),
            'contains': rule.get('contains', {}),
            'regex': rule.get('regex', {}),
            'threshold': rule.get('threshold', 1),
            'time_window_minutes': rule.get('time_window_minutes', 1),
            'group_by': rule.get('group_by', []),
            'distinct_field': rule.get('distinct_field'),
        },
    }


def export_sigma(rules: list[dict[str, Any]]) -> str:
    return yaml.safe_dump_all(
        [_export_rule(rule) for rule in rules],
        sort_keys=False,
        allow_unicode=True,
    )
