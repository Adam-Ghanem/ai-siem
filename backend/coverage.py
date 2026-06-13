from __future__ import annotations
from collections import Counter, defaultdict
from typing import Any


def _metadata(rule: dict[str, Any]) -> tuple[str, str, str]:
    rule_id = str(rule.get('rule_id') or rule.get('id') or 'UNKNOWN')
    tactic = str(rule.get('tactic') or rule.get('mitre_tactic') or 'Unknown')
    technique = str(rule.get('technique') or rule.get('mitre_technique') or 'Unknown')
    return rule_id, tactic, technique


def generate_attack_coverage(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize MITRE ATT&CK coverage from detection rule metadata.

    This is intentionally metadata-only. It reports what the project has
    implemented as detection rules; it does not claim real environment coverage.
    """
    tactic_counts: Counter[str] = Counter()
    technique_counts: Counter[tuple[str, str]] = Counter()
    technique_rules: dict[tuple[str, str], list[str]] = defaultdict(list)
    unmapped_rules: list[str] = []

    for rule in rules:
        rule_id, tactic, technique = _metadata(rule)
        tactic_counts[tactic] += 1
        technique_counts[(technique, tactic)] += 1
        technique_rules[(technique, tactic)].append(rule_id)
        if tactic == 'Unknown' or technique == 'Unknown':
            unmapped_rules.append(rule_id)

    tactics = [
        {'tactic': tactic, 'rule_count': count}
        for tactic, count in sorted(tactic_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    techniques = [
        {
            'technique': technique,
            'tactic': tactic,
            'rule_count': count,
            'rules': sorted(technique_rules[(technique, tactic)]),
        }
        for (technique, tactic), count in sorted(technique_counts.items(), key=lambda item: (-item[1], item[0][1], item[0][0]))
    ]

    return {
        'total_rules': len(rules),
        'tactics': tactics,
        'techniques': techniques,
        'unmapped_rules': sorted(unmapped_rules),
        'note': 'Coverage is based on implemented rule metadata, not guaranteed telemetry visibility.',
    }
