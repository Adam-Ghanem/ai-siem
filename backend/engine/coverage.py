from __future__ import annotations

from collections import Counter

from .event_model import Alert
from .rules import RULES


def mitre_coverage(alerts: list[Alert]) -> dict:
    configured = [
        {
            'rule_id': rule['rule_id'],
            'rule_name': rule['name'],
            'tactic': rule['tactic'],
            'technique': rule['technique'],
            'severity': rule['severity'],
        }
        for rule in RULES
    ]
    fired = Counter((alert.tactic, alert.technique) for alert in alerts)
    return {
        'configured_rules': configured,
        'configured_rule_count': len(configured),
        'active_techniques': [
            {'tactic': tactic, 'technique': technique, 'alert_count': count}
            for (tactic, technique), count in fired.most_common()
        ],
        'active_technique_count': len(fired),
        'tactics_configured': sorted({rule['tactic'] for rule in RULES}),
        'techniques_configured': sorted({rule['technique'] for rule in RULES}),
    }
