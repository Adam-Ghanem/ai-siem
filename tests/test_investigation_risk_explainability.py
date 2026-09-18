import unittest
from datetime import datetime, timezone

from backend.investigation import build_investigation
from backend.models import Alert, Incident


class InvestigationRiskExplainabilityTests(unittest.TestCase):
    def _incident(self, alert_ids):
        return Incident(
            incident_id='inc-risk',
            title='Risk test',
            priority='P3',
            status='open',
            owner='soc',
            related_alert_ids=alert_ids,
            related_assets=[],
            related_users=[],
            related_src_ips=[],
            evidence_summary='',
            timeline=[],
            recommended_actions=[],
        )

    def _alert(self, alert_id, rule_id):
        return Alert(
            alert_id=alert_id,
            rule_id=rule_id,
            title='Signal',
            severity='medium',
            confidence=0.8,
            tactic='Discovery',
            technique='T1046',
            timestamp=datetime.now(timezone.utc),
        )

    def test_repeated_alerts_from_one_rule_do_not_gain_correlation_bonus(self):
        alerts = [self._alert(f'a-{index}', 'DET-NOISY') for index in range(8)]
        result = build_investigation(
            self._incident([alert.alert_id for alert in alerts]),
            alerts,
            [],
            [],
        )

        self.assertEqual(result['risk_factors']['distinct_detection_rules'], 1)
        self.assertEqual(result['risk_factors']['correlation_bonus'], 0)
        self.assertEqual(result['risk_score'], 36)

    def test_distinct_detection_rules_add_bounded_corroboration_bonus(self):
        alerts = [self._alert(f'a-{index}', f'DET-{index}') for index in range(6)]
        result = build_investigation(
            self._incident([alert.alert_id for alert in alerts]),
            alerts,
            [],
            [],
        )

        factors = result['risk_factors']
        self.assertEqual(factors['distinct_detection_rules'], 6)
        self.assertEqual(factors['correlation_bonus'], 21)
        self.assertEqual(factors['priority_base'], 22)
        self.assertEqual(factors['severity_bonus'], 14)
        self.assertEqual(factors['anomaly_bonus'], 0)
        self.assertEqual(result['risk_score'], 57)


if __name__ == '__main__':
    unittest.main()
