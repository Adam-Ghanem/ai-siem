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

    def _alert(self, alert_id, rule_id, confidence=0.8):
        return Alert(
            alert_id=alert_id,
            rule_id=rule_id,
            title='Signal',
            severity='medium',
            confidence=confidence,
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

    def test_repeated_noisy_rule_cannot_dominate_investigation_confidence(self):
        alerts = [
            *[
                self._alert(f'noisy-{index}', 'DET-NOISY', confidence=0.99)
                for index in range(20)
            ],
            self._alert('independent', 'DET-INDEPENDENT', confidence=0.41),
        ]
        result = build_investigation(
            self._incident([alert.alert_id for alert in alerts]),
            alerts,
            [],
            [],
        )

        self.assertEqual(result['confidence'], 0.7)

    def test_same_rule_uses_strongest_observation_for_confidence(self):
        alerts = [
            self._alert('a-low', 'DET-SAME', confidence=0.35),
            self._alert('a-high', 'DET-SAME', confidence=0.85),
        ]
        result = build_investigation(
            self._incident([alert.alert_id for alert in alerts]),
            alerts,
            [],
            [],
        )

        self.assertEqual(result['confidence'], 0.85)


if __name__ == '__main__':
    unittest.main()
