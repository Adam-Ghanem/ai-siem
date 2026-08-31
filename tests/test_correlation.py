import unittest
from datetime import timedelta
from tests.helpers import alert, BASE
from backend.correlation import correlate


class CorrelationTests(unittest.TestCase):
    def test_related_alerts_become_one_incident(self):
        alerts = [alert(1, alert_id='AL-1', src_ip='10.0.0.9'), alert(2, alert_id='AL-2', user='adam', src_ip='10.0.0.9')]
        incidents = correlate(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertCountEqual(incidents[0].related_alert_ids, ['AL-1', 'AL-2'])

    def test_unrelated_alerts_become_separate_incidents(self):
        alerts = [
            alert(1, alert_id='AL-1', asset='host-a', user='adam', src_ip='10.0.0.1', tactic='Credential Access'),
            alert(90, alert_id='AL-2', asset='host-b', user='meryem', src_ip='10.0.0.2', tactic='Execution', timestamp=BASE + timedelta(minutes=90)),
        ]
        incidents = correlate(alerts)
        self.assertEqual(len(incidents), 2)

    def test_incident_contains_required_soc_fields(self):
        incident = correlate([alert(1, alert_id='AL-1'), alert(2, alert_id='AL-2')])[0]
        self.assertTrue(incident.related_alert_ids)
        self.assertTrue(incident.timeline)
        self.assertIsInstance(incident.evidence_summary, str)
        self.assertTrue(incident.recommended_actions)

    def test_same_tactic_alone_does_not_correlate_unrelated_entities(self):
        alerts = [
            alert(1, alert_id='AL-1', asset='host-a', user='alice', src_ip='10.0.0.1', tactic='Execution'),
            alert(2, alert_id='AL-2', asset='host-b', user='bob', src_ip='10.0.0.2', tactic='Execution'),
        ]
        self.assertEqual(len(correlate(alerts)), 2)

    def test_transitive_chain_cannot_bridge_outside_incident_window(self):
        alerts = [
            alert(1, alert_id='AL-1', src_ip='10.0.0.9', timestamp=BASE),
            alert(2, alert_id='AL-2', src_ip='10.0.0.9', timestamp=BASE + timedelta(minutes=20)),
            alert(3, alert_id='AL-3', src_ip='10.0.0.9', timestamp=BASE + timedelta(minutes=40)),
        ]
        incidents = correlate(alerts)
        self.assertEqual(len(incidents), 2)
        self.assertCountEqual(incidents[0].related_alert_ids, ['AL-1', 'AL-2'])

    def test_correlation_window_is_configurable(self):
        alerts = [
            alert(1, alert_id='AL-1', src_ip='10.0.0.9', timestamp=BASE),
            alert(2, alert_id='AL-2', src_ip='10.0.0.9', timestamp=BASE + timedelta(minutes=20)),
        ]
        self.assertEqual(len(correlate(alerts, window_seconds=900)), 2)
        self.assertEqual(len(correlate(alerts, window_seconds=1800)), 1)


if __name__ == '__main__':
    unittest.main()
