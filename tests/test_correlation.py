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

if __name__ == '__main__':
    unittest.main()
