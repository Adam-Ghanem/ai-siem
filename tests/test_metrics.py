import unittest
from tests.helpers import event, alert
from backend.correlation import correlate
from backend.metrics import calculate_metrics

class MetricsTests(unittest.TestCase):
    def test_total_events_equals_len_events(self):
        events = [event(i) for i in range(3)]
        metrics = calculate_metrics(events, [], [])
        self.assertEqual(metrics['total_events'], len(events))

    def test_risk_score_changes_with_alerts_and_incidents(self):
        events = [event(1)]
        no_risk = calculate_metrics(events, [], [])['risk_score']
        alerts = [alert(1, severity='critical')]
        with_risk = calculate_metrics(events, alerts, correlate(alerts))['risk_score']
        self.assertGreater(with_risk, no_risk)

    def test_source_and_event_type_distribution(self):
        events = [event(1, source='linux_auth', event_type='ssh_login'), event(2, source='firewall', event_type='network_connection'), event(3, source='firewall', event_type='network_connection')]
        metrics = calculate_metrics(events, [], [])
        self.assertEqual(metrics['source_distribution']['firewall'], 2)
        self.assertEqual(metrics['event_type_distribution']['network_connection'], 2)

if __name__ == '__main__':
    unittest.main()
