import unittest
from datetime import datetime, timezone

from backend.anomaly import detect_anomalies
from tests.helpers import event


class AnomalyTests(unittest.TestCase):
    def test_high_failed_login_count_creates_anomaly(self):
        anomalies = detect_anomalies(
            [
                event(i, status='failure', user='root', src_ip='203.0.113.10')
                for i in range(5)
            ]
        )
        self.assertTrue(any('failed-login' in a.reason for a in anomalies))

    def test_rare_source_ip_for_same_user(self):
        events = [
            event(1, status='success', user='adam', src_ip='10.0.0.1'),
            event(2, status='success', user='adam', src_ip='10.0.0.2'),
            event(3, status='success', user='adam', src_ip='10.0.0.3'),
            event(4, status='success', user='adam', src_ip='198.51.100.10'),
        ]

        anomalies = detect_anomalies(events)

        self.assertTrue(any('Rare source IP' in a.reason for a in anomalies))

    def test_public_172_address_is_not_misclassified_as_private(self):
        events = [
            event(1, status='success', user='adam', src_ip='10.0.0.1'),
            event(2, status='success', user='adam', src_ip='10.0.0.2'),
            event(3, status='success', user='adam', src_ip='10.0.0.3'),
            event(4, status='success', user='adam', src_ip='172.200.10.25'),
        ]

        anomalies = detect_anomalies(events)

        self.assertTrue(
            any('Rare source IP 172.200.10.25' in a.reason for a in anomalies)
        )

    def test_off_hours_privileged_access(self):
        anomalies = detect_anomalies(
            [
                event(
                    1,
                    status='success',
                    user='root',
                    timestamp=datetime(2026, 6, 11, 23, 15, tzinfo=timezone.utc),
                )
            ]
        )
        self.assertTrue(
            any(
                a.anomaly_score >= 0.7 and 'Privileged access' in a.reason
                for a in anomalies
            )
        )

    def test_benign_events_produce_few_or_no_high_score_anomalies(self):
        anomalies = detect_anomalies(
            [
                event(i, status='success', user=f'user{i}', src_ip=f'10.0.0.{i}')
                for i in range(1, 4)
            ]
        )
        self.assertFalse(any(a.anomaly_score >= 0.8 for a in anomalies))


if __name__ == '__main__':
    unittest.main()
