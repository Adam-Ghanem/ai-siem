import unittest

from backend.investigation import build_investigation
from backend.models import Anomaly, Incident


class InvestigationEntityMatchingTests(unittest.TestCase):
    def test_user_entity_matching_requires_exact_identity_not_substring(self):
        incident = Incident(
            incident_id='INC-ENTITY',
            title='Identity investigation',
            priority='P3',
            status='open',
            owner='unassigned',
            related_alert_ids=[],
            related_assets=[],
            related_users=['alice'],
            related_src_ips=[],
            evidence_summary='Identity-scoped signal',
            timeline=[],
            recommended_actions=[],
        )
        anomalies = [
            Anomaly(
                anomaly_id='anom-exact',
                entity='alice',
                anomaly_score=0.5,
                reason='Exact user anomaly',
                contributing_features={},
                related_event_ids=[],
                recommended_action='Review alice',
            ),
            Anomaly(
                anomaly_id='anom-substring',
                entity='malice',
                anomaly_score=1.0,
                reason='Different identity containing alice as a substring',
                contributing_features={},
                related_event_ids=[],
                recommended_action='Review malice',
            ),
        ]

        analysis = build_investigation(incident, [], [], anomalies)

        self.assertEqual(analysis['related_anomaly_ids'], ['anom-exact'])
        self.assertNotIn('Review malice', analysis['recommended_actions'])
        self.assertFalse(
            any('anom-substring' in evidence for evidence in analysis['key_evidence'])
        )


if __name__ == '__main__':
    unittest.main()
