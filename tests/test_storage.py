import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.models import Alert, Event
from backend.storage import (
    init_db,
    load_alerts,
    load_events,
    load_triage,
    save_alerts,
    save_events,
    save_triage,
    search_alerts,
    search_events,
    stats,
)


class StorageTests(unittest.TestCase):
    def test_sqlite_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'events.db'
            init_db(db)
            event = Event.from_dict({
                'id': 'evt-storage-1',
                'source': 'linux_auth',
                'event_type': 'ssh_login',
                'asset': 'lab-host',
                'user': 'adam',
                'src_ip': '203.0.113.10',
                'status': 'failure',
                'message': 'real test event',
                'raw_log': 'real test event',
            })
            self.assertEqual(save_events([event], db), 1)
            self.assertEqual(save_events([event], db), 0)
            loaded = load_events(db)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].id, 'evt-storage-1')
            self.assertEqual(loaded[0].source, 'linux_auth')
            storage_stats = stats(db)
            self.assertEqual(storage_stats['backend'], 'sqlite')
            self.assertEqual(storage_stats['stored_events'], 1)
            self.assertEqual(storage_stats['source_distribution']['linux_auth'], 1)

    def test_limited_load_returns_most_recent_events_in_chronological_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'hot-window.db'
            init_db(db)
            events = [
                Event.from_dict({
                    'id': f'evt-hot-{index}',
                    'timestamp': f'2026-09-01T0{index}:00:00+00:00',
                    'source': 'linux_auth',
                    'event_type': 'ssh_login',
                    'asset': 'host-a',
                    'message': f'event {index}',
                    'raw_log': f'event {index}',
                })
                for index in range(1, 6)
            ]
            self.assertEqual(save_events(events, db), 5)

            loaded = load_events(db, limit=3)

            self.assertEqual(
                [event.id for event in loaded],
                ['evt-hot-3', 'evt-hot-4', 'evt-hot-5'],
            )

    def test_search_events_filters_orders_and_counts_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'search.db'
            init_db(db)
            events = [
                Event.from_dict({
                    'id': 'evt-search-1',
                    'timestamp': '2026-08-31T10:00:00+00:00',
                    'source': 'linux_auth',
                    'event_type': 'ssh_login',
                    'asset': 'host-a',
                    'src_ip': '203.0.113.10',
                    'message': 'failed password for root',
                    'raw_log': 'sshd failed password for root',
                }),
                Event.from_dict({
                    'id': 'evt-search-2',
                    'timestamp': '2026-08-31T10:05:00+00:00',
                    'source': 'linux_auth',
                    'event_type': 'ssh_login',
                    'asset': 'host-a',
                    'src_ip': '203.0.113.11',
                    'message': 'failed password for admin',
                    'raw_log': 'sshd failed password for admin',
                }),
                Event.from_dict({
                    'id': 'evt-search-3',
                    'timestamp': '2026-08-31T10:10:00+00:00',
                    'source': 'windows_security',
                    'event_type': 'logon_success',
                    'asset': 'host-b',
                    'src_ip': '203.0.113.12',
                    'message': 'interactive logon',
                    'raw_log': 'successful interactive logon',
                }),
            ]
            self.assertEqual(save_events(events, db), 3)

            results, total = search_events(
                db,
                source='linux_auth',
                query='failed password',
                start=datetime(2026, 8, 31, 10, 1, tzinfo=timezone.utc),
                end=datetime(2026, 8, 31, 10, 6, tzinfo=timezone.utc),
                limit=10,
                offset=0,
            )

            self.assertEqual(total, 1)
            self.assertEqual([event.id for event in results], ['evt-search-2'])

            all_results, all_total = search_events(db, limit=2, offset=0)
            self.assertEqual(all_total, 3)
            self.assertEqual(
                [event.id for event in all_results],
                ['evt-search-3', 'evt-search-2'],
            )

    def test_alert_round_trip_is_idempotent_and_newest_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'alerts.db'
            init_db(db)
            alerts = [
                Alert(
                    alert_id='AL-DURABLE-1',
                    rule_id='DET-TEST-1',
                    title='First alert',
                    severity='high',
                    confidence=0.91,
                    tactic='Initial Access',
                    technique='T1078',
                    timestamp=datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc),
                    asset='host-a',
                    user='adam',
                    src_ip='203.0.113.10',
                    event_ids=['evt-1'],
                    evidence=['evidence-1'],
                    recommended_action='Investigate.',
                ),
                Alert(
                    alert_id='AL-DURABLE-2',
                    rule_id='DET-TEST-2',
                    title='Second alert',
                    severity='critical',
                    confidence=0.97,
                    tactic='Execution',
                    technique='T1059',
                    timestamp=datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc),
                    asset='host-b',
                    event_ids=['evt-2'],
                    evidence=['evidence-2'],
                    recommended_action='Contain.',
                ),
            ]

            self.assertEqual(save_alerts(alerts, db), 2)
            self.assertEqual(save_alerts(alerts, db), 0)
            loaded = load_alerts(db)

            self.assertEqual([alert.alert_id for alert in loaded], ['AL-DURABLE-2', 'AL-DURABLE-1'])
            self.assertEqual(loaded[0].event_ids, ['evt-2'])
            self.assertEqual(loaded[1].user, 'adam')
            self.assertEqual(stats(db)['stored_alerts'], 2)

    def test_search_alerts_filters_orders_and_counts_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'alert-search.db'
            init_db(db)
            alerts = [
                Alert(
                    alert_id='AL-SEARCH-1',
                    rule_id='DET-AUTH-1',
                    title='Credential attack',
                    severity='high',
                    confidence=0.90,
                    tactic='Credential Access',
                    technique='T1110',
                    timestamp=datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc),
                    asset='host-a',
                    user='adam',
                    src_ip='203.0.113.10',
                    event_ids=['evt-1'],
                    evidence=['failed logins'],
                    recommended_action='Investigate.',
                ),
                Alert(
                    alert_id='AL-SEARCH-2',
                    rule_id='DET-AUTH-2',
                    title='Admin credential attack',
                    severity='critical',
                    confidence=0.97,
                    tactic='Credential Access',
                    technique='T1110',
                    timestamp=datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc),
                    asset='host-a',
                    user='admin',
                    src_ip='203.0.113.11',
                    event_ids=['evt-2'],
                    evidence=['password spray'],
                    recommended_action='Contain.',
                ),
                Alert(
                    alert_id='AL-SEARCH-3',
                    rule_id='DET-EXEC-1',
                    title='PowerShell execution',
                    severity='medium',
                    confidence=0.82,
                    tactic='Execution',
                    technique='T1059.001',
                    timestamp=datetime(2026, 9, 1, 11, 0, tzinfo=timezone.utc),
                    asset='host-b',
                    user='admin',
                    src_ip='203.0.113.12',
                    event_ids=['evt-3'],
                    evidence=['encoded command'],
                    recommended_action='Review process tree.',
                ),
            ]
            self.assertEqual(save_alerts(alerts, db), 3)

            results, total = search_alerts(
                db,
                severity='critical',
                tactic='Credential Access',
                asset='host-a',
                user='admin',
                src_ip='203.0.113.11',
                rule_id='DET-AUTH-2',
                start=datetime(2026, 9, 1, 9, 30, tzinfo=timezone.utc),
                end=datetime(2026, 9, 1, 10, 30, tzinfo=timezone.utc),
                limit=10,
                offset=0,
            )

            self.assertEqual(total, 1)
            self.assertEqual([alert.alert_id for alert in results], ['AL-SEARCH-2'])

            all_results, all_total = search_alerts(db, limit=2, offset=0)
            self.assertEqual(all_total, 3)
            self.assertEqual(
                [alert.alert_id for alert in all_results],
                ['AL-SEARCH-3', 'AL-SEARCH-2'],
            )

    def test_triage_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'triage.db'
            init_db(db)
            saved = save_triage({
                'alert_id': 'AL-42',
                'action': 'contain',
                'analyst': 'soc-user',
                'status': 'recorded',
                'request_id': 'req-1',
            }, db)
            self.assertEqual(saved['alert_id'], 'AL-42')
            loaded = load_triage(db)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]['action'], 'contain')
            self.assertEqual(loaded[0]['request_id'], 'req-1')
            self.assertEqual(stats(db)['stored_triage_records'], 1)


if __name__ == '__main__':
    unittest.main()
