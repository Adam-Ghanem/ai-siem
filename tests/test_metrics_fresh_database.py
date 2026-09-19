import tempfile
import unittest
from pathlib import Path

from backend.metrics_storage import calculate_sqlite_metrics


class FreshDatabaseMetricsTests(unittest.TestCase):
    def test_metrics_initialize_incident_schema_on_fresh_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / 'fresh.db'

            metrics = calculate_sqlite_metrics(db_path)

            self.assertEqual(metrics['total_events'], 0)
            self.assertEqual(metrics['total_alerts'], 0)
            self.assertEqual(metrics['open_incidents'], 0)
            self.assertEqual(metrics['risk_score'], 0)
            self.assertEqual(metrics['top_tactics'], {})
            self.assertEqual(metrics['source_distribution'], {})
            self.assertEqual(metrics['event_type_distribution'], {})


if __name__ == '__main__':
    unittest.main()
