import unittest

from backend.models import Event


class EventIdentityValidationTests(unittest.TestCase):
    def test_rejects_blank_required_identity_fields(self):
        for field in ('source', 'event_type'):
            payload = {'source': 'sensor', 'event_type': 'auth'}
            payload[field] = '   '\n            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    Event.from_dict(payload)

    def test_rejects_blank_explicit_event_id(self):
        with self.assertRaisesRegex(ValueError, 'id'):
            Event.from_dict({'id': '   ', 'source': 'sensor', 'event_type': 'auth'})


if __name__ == '__main__':
    unittest.main()
