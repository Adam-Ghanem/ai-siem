import unittest

from backend.rule_validation import validate_rule, validate_rules
from backend.rules import RULES


class DetectionRuleValidationTests(unittest.TestCase):
    def test_production_rules_are_valid(self):
        self.assertEqual(validate_rules(RULES), RULES)

    def test_duplicate_rule_ids_are_rejected(self):
        rule = dict(RULES[0])
        with self.assertRaisesRegex(ValueError, 'duplicate detection rule id'):
            validate_rules([rule, dict(rule)])

    def test_unknown_event_field_is_rejected(self):
        rule = dict(RULES[0])
        rule['group_by'] = ['definitely_not_an_event_field']
        with self.assertRaisesRegex(ValueError, 'unknown event field'):
            validate_rule(rule)

    def test_invalid_regex_is_rejected_before_runtime_detection(self):
        rule = dict(RULES[0])
        rule['regex'] = {'message': ['([unterminated']}
        with self.assertRaisesRegex(ValueError, 'invalid regex'):
            validate_rule(rule)

    def test_invalid_confidence_and_threshold_are_rejected(self):
        bad_confidence = dict(RULES[0])
        bad_confidence['confidence'] = 1.5
        with self.assertRaisesRegex(ValueError, 'confidence must be between 0 and 1'):
            validate_rule(bad_confidence)

        bad_threshold = dict(RULES[0])
        bad_threshold['threshold'] = 0
        with self.assertRaisesRegex(ValueError, 'threshold must be a positive integer'):
            validate_rule(bad_threshold)

    def test_distinct_field_cannot_duplicate_grouping_dimension(self):
        rule = dict(RULES[0])
        rule['distinct_field'] = 'src_ip'
        with self.assertRaisesRegex(ValueError, 'must not also appear in group_by'):
            validate_rule(rule)


if __name__ == '__main__':
    unittest.main()
