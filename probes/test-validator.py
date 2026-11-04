#!/usr/bin/env python3
"""Standalone regression checks for native handback case admission."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location('validator', Path(__file__).with_name('validate-results.py'))
assert spec is not None and spec.loader is not None
validator = module_from_spec(spec)
spec.loader.exec_module(validator)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.coverage = self.root / 'COVERAGE.md'
        self.coverage.write_text('## Windows Crystal — 2 cases\n- `first`\n- `second`\n'
                                 '## macOS Crystal — 1 cases\n- `mac`\n'
                                 '## macOS independent SDK/C — 1 cases\n- `sdk`\n', encoding='utf-8')
        self.path = self.root / 'results.jsonl'
        self.items = [self.record('first'), self.record('second')]
        self.write(self.items)

    def tearDown(self):
        self.tmp.cleanup()

    def record(self, name, status='pass'):
        return {'schema': 1, 'platform': 'windows', 'checkpoint': '0009',
                'case': name, 'status': status, 'details': {}}

    def write(self, items):
        failures = sum(r['status'] in ('fail', 'error') for r in items)
        skips = sum(r['status'] == 'skip' for r in items)
        summary = self.record('summary', 'fail' if failures else 'pass')
        summary['details'] = {'cases': str(len(items)), 'failures': str(failures), 'skips': str(skips)}
        self.path.write_text(''.join(json.dumps(r) + '\n' for r in items + [summary]), encoding='utf-8')

    def check(self):
        return validator.validate(self.coverage, 'windows', self.root)

    def test_complete(self):
        self.assertEqual(self.check(), 2)

    def test_missing(self):
        self.write(self.items[:1])
        with self.assertRaisesRegex(ValueError, 'missing=second'):
            self.check()

    def test_duplicate(self):
        self.write(self.items + self.items[:1])
        with self.assertRaisesRegex(ValueError, 'duplicate=first'):
            self.check()

    def test_unknown_case(self):
        self.write(self.items + [self.record('extra')])
        with self.assertRaisesRegex(ValueError, 'unexpected=extra'):
            self.check()

    def test_failure_even_with_valid_summary(self):
        self.write([self.record('first', 'fail'), self.record('second')])
        with self.assertRaisesRegex(ValueError, 'nonpassing=first:fail'):
            self.check()

    def test_skip_not_qualification(self):
        self.write([self.record('first', 'skip'), self.record('second')])
        with self.assertRaisesRegex(ValueError, 'nonpassing=first:skip'):
            self.check()

    def test_summary_contradiction(self):
        self.write(self.items)
        records = [json.loads(s) for s in self.path.read_text().splitlines()]
        records[-1]['details']['cases'] = '999'
        self.path.write_text(''.join(json.dumps(r) + '\n' for r in records))
        with self.assertRaisesRegex(ValueError, 'summary counters'):
            self.check()

    def test_missing_summary(self):
        self.path.write_text(''.join(json.dumps(r) + '\n' for r in self.items))
        with self.assertRaisesRegex(ValueError, 'summary'):
            self.check()

    def test_wrong_checkpoint(self):
        self.write(self.items)
        records = [json.loads(s) for s in self.path.read_text().splitlines()]
        records[0]['checkpoint'] = '0007'
        self.path.write_text(''.join(json.dumps(r) + '\n' for r in records))
        with self.assertRaisesRegex(ValueError, 'wrong checkpoint'):
            self.check()

    def test_sdk_lane_with_real_summary_shape(self):
        sdk = {'schema': 1, 'platform': 'macos', 'source': 'native-sdk-c',
               'case': 'sdk', 'status': 'pass', 'details': {}}
        summary = {'schema': 1, 'platform': 'macos', 'source': 'native-sdk-c',
                   'case': 'summary', 'status': 'pass',
                   'details': {'cases': 1, 'failures': 0}}
        (self.root / 'abi-results.jsonl').write_text(
            json.dumps(sdk) + '\n' + json.dumps(summary) + '\n', encoding='utf-8')
        self.assertEqual(validator.validate(self.coverage, 'sdk', self.root), 1)

    def test_sdk_missing_summary(self):
        sdk = {'schema': 1, 'platform': 'macos', 'source': 'native-sdk-c',
               'case': 'sdk', 'status': 'pass', 'details': {}}
        (self.root / 'abi-results.jsonl').write_text(json.dumps(sdk) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'summary'):
            validator.validate(self.coverage, 'sdk', self.root)

    def test_sdk_summary_contradiction(self):
        sdk = {'schema': 1, 'platform': 'macos', 'source': 'native-sdk-c',
               'case': 'sdk', 'status': 'pass', 'details': {}}
        summary = {'schema': 1, 'platform': 'macos', 'source': 'native-sdk-c',
                   'case': 'summary', 'status': 'pass',
                   'details': {'cases': 2, 'failures': 0}}
        (self.root / 'abi-results.jsonl').write_text(
            json.dumps(sdk) + '\n' + json.dumps(summary) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'summary counters'):
            validator.validate(self.coverage, 'sdk', self.root)


if __name__ == '__main__':
    unittest.main()
