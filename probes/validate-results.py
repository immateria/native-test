#!/usr/bin/env python3
"""Validate exact revision-11 native coverage. A diagnostic handback may fail validation."""
import argparse
import json
from collections import Counter
from pathlib import Path
import re
import sys

SECTIONS = {
    'windows': 'Windows Crystal',
    'macos': 'macOS Crystal',
    'sdk': 'macOS independent SDK/C',
}


def expected_cases(coverage, lane):
    content = Path(coverage).read_text(encoding='utf-8')
    heading = None
    names = {key: [] for key in SECTIONS}
    for line in content.splitlines():
        if line.startswith('## '):
            heading = next((key for key, title in SECTIONS.items()
                            if line.startswith('## ' + title + ' ')), None)
        elif heading and line.startswith('- `'):
            match = re.fullmatch(r'- `([^`]+)`', line)
            if not match:
                raise ValueError(f'malformed coverage entry: {line}')
            names[heading].append(match.group(1))
    for key, entries in names.items():
        if not entries or len(entries) != len(set(entries)):
            raise ValueError(f'missing or duplicate coverage definitions: {key}')
    return set(names[lane])


def validate(coverage, lane, directory):
    directory = Path(directory)
    expected = expected_cases(coverage, lane)
    filename = 'abi-results.jsonl' if lane == 'sdk' else 'results.jsonl'
    records = []
    for number, line in enumerate((directory / filename).read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            raise ValueError(f'{filename}:{number}: empty record')
        try:
            record = json.loads(line)
        except (ValueError, TypeError) as error:
            raise ValueError(f'{filename}:{number}: invalid JSON: {error}') from error
        if not isinstance(record, dict) or not isinstance(record.get('case'), str):
            raise ValueError(f'{filename}:{number}: invalid record/case')
        if record.get('schema') != 1 or record.get('platform') != ('windows' if lane == 'windows' else 'macos'):
            raise ValueError(f'{filename}:{number}: wrong schema/platform')
        if lane == 'sdk':
            if record.get('source') != 'native-sdk-c':
                raise ValueError(f'{filename}:{number}: wrong SDK source')
        elif record.get('checkpoint') != '0009':
            raise ValueError(f'{filename}:{number}: wrong checkpoint')
        if record.get('status') not in ('pass', 'fail', 'error', 'skip', 'info'):
            raise ValueError(f'{filename}:{number}: invalid status')
        records.append(record)

    if not records:
        raise ValueError(f'{filename}: no results')
    summary = [r for r in records if r['case'] == 'summary']
    if len(summary) != 1 or records[-1] is not summary[0]:
        raise ValueError('missing/duplicate/non-final summary')
    summary_record = summary[0]
    details = summary_record.get('details')
    if not isinstance(details, dict):
        raise ValueError('summary details missing')
    body = records[:-1]
    failures = sum(r['status'] in ('fail', 'error') for r in body)
    skips = sum(r['status'] == 'skip' for r in body)
    counters_match = (
        str(details.get('cases')) == str(len(body)) and
        str(details.get('failures')) == str(failures)
    )
    if lane != 'sdk':
        counters_match = counters_match and str(details.get('skips')) == str(skips)
    if not counters_match or summary_record['status'] != ('pass' if failures == 0 else 'fail'):
        raise ValueError('summary counters/status contradict result records')

    counted = [r for r in records if r['case'] in expected]
    counts = Counter(r['case'] for r in counted)
    missing = sorted(expected - counts.keys())
    duplicate = sorted(name for name, number in counts.items() if number != 1)
    unexpected = sorted({r['case'] for r in records if r['case'] not in expected and
                         r['case'] != 'summary' and r['status'] != 'info'})
    nonpassing = sorted(r['case'] + ':' + r['status'] for r in counted if r['status'] != 'pass')
    if missing or duplicate or unexpected or nonpassing:
        issues = []
        for label, values in [('missing', missing), ('duplicate', duplicate),
                              ('unexpected', unexpected), ('nonpassing', nonpassing)]:
            if values:
                issues.append(label + '=' + ','.join(values[:12]) + ('...' if len(values) > 12 else ''))
        raise ValueError('; '.join(issues))
    if any(r['status'] in ('fail', 'error', 'skip') for r in records):
        raise ValueError('nonpassing diagnostic/summary record')
    return len(expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--coverage', required=True)
    parser.add_argument('--lane', choices=SECTIONS, required=True)
    parser.add_argument('--results', required=True)
    args = parser.parse_args()
    try:
        count = validate(args.coverage, args.lane, args.results)
    except (OSError, ValueError) as error:
        print(f'qualification_validation=fail lane={args.lane} error={error}', file=sys.stderr)
        return 1
    print(f'qualification_validation=pass lane={args.lane} cases={count}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
