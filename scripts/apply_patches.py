#!/usr/bin/env python3
"""Apply pinned, version-specific source changes; never patch release binaries."""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ('16.7.19', '17.25.2')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def transform(data, edits):
    text = data.decode('utf-8')
    for edit in edits:
        old, new, count = edit['old'], edit['new'], edit['count']
        if text.count(old) != count:
            raise ValueError('expected exactly ' + str(count) + ' occurrences of ' + repr(old))
        text = text.replace(old, new)
    return text.encode('utf-8')


def selected_features(spec, features=()):
    if len(features) != len(set(features)):
        raise ValueError('duplicate features')
    unknown = set(features) - set(spec['features'])
    if unknown:
        raise ValueError('unsupported features: ' + ', '.join(sorted(unknown)))
    defaults = spec.get('default_features', [])
    if len(defaults) != len(set(defaults)) or not set(defaults).issubset(spec['features']):
        raise ValueError('invalid default features')
    return [*defaults, *(feature for feature in features if feature not in defaults)]


def profile_bytes(base, entry, features):
    expected = transform(base, entry['edits'])
    for feature in features:
        expected = transform(expected, entry.get('optional', {}).get(feature, []))
    return expected


def prepare(source, version, features=()):
    if version not in VERSIONS:
        raise ValueError('unsupported version: ' + version)
    spec = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
    effective = selected_features(spec, features)
    pending, records = [], []
    for entry in spec['files']:
        path = source / entry['path']
        if not path.is_file() or path.is_symlink():
            raise ValueError('required regular source file missing: ' + str(path))
        base = (ROOT / 'tests' / 'fixtures' / version / entry['path']).read_bytes()
        if digest(base) != entry['upstream_sha256']:
            raise ValueError('corrupt pinned source fixture: ' + entry['path'])
        compatible = profile_bytes(base, entry, spec.get('default_features', []))
        expected = profile_bytes(base, entry, effective)
        actual = path.read_bytes()
        if actual == expected:
            status = 'already-applied' if expected != base else 'verified-unchanged'
        elif actual == base or (features and actual == compatible):
            status = 'applied' if expected != base else 'verified-unchanged'
            if expected != base:
                pending.append((path, expected))
        else:
            raise ValueError('source drift or partially applied patch: ' + entry['path'])
        records.append({'path': entry['path'], 'status': status,
                        'upstream_sha256': digest(base), 'result_sha256': digest(expected)})
    return pending, records, spec


def apply(source, version, report, features=(), dry_run=False):
    source = source.resolve()
    if report.resolve().is_relative_to(source):
        raise ValueError('report must be outside source tree')
    if report.is_symlink():
        raise ValueError('report must not be a symlink')
    pending, records, spec = prepare(source, version, features)
    staged = []
    try:
        if not dry_run:
            for path, data in pending:
                temporary = path.with_name(path.name + '.nianchu-tmp')
                with temporary.open('xb') as output:
                    output.write(data)
                temporary.chmod(path.stat().st_mode & 0o777)
                staged.append((temporary, path))
            for temporary, path in staged:
                os.replace(temporary, path)
            # A fresh preparation must accept every final file, including no-op guards.
            prepare(source, version, features)
    finally:
        for temporary, _ in staged:
            if temporary.exists():
                temporary.unlink()
    result = {'schema': 1, 'version': version, 'profile': 'nianchu-compatible',
              'features': selected_features(spec, features), 'dry_run': dry_run, 'files': records,
              'java_bridge': spec['java_bridge'],
              'binary_rewriting': False, 'runtime_tested': False}
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def export_diff(version, feature=None):
    spec = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
    output = []
    for entry in spec['files']:
        base = (ROOT / 'tests' / 'fixtures' / version / entry['path']).read_bytes()
        compatible = transform(base, entry['edits'])
        if feature:
            before, after = compatible, transform(compatible, entry.get('optional', {}).get(feature, []))
        else:
            before, after = base, compatible
        output.extend(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                          fromfile='a/' + entry['path'], tofile='b/' + entry['path']))
    return ''.join(output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--version', choices=VERSIONS, required=True)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--feature', action='append', default=[])
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = apply(args.source.resolve(), args.version, args.report, args.feature, args.dry_run)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
