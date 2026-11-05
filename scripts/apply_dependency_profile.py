#!/usr/bin/env python3
"""Apply a separate pinned dependency recipe; never build or certify SDK consumption."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('source_recipes', ROOT / 'scripts/apply_patches.py')
recipes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipes)


def prepare(source, version, component):
    if (version not in recipes.VERSIONS or component not in ('glib', 'releng', 'gum-runtime')
            or (component == 'gum-runtime' and version != '16.7.19')):
        raise ValueError('unsupported dependency profile')
    recipe = json.loads((ROOT / 'patches' / component / version / 'spec.json').read_text(encoding='utf-8'))
    pending, records = [], []
    for entry in recipe['files']:
        relative = entry['path']
        if component == 'glib':
            fixture = ROOT / 'tests/fixtures/glib' / version / relative
        elif component == 'releng':
            fixture = ROOT / 'tests/fixtures' / version / 'releng' / relative
        else:
            fixture = ROOT / 'tests/fixtures' / version / 'subprojects/frida-gum' / relative
        base = fixture.read_bytes()
        if recipes.digest(base) != entry['upstream_sha256']:
            raise ValueError('corrupt pinned dependency fixture')
        path = source / relative
        if not path.is_file() or path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ValueError('required regular dependency file missing: ' + relative)
        expected = recipes.transform(base, entry['edits'])
        actual = path.read_bytes()
        if actual == expected:
            status = 'already-applied' if expected != base else 'verified-unchanged'
        elif actual == base:
            status = 'applied'
            pending.append((path, expected))
        else:
            raise ValueError('dependency source drift or partial profile: ' + relative)
        records.append({'path': relative, 'status': status, 'upstream_sha256': recipes.digest(base),
                        'result_sha256': recipes.digest(expected)})
    return pending, records, recipe


def apply(source, version, component, report, dry_run=False):
    if source.is_symlink() or any(parent.is_symlink() for parent in source.parents):
        raise ValueError('dependency source path must not contain symlinks')
    source = source.resolve()
    if report.exists() or report.is_symlink():
        raise ValueError('dependency report must be new')
    if report.resolve().is_relative_to(source):
        raise ValueError('dependency report must be outside source')
    pending, records, recipe = prepare(source, version, component)
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
            prepare(source, version, component)
    finally:
        for temporary, _ in staged:
            if temporary.exists():
                temporary.unlink()
    result = {'schema': 1, 'version': version, 'component': component, 'profile': recipe['profile'],
              'scope': recipe['scope'], 'dry_run': dry_run, 'files': records,
              'complete_checkout_verified': False, 'sdk_built': False,
              'sdk_consumption_verified': False, 'runtime_tested': False}
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--version', choices=recipes.VERSIONS, required=True)
    parser.add_argument('--component', choices=('glib', 'releng', 'gum-runtime'), required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        result = apply(args.source, args.version, args.component, args.report, args.dry_run)
        print('PASS: ' + result['profile'] + ' source contract; no SDK build or final-link claim')
    except (OSError, ValueError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
