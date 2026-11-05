#!/usr/bin/env python3
"""Prepare an isolated source-only Java bridge experiment; never alter client packages."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('patch_recipes', ROOT / 'scripts/apply_patches.py')
recipes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipes)


VERSIONS = ('6.3.9', '7.0.13')


def prepare(source, out, version='6.3.9'):
    if version not in VERSIONS:
        raise ValueError('unsupported bridge version')
    recipe = json.loads((ROOT / 'patches/java-bridge' / version / 'spec.json').read_text(encoding='utf-8'))
    source = source.resolve()
    out = out.resolve()
    if out.exists() or out.is_relative_to(source) or source.is_relative_to(out):
        raise ValueError('output must be new and separate from source')
    paths = list(source.rglob('*'))
    if any(path.is_symlink() for path in paths):
        raise ValueError('package symlinks are not supported')
    files = {path.relative_to(source).as_posix(): path.read_bytes() for path in paths if path.is_file()}
    if set(files) != set(recipe['package_files']):
        raise ValueError('package file set mismatch')
    for relative, sha in recipe['package_files'].items():
        if recipes.digest(files[relative]) != sha:
            raise ValueError('official package source drift: ' + relative)
    for entry in recipe['files']:
        relative = entry['path']
        fixture = (ROOT / 'tests/fixtures/java-bridge' / version / relative).read_bytes()
        if recipes.digest(fixture) != entry['upstream_sha256'] or files[relative] != fixture:
            raise ValueError('corrupt or mismatching pinned bridge fixture')
        files[relative] = recipes.transform(fixture, entry['edits'])
    out.mkdir(parents=True)
    package_dir = out / 'package'
    for relative, data in files.items():
        path = package_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as output:
            output.write(data)
        if path.read_bytes() != data:
            raise ValueError('prepared bridge byte identity mismatch')
    report = {'schema': 1, 'version': recipe['version'], 'profile': recipe['profile'],
              'source': recipe['source'], 'integration': recipe['integration'],
              'retained': recipe['retained'], 'unsupported': recipe['unsupported'],
              'files': {relative: recipes.digest(data) for relative, data in sorted(files.items())},
              'package_executed': False, 'runtime_tested': False, 'bundled_runtime_built': False}
    (out / 'bridge-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='verified official package directory')
    parser.add_argument('--version', choices=VERSIONS, default='6.3.9')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare(args.source, args.out, args.version)
        print('PASS: ' + report['profile'] + ' source prepared; not bundled or runtime tested')
    except (OSError, ValueError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
