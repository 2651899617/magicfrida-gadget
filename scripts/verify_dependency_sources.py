#!/usr/bin/env python3
"""Verify pristine pinned dependency inputs; this does not build or certify an SDK."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(directory, *args):
    return subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                           '-c', 'core.untrackedCache=false', '-C', str(directory), *args],
                          capture_output=True, check=True).stdout


def pins_for(version):
    pins = json.loads((ROOT / 'patches/dependencies.json').read_text(encoding='utf-8'))['versions']
    if version not in pins:
        raise ValueError('unsupported dependency version')
    pin = pins[version]
    versions = json.loads((ROOT / 'versions.json').read_text(encoding='utf-8'))['versions']
    matches = [item for item in versions if item['version'] == version]
    if len(matches) != 1 or matches[0]['submodules']['releng'] != pin['releng_commit']:
        raise ValueError('dependency releng pin mismatch')
    fixture = (ROOT / 'tests/fixtures' / version / 'releng/deps.toml').read_bytes()
    if digest(fixture) != pin['deps_sha256']:
        raise ValueError('corrupt pinned deps.toml fixture')
    return pin, fixture


def snapshot(directory, commit):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('dependency checkout must be a regular directory')
    directory = directory.resolve()
    top = Path(os.fsdecode(git(directory, 'rev-parse', '--show-toplevel').strip())).resolve()
    if top != directory:
        raise ValueError('dependency path is not its own Git checkout')
    if git(directory, 'rev-parse', '--show-object-format').strip() != b'sha1':
        raise ValueError('unsupported Git object format')
    if git(directory, 'rev-parse', 'HEAD').strip().decode('ascii') != commit:
        raise ValueError('dependency HEAD mismatch: ' + directory.name)
    status_args = ('status', '--porcelain=v1', '--untracked-files=all', '--ignored', '--ignore-submodules=none')
    if git(directory, *status_args):
        raise ValueError('dependency checkout is not pristine: ' + directory.name)
    entries = git(directory, 'ls-tree', '--full-tree', '-r', '-z', 'HEAD').split(b'\0')
    files, submodules = {}, {}
    for entry in entries:
        if not entry:
            continue
        header, encoded_path = entry.split(b'\t', 1)
        mode, kind, object_id = header.decode('ascii').split(' ')
        relative = encoded_path.decode('utf-8')
        name = PurePosixPath(relative)
        if (name.is_absolute() or '..' in name.parts or '\\' in relative or ':' in relative
                or any(part.lower() == '.git' for part in name.parts)):
            raise ValueError('invalid dependency tree path')
        path = directory / relative
        if any(parent.is_symlink() for parent in path.parents if parent != directory and parent.is_relative_to(directory)):
            raise ValueError('symlink in dependency parent path')
        if mode == '160000' and kind == 'commit':
            submodules[relative] = snapshot(path, object_id)
            continue
        if kind != 'blob' or mode not in ('100644', '100755', '120000'):
            raise ValueError('unsupported dependency tree entry')
        if mode == '120000':
            if not path.is_symlink():
                raise ValueError('dependency symlink checkout mismatch')
            data = os.fsencode(os.readlink(path))
        else:
            if path.is_symlink() or not path.is_file():
                raise ValueError('required regular dependency file missing')
            data = path.read_bytes()
        actual_blob = hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()
        if actual_blob != object_id:
            raise ValueError('dependency blob byte mismatch: ' + relative)
        files[relative] = {'mode': mode, 'sha256': digest(data)}
    if git(directory, 'rev-parse', 'HEAD').strip().decode('ascii') != commit or git(directory, *status_args):
        raise ValueError('dependency checkout changed during verification')
    return {'commit': commit, 'files': files, 'submodules': submodules}


def verify(releng, glib, version):
    pin, fixture = pins_for(version)
    if releng.is_symlink() or glib.is_symlink():
        raise ValueError('dependency roots must not be symlinks')
    releng, glib = releng.resolve(), glib.resolve()
    if releng.is_relative_to(glib) or glib.is_relative_to(releng):
        raise ValueError('dependency checkouts must be separate')
    deps = releng / 'deps.toml'
    if deps.is_symlink() or not deps.is_file() or deps.read_bytes() != fixture:
        raise ValueError('pinned deps.toml source drift')
    inputs = {'releng': snapshot(releng, pin['releng_commit']),
              'glib': snapshot(glib, pin['glib']['commit'])}
    identity = digest(json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode('utf-8'))
    return {'schema': 1, 'version': version, 'scope': 'pristine-dependency-inputs-only',
            'sdk_version': pin['sdk_version'], 'bootstrap_version': pin['bootstrap_version'],
            'deps_sha256': pin['deps_sha256'], 'inputs': inputs, 'input_sha256': identity,
            'source_modified': False, 'sdk_built': False, 'sdk_consumption_verified': False,
            'runtime_tested': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--releng', type=Path, required=True)
    parser.add_argument('--glib', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.report.exists() or args.report.is_symlink():
            raise ValueError('report must be new')
        if any(args.report.resolve().is_relative_to(path.resolve()) for path in (args.releng, args.glib)):
            raise ValueError('report must be outside dependency checkouts')
        report = verify(args.releng, args.glib, args.version)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open('x', encoding='utf-8', newline='\n') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        print('PASS: pristine dependency inputs verified; SDK not built or consumption verified')
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
