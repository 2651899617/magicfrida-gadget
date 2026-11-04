#!/usr/bin/env python3
"""Validate source commits and installed NDK before any patch/build step."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def version_info(version):
    manifest = json.loads((ROOT / 'versions.json').read_text(encoding='utf-8'))
    matches = [item for item in manifest['versions'] if item['version'] == version]
    if len(matches) != 1:
        raise ValueError('unsupported or duplicate version: ' + version)
    return matches[0]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def verify(source, version, ndk):
    expected = version_info(version)
    actual = {'commit': run('git', '-C', str(source), 'rev-parse', 'HEAD'), 'submodules': {}}
    if actual['commit'] != expected['commit']:
        raise ValueError('superproject commit mismatch')
    for relative, sha in expected['submodules'].items():
        value = run('git', '-C', str(source / relative), 'rev-parse', 'HEAD')
        if value != sha:
            raise ValueError('submodule commit mismatch: ' + relative)
        actual['submodules'][relative] = value
    props = (ndk / 'source.properties').read_text(encoding='utf-8')
    match = re.search(r'^Pkg\.Revision\s*=\s*(\S+)\s*$', props, re.M)
    if not match or match[1] != expected['ndk_revision']:
        raise ValueError('installed NDK revision mismatch')
    env_source = (source / 'releng/env_android.py').read_text(encoding='utf-8')
    required = re.search(r'^NDK_REQUIRED\s*=\s*(\d+)\s*$', env_source, re.M)
    if not required or int(required[1]) != expected['ndk_major']:
        raise ValueError('pinned releng NDK requirement mismatch')
    if 'ANDROID_NDK_ROOT' not in env_source:
        raise ValueError('unverified NDK environment variable')
    actual.update({'schema': 1, 'version': version, 'ndk_revision': match[1],
                   'python': platform.python_version(), 'node': run('node', '--version'),
                   'npm': run('npm.cmd' if os.name == 'nt' else 'npm', '--version'),
                   'git': run('git', '--version'), 'runtime_tested': False})
    # Preserve all gitlinks without collecting remote URLs or any credentials.
    actual['submodule_status'] = run('git', '-C', str(source), 'submodule', 'status', '--recursive').splitlines()
    if any(line and line[0] in '-+U' for line in actual['submodule_status']):
        raise ValueError('submodules missing, drifting, or conflicted')
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.source.resolve(), args.version, args.ndk.resolve())
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print('PASS: pinned source and NDK verified; no runtime claim')
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
