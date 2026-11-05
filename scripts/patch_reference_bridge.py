#!/usr/bin/env python3
"""Apply only the reference PrettyMethod hook deletion to a private npm package.

Run with python -I. The source is the actual node_modules/frida-java-bridge
package, not its parent or a prepared direct-art-gc package. Every package file
must match the pinned official inventory, either wholly original or wholly
reference-patched. Additional files (including package-local node_modules),
symlinks and junctions are rejected; sibling npm dependencies are unaffected.
The report must be outside the package. Do not run npm concurrently with this
operation. No package code is executed and no Android runtime claim is made.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ('6.3.9', '7.0.13')
AUTHOR = 'nianchu'
PROFILE = 'reference-disable-art-prettymethod-hook'
TARGET = 'lib/android.js'
REFERENCE_PATCH = 'frida-gum/frida-disable_art_prettymethod_hook.patch'
INVENTORY_SHA256 = {
    '6.3.9': '19da4ccdbf0d076f7a9903161694ccb9082934be09b94a9e44c96b035dee2604',
    '7.0.13': '45b060f600be4c9056a7dcc580e89e84d0cb1a1a3305ff958c36cd062653ded9',
}
PATCHED_ANDROID_SHA256 = {
    '6.3.9': 'bcc4ea4b6840834689d97f345737aa3c4c65e00bc99eebddf13d340491ebf342',
    '7.0.13': 'f7aa948853da310094f87ed77d58d3cea8c72776143057a6ff26bf8f7284c8e4',
}
SOURCE_PINS = {
    '6.3.9': {
        'url': 'https://registry.npmjs.org/frida-java-bridge/-/frida-java-bridge-6.3.9.tgz',
        'integrity': 'sha512-fExkTX26591TZQAPuKCcWZUkpxHeSEV/D+cCWyZl2CDRy0grgXGqdDrZePcx656a8w/w2UDheLCI3zDZERVAFg==',
        'shasum': '0d17c2aeeba526cead21b6b3b0b7ea5f1660d490',
        'sha256': 'fc0a7ff83903f758a5b2f36094768f09fd3ad4ce4a455c49eb96495a594147c9',
        'license': 'LGPL-2.0 WITH WxWindows-exception-3.1',
    },
    '7.0.13': {
        'url': 'https://registry.npmjs.org/frida-java-bridge/-/frida-java-bridge-7.0.13.tgz',
        'integrity': 'sha512-YSyKjxbxKnSi3KSUy9vciOvTOuq0RRh9dkxzkQVEdfIIZlw20zE8D3Cq9eL2FDqUVj4YKas6Wf09kCjL5zbffg==',
        'shasum': '5d67beeae3c00e895c18c5f47f582480800c2c09',
        'sha256': '0ae4e5393b5bf237ba7cfe23666248a7e6884cc9321ac0a77f073bcb30d951c0',
        'license': 'LGPL-2.0 WITH WxWindows-exception-3.1',
    },
}
REMOVED_LINES = (
    b'  Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);\n'
    b'  Interceptor.flush();\n'
)
ORIGINAL_FUNCTION = b"""function fixupArtQuickDeliverExceptionBug (api) {
  const prettyMethod = api['art::ArtMethod::PrettyMethod'];
  if (prettyMethod === undefined) {
    return;
  }

  /*
   * There is a bug in art::Thread::QuickDeliverException() where it assumes
   * there is a Java stack frame present on the art::Thread's stack. This is
   * not the case if a native thread calls a throwing method like FindClass().
   *
   * We work around this bug here by detecting when method->PrettyMethod()
   * happens with method == nullptr.
   */
  Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);
  Interceptor.flush();
}
"""
PATCHED_FUNCTION = ORIGINAL_FUNCTION.replace(REMOVED_LINES, b'', 1)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')


def load_inventory(version):
    if version not in VERSIONS:
        raise ValueError('unsupported bridge version: ' + str(version))
    recipe = json.loads((ROOT / 'patches/java-bridge' / version / 'spec.json').read_bytes())
    inventory = recipe.get('package_files')
    canonical = json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if (recipe.get('version') != version or not isinstance(inventory, dict)
            or digest(canonical) != INVENTORY_SHA256[version]
            or recipe.get('source') != SOURCE_PINS[version]):
        raise ValueError('pinned official bridge inventory identity mismatch')
    # Intentionally do not read or apply the legacy recipe's profile or edits.
    return inventory


def checked_path(path, label):
    path = Path(path).absolute()
    for component in (path, *path.parents):
        if (component.is_symlink()
                or (hasattr(component, 'is_junction') and component.is_junction())):
            raise ValueError(label + ' must not contain symlinks or junctions')
    return path.resolve()


def read_package(source):
    source = checked_path(source, 'bridge source')
    if not source.is_dir():
        raise ValueError('bridge source must be an existing package directory')
    files = {}

    def walk_error(error):
        raise error

    for directory, dirs, names in os.walk(source, followlinks=False, onerror=walk_error):
        parent = Path(directory)
        for name in dirs + names:
            path = parent / name
            if (path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())):
                raise ValueError('bridge package must not contain symlinks or junctions')
        for name in names:
            path = parent / name
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError('bridge package must contain only regular files')
            files[path.relative_to(source).as_posix()] = path.read_bytes()
    return source, files


def package_hashes(files):
    return {relative: digest(data) for relative, data in sorted(files.items())}


def preflight(source, version):
    inventory = load_inventory(version)
    source, files = read_package(source)
    missing = sorted(set(inventory) - set(files))
    extra = sorted(set(files) - set(inventory))
    if missing or extra:
        raise ValueError('official package file set mismatch; missing=' + repr(missing)
                         + '; extra=' + repr(extra))
    before = package_hashes(files)
    patched = dict(inventory, **{TARGET: PATCHED_ANDROID_SHA256[version]})
    if before == inventory:
        state = 'original'
        if files[TARGET].count(ORIGINAL_FUNCTION) != 1 or files[TARGET].count(REMOVED_LINES) != 1:
            raise ValueError('reference hook exact byte guard mismatch')
        android = files[TARGET].replace(ORIGINAL_FUNCTION, PATCHED_FUNCTION, 1)
        if digest(android) != PATCHED_ANDROID_SHA256[version]:
            raise ValueError('reference hook result hash guard mismatch')
    elif before == patched:
        state = 'patched'
        android = files[TARGET]
        if android.count(PATCHED_FUNCTION) != 1 or REMOVED_LINES in android:
            raise ValueError('patched reference hook exact byte guard mismatch')
    else:
        drift = [relative for relative in sorted(inventory)
                 if before[relative] not in (inventory[relative], patched[relative])]
        raise ValueError('official package source drift or partial profile: ' + ', '.join(drift))
    return source, files, before, state, android


def stage_bytes(path, data, mode=None):
    """Stage a regular sibling file for an atomic replacement; clean up on error."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.nianchu-', suffix='.tmp', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if mode is not None:
            temporary.chmod(mode)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def atomic_write(path, data):
    temporary = stage_bytes(path, data, stat.S_IMODE(path.stat().st_mode))
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def patch(source, version, report_path):
    source = checked_path(source, 'bridge source')
    report_path = checked_path(report_path, 'report path')
    if report_path.is_relative_to(source):
        raise ValueError('report must be external to the bridge package')
    if report_path.exists() and not report_path.is_file():
        raise ValueError('report must be a regular file path')
    for parent in report_path.parents:
        if parent.exists() and not parent.is_dir():
            raise ValueError('report parent must be a directory')
    source, files, before, state, android = preflight(source, version)
    expected_after = package_hashes(dict(files, **{TARGET: android}))
    report = {
        'schema': 1,
        'author': AUTHOR,
        'profile': PROFILE,
        'version': version,
        'reference_patch': REFERENCE_PATCH,
        'source': str(source),
        'upstream': SOURCE_PINS[version],
        'status': 'patched' if state == 'original' else 'already-patched',
        'state_before': state,
        'state_after': 'patched',
        'patch_files': [TARGET],
        'changed_files': [TARGET] if state == 'original' else [],
        'before': before,
        'after': expected_after,
        'package_executed': False,
        'runtime_tested': False,
    }
    # No writes, including report creation, occur until the entire group passes.
    # Stage the external report first so an invalid/unwritable output fails before
    # changing android.js. Its predicted hashes are proven against actual bytes
    # after the replacement, before the success report is published.
    report_path.parent.mkdir(parents=True, exist_ok=True)
    staged_report = stage_bytes(report_path, json_bytes(report))
    try:
        if state == 'original':
            atomic_write(source / TARGET, android)
        _, actual_files = read_package(source)
        actual_after = package_hashes(actual_files)
        if actual_after != expected_after:
            raise ValueError('reference bridge post-write full package identity mismatch')
        report['after'] = actual_after
        os.replace(staged_report, report_path)
    finally:
        staged_report.unlink(missing_ok=True)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True,
                        help='actual private node_modules/frida-java-bridge directory')
    parser.add_argument('--version', choices=VERSIONS, required=True)
    parser.add_argument('--report', type=Path, required=True,
                        help='JSON report outside the bridge package')
    args = parser.parse_args(argv)
    try:
        report = patch(args.source, args.version, args.report)
    except (OSError, ValueError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    print('PASS: ' + report['status'] + ' ' + args.version + '; only ' + TARGET
          + '; runtime_tested=false')
    return 0


if __name__ == '__main__':
    sys.exit(main())
