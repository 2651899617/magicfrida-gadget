#!/usr/bin/env python3
import ast
import difflib
import enum
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dependency_profiles', ROOT / 'scripts/apply_dependency_profile.py')
profiles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profiles)


class DependencyProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def source(self, component, version, name):
        source = self.directory / name
        fixture = (ROOT / 'tests/fixtures/glib' / version if component == 'glib'
                   else ROOT / 'tests/fixtures' / version / 'releng')
        shutil.copytree(fixture, source)
        return source

    def test_apply_repeat_dry_run_and_report_boundaries(self):
        for component in ('glib', 'releng'):
            for version in profiles.recipes.VERSIONS:
                with self.subTest(component=component, version=version):
                    source = self.source(component, version, component + version)
                    before = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
                    report = self.directory / (component + version + '-dry.json')
                    result = profiles.apply(source, version, component, report, True)
                    self.assertTrue(result['dry_run'])
                    self.assertEqual(before, {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()})
                    result = profiles.apply(source, version, component, self.directory / (component + version + '.json'))
                    self.assertTrue(any(item['status'] == 'applied' for item in result['files']))
                    for field in ('complete_checkout_verified', 'sdk_built', 'sdk_consumption_verified', 'runtime_tested'):
                        self.assertFalse(result[field])
                    pending, records, _ = profiles.prepare(source, version, component)
                    self.assertEqual(pending, [])
                    self.assertNotIn('applied', [item['status'] for item in records])
                    with self.assertRaisesRegex(ValueError, 'must be new'):
                        profiles.apply(source, version, component, report)
                    with self.assertRaisesRegex(ValueError, 'outside source'):
                        profiles.apply(source, version, component, source / 'report.json')

    def test_drift_missing_and_staging_conflict_do_not_apply(self):
        for component in ('glib', 'releng'):
            for version in profiles.recipes.VERSIONS:
                source = self.source(component, version, component + version)
                _, _, recipe = profiles.prepare(source, version, component)
                path = source / recipe['files'][-1]['path']
                original = path.read_bytes()
                path.write_bytes(original + b'\n/* drift */\n')
                before = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
                with self.assertRaisesRegex(ValueError, 'source drift'):
                    profiles.apply(source, version, component, self.directory / 'failed.json')
                self.assertEqual(before, {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()})
                self.assertFalse((self.directory / 'failed.json').exists())
                path.unlink()
                with self.assertRaisesRegex(ValueError, 'regular dependency file missing'):
                    profiles.apply(source, version, component, self.directory / 'missing.json')
                path.write_bytes(original)
                pending, _, _ = profiles.prepare(source, version, component)
                temporary = pending[-1][0].with_name(pending[-1][0].name + '.nianchu-tmp')
                temporary.write_bytes(b'keep staging conflict')
                with self.assertRaises(FileExistsError):
                    profiles.apply(source, version, component, self.directory / 'conflict.json')
                self.assertEqual(temporary.read_bytes(), b'keep staging conflict')
                for relative, data in before.items():
                    expected = original if relative == path.relative_to(source) else data
                    self.assertEqual((source / relative).read_bytes(), expected)

    def test_exported_dependency_diffs_replay_with_zero_fuzz(self):
        tool = shutil.which('patch')
        self.assertIsNotNone(tool, 'patch is required for dependency profile replay')
        for component in ('glib', 'releng'):
            for version in profiles.recipes.VERSIONS:
                source = self.source(component, version, component + version)
                pending, _, recipe = profiles.prepare(source, version, component)
                expected = dict(pending)
                diff = []
                for entry in recipe['files']:
                    path = source / entry['path']
                    before = path.read_bytes().decode()
                    after = expected.get(path, path.read_bytes()).decode()
                    diff.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                    fromfile='a/' + entry['path'], tofile='b/' + entry['path']))
                path = ROOT / 'patches' / component / version / (recipe['profile'] + '.patch')
                self.assertEqual(path.read_bytes(), ''.join(diff).encode())
                result = subprocess.run([tool, '--binary', '-p1', '--fuzz=0', '--batch', '--input', str(path)],
                                        cwd=source, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('offset', result.stdout.lower())
                self.assertNotIn('fuzz', result.stdout.lower())
                self.assertEqual(profiles.prepare(source, version, component)[0], [])

    def test_glib_profile_only_changes_diagnostic_thread_names(self):
        for version in profiles.recipes.VERSIONS:
            source = self.source('glib', version, version)
            pending, records, recipe = profiles.prepare(source, version, 'glib')
            self.assertEqual(len(pending), 2)
            self.assertEqual(len(records), 7)
            edits = {'glib/gmain.c': (b'g_thread_new ("gmain",', b'g_thread_new ("nianchu-worker",'),
                     'gio/gdbusprivate.c': (b'g_thread_new ("gdbus",', b'g_thread_new ("nianchu-dbus",')}
            for path, after in pending:
                relative = path.relative_to(source).as_posix()
                old, new = edits[relative]
                self.assertEqual(after, path.read_bytes().replace(old, new))
            self.assertLessEqual(len('nianchu-worker'.encode()), 15)
            self.assertLessEqual(len('nianchu-dbus'.encode()), 15)
            unchanged = {entry['path'] for entry in recipe['files'] if not entry['edits']}
            self.assertEqual(unchanged, {'glib/gthread.c', 'gio/meson.build', 'gio/gdbusproxy.c',
                                         'gio/gdbusproxy.h', 'LICENSES/LGPL-2.1-or-later.txt'})


class SdkLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.sdk = self.directory / 'sdk-android-arm64'
        (self.sdk / 'lib').mkdir(parents=True)
        (self.sdk / 'VERSION.txt').write_bytes(b'fixed-sdk\n')
        (self.sdk / 'lib/libglib.a').write_bytes(b'synthetic test bytes; not a real SDK')
        self.lock = self.directory / 'sdk-lock.json'
        self.write_lock()

    def write_lock(self, **changes):
        lock = {'schema': 1, 'machine': 'android-arm64', 'sdk_version': 'fixed-sdk',
                'prefix': self.sdk.resolve().as_posix(),
                'files': {p.relative_to(self.sdk).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in self.sdk.rglob('*') if p.is_file()}}
        lock.update(changes)
        self.lock.write_text(json.dumps(lock), encoding='utf-8')
        return lock

    def load_functions(self, version):
        recipe = json.loads((ROOT / 'patches/releng' / version / 'spec.json').read_text(encoding='utf-8'))
        fixture = (ROOT / 'tests/fixtures' / version / 'releng/deps.py').read_bytes()
        self.assertEqual(profiles.recipes.digest(fixture), recipe['files'][0]['upstream_sha256'])
        after = profiles.recipes.transform(fixture, recipe['files'][0]['edits'])
        tree = ast.parse(after.decode('utf-8'))
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('_verify_locked_sdk', 'sync')]
        self.assertEqual(len(nodes), 2)
        class Bundle(enum.Enum):
            SDK = 1
            TOOLCHAIN = 2
        namespace = {'Path': Path, 'os': os, 'json': json, 're': re, 'Bundle': Bundle,
                     'SourceState': types.SimpleNamespace(PRISTINE='pristine', MODIFIED='modified'),
                     'shutil': types.SimpleNamespace(rmtree=lambda *_: self.fail('SDK deletion must not be reached')),
                     'compute_bundle_parameters': lambda *_: self.fail('SDK archive/network path must not be reached'),
                     'load_dependency_parameters': lambda: types.SimpleNamespace(deps_version='fixed-sdk')}
        # Execute only the two edited functions with I/O fallbacks replaced by failing test doubles.
        module = ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0), *nodes],
                            type_ignores=[])
        for node in nodes:
            node.args.defaults = [ast.Constant(value=None) for _ in node.args.defaults]
        exec(compile(ast.fix_missing_locations(module), '<sdk-source-model>', 'exec'), namespace)
        return namespace

    def call(self, namespace, *, version='fixed-sdk', machine='android-arm64', location=None):
        with patch.dict(os.environ, {'NIANCHU_SDK_LOCK': str(self.lock)}):
            return namespace['sync'](namespace['Bundle'].SDK, types.SimpleNamespace(identifier=machine),
                                     location or self.sdk, version)

    def test_lock_success_and_unlocked_upstream_behavior(self):
        for version in profiles.recipes.VERSIONS:
            namespace = self.load_functions(version)
            self.assertEqual(self.call(namespace), 'pristine')
            self.assertEqual(self.call(namespace, version=None), 'pristine')
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(namespace['sync'](namespace['Bundle'].SDK,
                                                  types.SimpleNamespace(identifier='android-arm64'),
                                                  self.sdk, 'fixed-sdk'), 'pristine')
            with patch.dict(os.environ, {'NIANCHU_SDK_LOCK': 'ignored-for-toolchain'}):
                self.assertEqual(namespace['sync'](namespace['Bundle'].TOOLCHAIN,
                                                  types.SimpleNamespace(identifier='android-arm64'),
                                                  self.sdk, 'fixed-sdk'), 'pristine')

    def test_lock_identity_missing_and_relative_paths_fail_before_fallback(self):
        for version in profiles.recipes.VERSIONS:
            namespace = self.load_functions(version)
            for options in ({'version': 'wrong'}, {'machine': 'android-arm'},
                            {'location': self.directory / 'missing'}, {'location': Path('relative-sdk')}):
                with self.subTest(version=version, options=options), self.assertRaises(ValueError):
                    self.call(namespace, **options)
            original = self.lock.read_bytes()
            self.lock.unlink()
            with self.assertRaisesRegex(ValueError, 'missing'):
                self.call(namespace)
            self.lock.write_bytes(original)
            with patch.dict(os.environ, {'NIANCHU_SDK_LOCK': 'relative.json'}), self.assertRaisesRegex(ValueError, 'absolute'):
                namespace['sync'](namespace['Bundle'].SDK, types.SimpleNamespace(identifier='android-arm64'),
                                  self.sdk, 'fixed-sdk')
            self.assertTrue(self.sdk.is_dir())

    def test_hash_file_set_and_version_content_fail_closed(self):
        for version in profiles.recipes.VERSIONS:
            namespace = self.load_functions(version)
            library = self.sdk / 'lib/libglib.a'
            original = library.read_bytes()
            library.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                self.call(namespace)
            library.write_bytes(original)
            library.unlink()
            with self.assertRaisesRegex(ValueError, 'file set mismatch'):
                self.call(namespace)
            library.write_bytes(original)
            extra = self.sdk / 'unexpected'
            extra.write_bytes(b'extra')
            with self.assertRaisesRegex(ValueError, 'file set mismatch'):
                self.call(namespace)
            extra.unlink()
            marker = self.sdk / 'VERSION.txt'
            marker.write_bytes(b'wrong\n')
            self.write_lock()
            with self.assertRaisesRegex(ValueError, 'version mismatch'):
                self.call(namespace)
            marker.write_bytes(b'fixed-sdk\n')
            self.write_lock()

    def test_malformed_duplicate_and_unsafe_lock_paths_rejected(self):
        for version in profiles.recipes.VERSIONS:
            namespace = self.load_functions(version)
            valid = self.write_lock()
            for lock in ({**valid, 'schema': True}, {**valid, 'files': {}},
                         {**valid, 'files': {**valid['files'], '../outside': '0' * 64}},
                         {**valid, 'files': {**valid['files'], 'a\\b': '0' * 64}},
                         {**valid, 'files': {**valid['files'], 'x': 'not-a-hash'}}):
                self.lock.write_text(json.dumps(lock), encoding='utf-8')
                with self.assertRaises(ValueError):
                    self.call(namespace)
            self.lock.write_text('{"schema":1,"schema":1}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                self.call(namespace)
            self.write_lock()
            nested = self.sdk / 'lock.json'
            nested.write_bytes(self.lock.read_bytes())
            with patch.dict(os.environ, {'NIANCHU_SDK_LOCK': str(nested)}), self.assertRaisesRegex(ValueError, 'outside the SDK'):
                namespace['sync'](namespace['Bundle'].SDK, types.SimpleNamespace(identifier='android-arm64'),
                                  self.sdk, 'fixed-sdk')
            nested.unlink()


if __name__ == '__main__':
    unittest.main()
