#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('source_verifier', ROOT / 'scripts/verify_source.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class SourceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / 'source'
        self.ndk = self.root / 'ndk'
        (self.source / 'releng').mkdir(parents=True)
        self.ndk.mkdir()
        self.expected = copy.deepcopy(verifier.version_info('17.25.2'))
        self.head = self.expected['commit']
        self.submodules = copy.deepcopy(self.expected['submodules'])
        self.status = '\n'.join(' ' + sha + ' ' + path + ' (pinned)' for path, sha in self.submodules.items())
        self.properties = self.ndk / 'source.properties'
        self.properties.write_text('Pkg.Revision = ' + self.expected['ndk_revision'] + '\n', encoding='utf-8')
        self.env_source = self.source / 'releng/env_android.py'
        self.env_source.write_text('NDK_REQUIRED = 29\nNDK_VAR = "ANDROID_NDK_ROOT"\n', encoding='utf-8')

    def command(self, *args):
        if args[-2:] == ('rev-parse', 'HEAD'):
            path = Path(args[2])
            if path == self.source:
                return self.head
            return self.submodules[path.relative_to(self.source).as_posix()]
        if args[-3:] == ('submodule', 'status', '--recursive'):
            return self.status
        if args == ('node', '--version'):
            return 'v22.0.0'
        if args[-1] == '--version':
            return 'mock actual version'
        raise AssertionError('unexpected command: ' + repr(args))

    def verify(self):
        with patch.object(verifier, 'run', side_effect=self.command):
            return verifier.verify(self.source, '17.25.2', self.ndk)

    def test_exact_source_and_ndk_report(self):
        report = self.verify()
        self.assertEqual(report['commit'], self.expected['commit'])
        self.assertEqual(report['submodules'], self.expected['submodules'])
        self.assertEqual(report['ndk_revision'], '29.0.14206865')
        self.assertFalse(report['runtime_tested'])
        self.assertIn('python', report)
        self.assertIn('submodule_status', report)

    def test_top_level_and_submodule_drift_fail(self):
        self.head = '0' * 40
        with self.assertRaisesRegex(ValueError, 'superproject'):
            self.verify()
        self.head = self.expected['commit']
        self.submodules['releng'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'submodule commit'):
            self.verify()

    def test_wrong_exact_ndk_revision_fails(self):
        self.properties.write_text('Pkg.Revision = 29.0.99999999\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'installed NDK'):
            self.verify()

    def test_upstream_requirement_drift_fails(self):
        self.env_source.write_text('NDK_REQUIRED = 25\nANDROID_NDK_ROOT = 0\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'NDK requirement'):
            self.verify()
        self.env_source.write_text('NDK_REQUIRED = 29\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'environment variable'):
            self.verify()

    def test_uninitialized_drifting_or_conflicted_status_fails(self):
        for marker in '-+U':
            self.status = marker + self.expected['submodules']['releng'] + ' releng'
            with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, 'submodules missing'):
                self.verify()


if __name__ == '__main__':
    unittest.main()
