#!/usr/bin/env python3
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dependency_verifier', ROOT / 'scripts/verify_dependency_sources.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class DependencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def command(self, directory, *args, data=None):
        return subprocess.run(['git', '-C', str(directory), *args], input=data,
                              capture_output=True, check=True).stdout.strip()

    def checkout(self, name, files):
        directory = self.directory / name
        directory.mkdir()
        self.command(directory, 'init', '--quiet')
        self.command(directory, 'config', 'core.autocrlf', 'false')
        self.command(directory, 'config', 'core.fsmonitor', 'false')
        entries = []
        for relative, data in sorted(files.items()):
            path = directory / relative
            path.write_bytes(data)
            blob = self.command(directory, 'hash-object', '-w', '--stdin', data=data).decode()
            entries.append('100644 blob ' + blob + '\t' + relative + '\n')
        tree = self.command(directory, 'mktree', data=''.join(entries).encode()).decode()
        # Synthetic object history exists only in this temporary test repository.
        commit_data = ('tree ' + tree + '\nauthor Test <test@invalid> 0 +0000\n'
                       'committer Test <test@invalid> 0 +0000\n\nfixture\n').encode()
        commit = self.command(directory, 'hash-object', '-t', 'commit', '-w', '--stdin', data=commit_data).decode()
        self.command(directory, 'update-ref', 'HEAD', commit)
        self.command(directory, 'read-tree', 'HEAD')
        return directory, commit

    def test_pins_match_full_deps_fixtures_and_versions(self):
        def fields(data, section):
            # Fixed, hash-checked tables; avoid requiring tomllib on Python 3.10 CI.
            match = re.search(r'^\[' + re.escape(section) + r'\]\n([^\[]*)', data.decode('utf-8'), re.M)
            self.assertIsNotNone(match)
            return dict(re.findall(r'^(version|bootstrap_version|url) = "([^"]+)"$', match[1], re.M))

        for version in ('16.7.19', '17.25.2'):
            pin, data = verifier.pins_for(version)
            deps, glib = fields(data, 'dependencies'), fields(data, 'glib')
            self.assertEqual(deps['version'], pin['sdk_version'])
            self.assertEqual(deps['bootstrap_version'], pin['bootstrap_version'])
            self.assertEqual(glib['version'], pin['glib']['commit'])
            self.assertEqual(glib['url'], pin['glib']['url'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), pin['deps_sha256'])
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            verifier.pins_for('17.0.0')

    def test_real_git_snapshot_matches_every_blob(self):
        files = {'build.py': b'print("fixture")\n', 'source.c': b'int example;\n'}
        directory, commit = self.checkout('source', files)
        result = verifier.snapshot(directory, commit)
        self.assertEqual(result['commit'], commit)
        self.assertEqual(result['submodules'], {})
        self.assertEqual(set(result['files']), set(files))
        for relative, data in files.items():
            self.assertEqual(result['files'][relative]['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.command(directory, 'status', '--porcelain'), b'')

    def test_head_mismatch_rejected_even_when_fetch_head_matches(self):
        directory, commit = self.checkout('source', {'source.c': b'int example;\n'})
        expected = '0' * 40
        (directory / '.git/FETCH_HEAD').write_text(expected + '\n', encoding='ascii')
        with self.assertRaisesRegex(ValueError, 'HEAD mismatch'):
            verifier.snapshot(directory, expected)
        self.assertEqual(verifier.snapshot(directory, commit)['commit'], commit)

    def test_modified_untracked_and_ignored_inputs_are_rejected(self):
        files = {'.gitignore': b'cache/\n', 'source.c': b'int example;\n'}
        directory, commit = self.checkout('source', files)
        source = directory / 'source.c'
        source.write_bytes(b'int changed;\n')
        with self.assertRaisesRegex(ValueError, 'not pristine'):
            verifier.snapshot(directory, commit)
        source.write_bytes(files['source.c'])
        extra = directory / 'unexpected'
        extra.write_bytes(b'not in the input tree')
        with self.assertRaisesRegex(ValueError, 'not pristine'):
            verifier.snapshot(directory, commit)
        extra.unlink()
        (directory / 'cache').mkdir()
        (directory / 'cache/old.manifest').write_bytes(b'old build')
        with self.assertRaisesRegex(ValueError, 'not pristine'):
            verifier.snapshot(directory, commit)

    def test_skip_worktree_cannot_hide_byte_drift(self):
        directory, commit = self.checkout('source', {'source.c': b'int example;\n'})
        self.command(directory, 'update-index', '--skip-worktree', 'source.c')
        (directory / 'source.c').write_bytes(b'int changed;\n')
        self.assertEqual(self.command(directory, 'status', '--porcelain'), b'')
        with self.assertRaisesRegex(ValueError, 'blob byte mismatch'):
            verifier.snapshot(directory, commit)

    def test_nested_non_checkout_and_exported_tree_rejected(self):
        directory, commit = self.checkout('source', {'source.c': b'int example;\n'})
        nested = directory / 'nested'
        nested.mkdir()
        with self.assertRaisesRegex(ValueError, 'own Git checkout'):
            verifier.snapshot(nested, commit)
        exported = self.directory / 'exported'
        exported.mkdir()
        (exported / 'source.c').write_bytes(b'int example;\n')
        with self.assertRaises(subprocess.CalledProcessError):
            verifier.snapshot(exported, commit)

    def test_missing_recursive_submodule_rejected(self):
        directory, _ = self.checkout('source', {'source.c': b'int example;\n'})
        module, module_commit = self.checkout('module', {'source.c': b'int module;\n'})
        blob = self.command(directory, 'hash-object', '-w', '--stdin', data=b'int example;\n').decode()
        tree = self.command(directory, 'mktree', '--missing', data=(
            '160000 commit ' + module_commit + '\tmodule\n100644 blob ' + blob + '\tsource.c\n').encode()).decode()
        commit_data = ('tree ' + tree + '\nauthor Test <test@invalid> 0 +0000\n'
                       'committer Test <test@invalid> 0 +0000\n\nrecursive fixture\n').encode()
        commit = self.command(directory, 'hash-object', '-t', 'commit', '-w', '--stdin', data=commit_data).decode()
        self.command(directory, 'update-ref', 'HEAD', commit)
        self.command(directory, 'read-tree', 'HEAD')
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            verifier.snapshot(directory, commit)
        self.assertTrue(module.is_dir())

    def test_report_is_input_only_and_deps_drift_fails_before_snapshot(self):
        version = '16.7.19'
        pin, data = verifier.pins_for(version)
        releng, releng_commit = self.checkout('releng', {'deps.toml': data})
        glib, glib_commit = self.checkout('glib', {'meson.build': b'project("fixture")\n'})
        pin = {**pin, 'releng_commit': releng_commit, 'glib': {**pin['glib'], 'commit': glib_commit}}
        with patch.object(verifier, 'pins_for', return_value=(pin, data)):
            report = verifier.verify(releng, glib, version)
            self.assertEqual(report['scope'], 'pristine-dependency-inputs-only')
            for field in ('source_modified', 'sdk_built', 'sdk_consumption_verified', 'runtime_tested'):
                self.assertFalse(report[field])
            identity = verifier.digest(json.dumps(report['inputs'], sort_keys=True, separators=(',', ':')).encode())
            self.assertEqual(report['input_sha256'], identity)
            (releng / 'deps.toml').write_bytes(data + b'\n# drift\n')
            with patch.object(verifier, 'snapshot') as snapshot:
                with self.assertRaisesRegex(ValueError, 'deps.toml source drift'):
                    verifier.verify(releng, glib, version)
                snapshot.assert_not_called()

    def test_cli_rejects_existing_or_nested_report_without_writes(self):
        releng = self.directory / 'releng'
        glib = self.directory / 'glib'
        releng.mkdir()
        glib.mkdir()
        report = self.directory / 'keep.json'
        report.write_bytes(b'keep')
        command = [sys.executable, '-I', '-B', str(ROOT / 'scripts/verify_dependency_sources.py'),
                   '--releng', str(releng), '--glib', str(glib), '--version', '16.7.19']
        result = subprocess.run(command + ['--report', str(report)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('report must be new', result.stderr)
        self.assertEqual(report.read_bytes(), b'keep')
        nested = releng / 'new.json'
        result = subprocess.run(command + ['--report', str(nested)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('outside dependency checkouts', result.stderr)
        self.assertFalse(nested.exists())


if __name__ == '__main__':
    unittest.main()
