#!/usr/bin/env python3
import difflib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bridge_preparer', ROOT / 'scripts/prepare_java_bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class JavaBridgeTests(unittest.TestCase):
    version = '6.3.9'
    integration = 'standalone-source-only'

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / 'source'
        shutil.copytree(ROOT / 'tests/fixtures/java-bridge' / self.version, self.source)
        self.out = self.directory / 'prepared'

    def test_prepare_is_isolated_and_reports_retained_features(self):
        before = {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob('*') if p.is_file()}
        report = bridge.prepare(self.source, self.out, self.version)
        self.assertEqual(before, {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob('*') if p.is_file()})
        self.assertEqual(report['profile'], 'direct-art-gc')
        self.assertEqual(report['integration'], self.integration)
        self.assertFalse(report['runtime_tested'])
        self.assertFalse(report['bundled_runtime_built'])
        self.assertEqual(set(report['retained']), {'GetOatQuickMethodHeader', 'GC-class-reference-sync', 'PrettyMethod', 'JDWP'})
        self.assertEqual(json.loads((self.out / 'bridge-report.json').read_text(encoding='utf-8')), report)
        for relative, sha in report['files'].items():
            self.assertEqual(bridge.recipes.digest((self.out / 'package' / relative).read_bytes()), sha)
            if relative not in ('lib/android.js', 'lib/class-factory.js'):
                self.assertEqual((self.out / 'package' / relative).read_bytes(), (self.source / relative).read_bytes())
        for version in ('16.7.19', '17.25.2'):
            recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            self.assertFalse(recipe['java_bridge']['modified'])

    def test_source_drift_missing_and_extra_files_fail_before_output(self):
        path = self.source / 'lib/android.js'
        original = path.read_bytes()
        path.write_bytes(original + b'\n// drift\n')
        with self.assertRaisesRegex(ValueError, 'source drift'):
            bridge.prepare(self.source, self.out, self.version)
        self.assertFalse(self.out.exists())
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'file set mismatch'):
            bridge.prepare(self.source, self.out, self.version)
        self.assertFalse(self.out.exists())
        path.write_bytes(original)
        (self.source / 'unexpected.js').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'file set mismatch'):
            bridge.prepare(self.source, self.out, self.version)
        self.assertFalse(self.out.exists())

    def test_existing_and_nested_outputs_are_rejected(self):
        self.out.mkdir()
        sentinel = self.out / 'keep'
        sentinel.write_bytes(b'unchanged')
        with self.assertRaisesRegex(ValueError, 'new and separate'):
            bridge.prepare(self.source, self.out, self.version)
        self.assertEqual(sentinel.read_bytes(), b'unchanged')
        with self.assertRaisesRegex(ValueError, 'new and separate'):
            bridge.prepare(self.source, self.source / 'nested', self.version)
        self.assertFalse((self.source / 'nested').exists())

    def test_diff_and_zero_fuzz_replay_match_recipe(self):
        bridge.prepare(self.source, self.out, self.version)
        expected = []
        for relative in ('lib/android.js', 'lib/class-factory.js'):
            before = (self.source / relative).read_bytes()
            after = (self.out / 'package' / relative).read_bytes()
            expected.extend(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                                fromfile='a/' + relative, tofile='b/' + relative))
        patch = ROOT / 'patches/java-bridge' / self.version / 'direct-art-gc.patch'
        self.assertEqual(patch.read_bytes(), ''.join(expected).encode())
        tool = shutil.which('patch')
        if not tool:
            self.skipTest('patch tool unavailable')
        result = subprocess.run([tool, '--binary', '-p1', '--fuzz=0', '--batch', '--input', str(patch)],
                                cwd=self.source, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('offset', result.stdout.lower())
        self.assertNotIn('fuzz', result.stdout.lower())
        for relative in ('lib/android.js', 'lib/class-factory.js'):
            self.assertEqual((self.source / relative).read_bytes(), (self.out / 'package' / relative).read_bytes())

    def test_gc_oat_roles_and_non_direct_features_are_preserved(self):
        bridge.prepare(self.source, self.out, self.version)
        text = (self.out / 'package/lib/android.js').read_text(encoding='utf-8')
        self.assertIn('is_replacement = g_hash_table_contains (methods, method);', text)
        self.assertIn('*((uint32_t *) replacement_method) = *((uint32_t *) hooked_method);', text)
        self.assertIn('g_hash_table_insert (replacements, replacement_method, original_method);', text)
        self.assertIn('Interceptor.attach(copyingPhase, artController.hooks.Gc.copyingPhase);', text)
        self.assertIn('Interceptor.attach(runFlip, artController.hooks.Gc.runFlip);', text)
        self.assertIn('Interceptor.replace(getOatQuickMethodHeaderImpl, artController.hooks.ArtMethod.getOatQuickMethodHeader);', text)
        original = (self.source / 'lib/android.js').read_text(encoding='utf-8')
        start = original.index('function requestDeoptimization (')
        end = original.index('function makeJdwpOptions () {', start)
        self.assertIn(original[start:end], text)
        start = text.index('class ArtMethodMangler {')
        end = text.index('function xposedIsSupported () {', start)
        self.assertNotIn('notifyArtMethodHooked(', text[start:end])
        self.assertNotIn('ArtQuickCodeInterceptor', text[start:end])
        self.assertIn('ensureArtKnowsHowToHandleReplacementMethods(vm);', text[start:end])

    def test_direct_method_source_model_and_syntax(self):
        bridge.prepare(self.source, self.out, self.version)
        node = shutil.which('node')
        self.assertIsNotNone(node, 'node is required for the direct ART source model')
        android = self.out / 'package/lib/android.js'
        for relative in ('lib/android.js', 'lib/class-factory.js'):
            syntax = subprocess.run([node, '--check', str(self.out / 'package' / relative)], capture_output=True, text=True)
            self.assertEqual(syntax.returncode, 0, syntax.stdout + syntax.stderr)
        result = subprocess.run([node, str(ROOT / 'tests/test_direct_art_model.js'), str(android),
                                 str(self.out / 'package/lib/class-factory.js')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('39 checks; no Android runtime claim', result.stdout)
        print(result.stdout.strip())


class ExternalJavaBridgeTests(JavaBridgeTests):
    version = '7.0.13'
    integration = 'external-esm-source-only'

    def test_external_esm_and_clone_synchronization_are_preserved(self):
        bridge.prepare(self.source, self.out, self.version)
        package = self.out / 'package'
        metadata = json.loads((package / 'package.json').read_text(encoding='utf-8'))
        self.assertEqual(metadata['type'], 'module')
        self.assertEqual((package / 'index.js').read_bytes(), (self.source / 'index.js').read_bytes())
        text = (package / 'lib/android.js').read_text(encoding='utf-8')
        self.assertIn('export function makeMethodMangler (methodId)', text)
        self.assertIn('quick_code = replacement_method + quick_code_offset;', text)
        self.assertNotIn('quick_code = hooked_method + quick_code_offset;', text)


if __name__ == '__main__':
    unittest.main()
