#!/usr/bin/env python3
import ast
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


profiles = load('runtime_profiles', 'scripts/apply_dependency_profile.py')
bridge = load('runtime_bridge', 'scripts/prepare_java_bridge.py')
FIXTURE = ROOT / 'tests/fixtures/16.7.19/subprojects/frida-gum'


class BridgeRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / 'gum'
        self.recipe = json.loads((ROOT / 'patches/gum-runtime/16.7.19/spec.json').read_text(encoding='utf-8'))
        for entry in self.recipe['files']:
            path = self.source / entry['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((FIXTURE / entry['path']).read_bytes())
        self.prepared = self.directory / 'bridge'
        bridge.prepare(ROOT / 'tests/fixtures/java-bridge/6.3.9', self.prepared)
        self.package = self.prepared / 'package'
        pending, _, _ = profiles.prepare(self.source, '16.7.19', 'gum-runtime')
        self.expected = dict(pending)
        self.runtime_source = self.expected[self.source / 'bindings/gumjs/generate-runtime.py']
        self.namespace = {'__name__': 'runtime_source_model', '__file__': str(self.source / 'bindings/gumjs/generate-runtime.py')}
        # Pinned code only; npm/compiler invocations are replaced below, never executed here.
        exec(compile(self.runtime_source, '<runtime-source-model>', 'exec'), self.namespace)
        self.output = self.directory / 'output'
        self.output.mkdir()
        self.priv = self.directory / 'runtime-cache'
        self.experimental_priv = self.priv.with_name(self.priv.name + '-direct-art-gc')
        self.input = self.directory / 'input'
        (self.input / 'runtime').mkdir(parents=True)
        for relative in ('entrypoint-quickjs.js', 'entrypoint-v8.js', 'objc.js', 'swift.js', 'java.js'):
            (self.input / 'runtime' / relative).write_text('// synthetic compiler input\n', encoding='utf-8')
        self.calls = []

    def cache(self, directory, experimental=False):
        package = directory / 'node_modules/frida-java-bridge'
        shutil.copytree(self.package if experimental else ROOT / 'tests/fixtures/java-bridge/6.3.9', package)
        compiler = directory / 'node_modules/.bin' / self.namespace['make_script_filename']('frida-compile')
        compiler.parent.mkdir()
        compiler.write_bytes(b'not an executable compiler; model only')
        return package

    def fake_run(self, args, **kwargs):
        cwd = Path(kwargs['cwd'])
        self.calls.append((list(args), cwd))
        name = Path(args[0]).name
        if name.startswith('frida-compile'):
            output = cwd / args[args.index('-o') + 1]
            output.parent.mkdir(parents=True, exist_ok=True)
            package = cwd / 'node_modules/frida-java-bridge'
            observed = {p.relative_to(package).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in package.rglob('*') if p.is_file()}
            if cwd == self.experimental_priv:
                self.assertEqual(observed, self.recipe['bridge_result_hashes'])
            else:
                self.assertEqual(observed, self.namespace['NIANCHU_BRIDGE_BASE_HASHES'])
            fingerprint = observed['lib/android.js']
            output.write_text('// SOURCE MODEL ONLY ' + fingerprint + '\n', encoding='utf-8')
        elif name == 'quickcompile-model':
            output = cwd / args[-1]
            output.write_bytes(b'MODEL-NOT-QUICKJS-BYTECODE:' + hashlib.sha256((cwd / args[-2]).read_bytes()).digest())
        else:
            self.fail('unexpected external invocation: ' + repr(args))
        return subprocess.CompletedProcess(args, 0)

    def generate(self, backends, package=None):
        cmodule = self.namespace['generate_runtime_cmodule']
        self.namespace['generate_runtime_cmodule'] = lambda output, *_: (output / 'gumcmodule-runtime.h').write_bytes(b'model')
        try:
            with patch.object(self.namespace['subprocess'], 'run', side_effect=self.fake_run):
                self.namespace['generate_runtime'](self.output, self.priv, self.input, self.directory,
                                                   self.directory, None, Path('npm-model'),
                                                   Path('quickcompile-model'), backends, 'arm64',
                                                   sys.byteorder, package)
        finally:
            self.namespace['generate_runtime_cmodule'] = cmodule

    def test_recipe_apply_repeat_drift_and_zero_fuzz_replay(self):
        diff = []
        for entry in self.recipe['files']:
            path = self.source / entry['path']
            diff.extend(difflib.unified_diff(path.read_bytes().decode().splitlines(True),
                                            self.expected[path].decode().splitlines(True),
                                            fromfile='a/' + entry['path'], tofile='b/' + entry['path']))
        exported = ROOT / 'patches/gum-runtime/16.7.19/direct-art-runtime.patch'
        self.assertEqual(exported.read_bytes(), ''.join(diff).encode())
        tool = shutil.which('patch')
        self.assertIsNotNone(tool)
        result = subprocess.run([tool, '--binary', '-p1', '--fuzz=0', '--batch', '--input', str(exported)],
                                cwd=self.source, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('fuzz', result.stdout.lower())
        self.assertNotIn('offset', result.stdout.lower())
        self.assertEqual(profiles.prepare(self.source, '16.7.19', 'gum-runtime')[0], [])
        report = profiles.apply(self.source, '16.7.19', 'gum-runtime', self.directory / 'profile.json')
        self.assertFalse(report['runtime_tested'])
        self.assertFalse(report['sdk_consumption_verified'])
        path = self.source / 'bindings/gumjs/meson.build'
        path.write_bytes(path.read_bytes() + b'\n# drift\n')
        with self.assertRaisesRegex(ValueError, 'source drift'):
            profiles.apply(self.source, '16.7.19', 'gum-runtime', self.directory / 'failed.json')
        self.assertFalse((self.directory / 'failed.json').exists())
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            profiles.prepare(self.source, '17.25.2', 'gum-runtime')

    def test_meson_tracks_every_bridge_file_and_default_option_is_empty(self):
        text = self.expected[self.source / 'bindings/gumjs/meson.build'].decode()
        for relative in self.recipe['bridge_result_hashes']:
            self.assertIn("nianchu_bridge_source / '" + relative + "'", text)
        self.assertIn("gumjs_runtime_sources += files(", text)
        self.assertIn("gumjs_runtime_outputs += 'nianchu-java-bridge-report.json'", text)
        self.assertIn('    host_machine.endian(),\n    nianchu_bridge_source,', text)
        options = self.expected[self.source / 'meson.options'].decode()
        self.assertIn("option('nianchu_java_bridge_source',\n  type: 'string',\n  value: '',", options)
        ast.parse(self.runtime_source.decode())

    def test_default_runtime_uses_unmodified_cache_without_report(self):
        self.cache(self.priv)
        self.generate({'qjs', 'v8'})
        self.assertFalse(self.experimental_priv.exists())
        self.assertFalse((self.output / 'nianchu-java-bridge-report.json').exists())
        self.assertTrue((self.output / 'gumquickscript-java.h').is_file())
        self.assertTrue((self.output / 'gumv8script-java.h').is_file())
        self.assertTrue(all(cwd == self.priv for _, cwd in self.calls))

    def test_experiment_is_staged_before_both_compilers_and_repeat_isolated(self):
        default_package = self.cache(self.priv)
        self.cache(self.experimental_priv)
        before = {p.relative_to(default_package): p.read_bytes() for p in default_package.rglob('*') if p.is_file()}
        source_before = {p.relative_to(self.package): p.read_bytes() for p in self.package.rglob('*') if p.is_file()}
        self.generate({'qjs', 'v8'}, self.package)
        report = json.loads((self.output / 'nianchu-java-bridge-report.json').read_text(encoding='utf-8'))
        self.assertTrue(report['runtime_generated'])
        self.assertFalse(report['frida_binary_built'])
        self.assertFalse(report['final_binary_consumption_verified'])
        self.assertFalse(report['runtime_tested'])
        self.assertEqual(report['bridge_files'], self.recipe['bridge_result_hashes'])
        self.assertEqual(len(report['generated_files']), 5)
        for relative in ('gumquickscript-java.h', 'gumv8script-java.h'):
            self.assertEqual(report['generated_files'][relative], hashlib.sha256((self.output / relative).read_bytes()).hexdigest())
        self.assertTrue(all(cwd == self.experimental_priv for _, cwd in self.calls))
        self.generate({'qjs', 'v8'}, self.package)
        self.assertEqual(before, {p.relative_to(default_package): p.read_bytes() for p in default_package.rglob('*') if p.is_file()})
        self.assertEqual(source_before, {p.relative_to(self.package): p.read_bytes() for p in self.package.rglob('*') if p.is_file()})
        print('PASS runtime source integration model: QJS/V8 compiler calls stubbed; no real bundle or Android claim')

    def test_input_drift_and_cache_drift_fail_before_compiler_calls(self):
        source = self.package / 'lib/android.js'
        source.write_bytes(source.read_bytes() + b'\n// drift\n')
        with self.assertRaisesRegex(ValueError, 'package identity mismatch'):
            self.generate({'qjs'}, self.package)
        self.assertEqual(self.calls, [])
        source.write_bytes(bridge.recipes.transform((ROOT / 'tests/fixtures/java-bridge/6.3.9/lib/android.js').read_bytes(),
                                                  json.loads((ROOT / 'patches/java-bridge/6.3.9/spec.json').read_text())['files'][0]['edits']))
        package = self.cache(self.experimental_priv)
        path = package / 'lib/class-factory.js'
        path.write_bytes(path.read_bytes() + b'\n// cache drift\n')
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'cache drift'):
            self.generate({'qjs'}, self.package)
        self.assertEqual(self.calls, [])
        self.assertEqual(path.read_bytes(), before)

    def test_relative_nested_and_empty_backend_inputs_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'absolute'):
            self.generate({'qjs'}, Path('relative-package'))
        with self.assertRaisesRegex(ValueError, 'separate'):
            self.generate({'qjs'}, self.output / 'bridge')
        with self.assertRaisesRegex(ValueError, 'backend'):
            self.generate(set(), self.package)
        with self.assertRaisesRegex(ValueError, 'separate'):
            self.generate({'qjs'}, self.experimental_priv / 'bridge')
        self.assertEqual(self.calls, [])

    def test_missing_compiler_cache_install_and_partial_write_are_fail_closed(self):
        original = self.fake_run
        def install(args, **kwargs):
            cwd = Path(kwargs['cwd'])
            if Path(args[0]).name == 'npm-model':
                self.calls.append((list(args), cwd))
                self.assertEqual(cwd, self.experimental_priv)
                if 'install' in args and '-E' in args:
                    self.cache(cwd)
                return subprocess.CompletedProcess(args, 0)
            return original(args, **kwargs)

        self.fake_run = install
        try:
            self.generate({'qjs'}, self.package)
        finally:
            self.fake_run = original
        self.assertTrue((self.output / 'nianchu-java-bridge-report.json').is_file())
        shutil.rmtree(self.experimental_priv)
        destination = self.cache(self.experimental_priv)
        before = {p.relative_to(destination): p.read_bytes() for p in destination.rglob('*') if p.is_file()}
        self.calls = []
        replace = self.namespace['os'].replace
        def fail_second(source, target):
            if Path(target).name == 'class-factory.js':
                raise OSError('simulated staged-write failure')
            return replace(source, target)
        with patch.object(self.namespace['os'], 'replace', side_effect=fail_second):
            with self.assertRaisesRegex(OSError, 'staged-write failure'):
                self.generate({'qjs'}, self.package)
        self.assertEqual(self.calls, [])
        self.assertFalse(any(destination.rglob('*.nianchu-tmp')))
        self.assertNotEqual(before, {p.relative_to(destination): p.read_bytes() for p in destination.rglob('*') if p.is_file()})
        with self.assertRaisesRegex(ValueError, 'cache drift or partial'):
            self.generate({'qjs'}, self.package)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
