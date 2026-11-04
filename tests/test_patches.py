#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('patches', ROOT / 'scripts/apply_patches.py')
patches = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patches)


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def source(self, version):
        source = self.directory / version
        shutil.copytree(ROOT / 'tests/fixtures' / version, source)
        return source

    def test_default_and_repeat_for_both_versions(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            first = patches.apply(source, version, self.directory / (version + '.json'))
            self.assertEqual(sum(item['status'] == 'applied' for item in first['files']), 4)
            second = patches.apply(source, version, self.directory / (version + '.json'))
            self.assertNotIn('applied', [item['status'] for item in second['files']])
            linux = (source / 'subprojects/frida-core/src/linux/linux-host-session.vala').read_text(encoding='utf-8')
            self.assertIn('frida_agent_main', linux)
            self.assertEqual(linux.count('"nianchu-agent-arm.so"'), 2)
            self.assertEqual(linux.count('"nianchu-agent-arm64.so"'), 2)

    def test_missing_file_never_partially_applies(self):
        source = self.source('16.7.19')
        first = source / 'subprojects/frida-core/server/server.vala'
        before = first.read_bytes()
        (source / 'subprojects/frida-gum/bindings/gumjs/generate-runtime.py').unlink()
        with self.assertRaises(ValueError):
            patches.prepare(source, '16.7.19')
        self.assertEqual(first.read_bytes(), before)

    def test_drift_and_partial_edits_fail(self):
        source = self.source('16.7.19')
        path = source / 'subprojects/frida-core/server/server.vala'
        path.write_bytes(path.read_bytes() + b'\n// unexpected drift\n')
        with self.assertRaisesRegex(ValueError, 'source drift'):
            patches.prepare(source, '16.7.19')

    def test_dry_run_changes_nothing(self):
        source = self.source('17.25.2')
        before = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
        patches.apply(source, '17.25.2', self.directory / 'dry.json', dry_run=True)
        after = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_optional_exit_has_no_dangling_windows_call(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'exit.json', ['exit-monitor-off'])
            text = (source / 'subprojects/frida-core/lib/payload/exit-monitor.vala').read_text(encoding='utf-8')
            start = text.index('\t\tconstruct {')
            end = text.index('\t\tpublic override void dispose', start)
            self.assertNotIn('listener);', text[start:end])
            self.assertNotIn('interceptor.attach', text[start:end])

    def test_optional_signal_keeps_handler_install_and_cleanup(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'signal.json', ['signal-interposition-off'])
            text = (source / 'subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c').read_text(encoding='utf-8')
            self.assertIn('gum_original_sigaction (sig, &action, old_handler)', text)
            self.assertIn('gum_original_sigaction (sig, old_handler, NULL)', text)
            self.assertNotIn('gum_interceptor_replace (interceptor, gum_original_signal,', text)

    def test_module_entry_and_android_constructor_are_explicit(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'module.json', ['zygisk-loader'])
            text = (source / 'subprojects/frida-core/lib/gadget/gadget-glue.c').read_text(encoding='utf-8')
            self.assertIn('nianchu_gadget_init (const gchar * config_data, int * result)', text)
            self.assertIn('frida_gadget_load (NULL, config_data, result);', text)
            start = text.index('frida_on_load (void)')
            end = text.index('__attribute__ ((destructor))', start)
            self.assertIn('#ifndef HAVE_ANDROID', text[start:end])
            self.assertIn('frida_gadget_unload ();', text[end:])
            exports = (source / 'subprojects/frida-core/lib/gadget/frida-gadget.version').read_text(encoding='utf-8')
            self.assertIn('global:\n    nianchu_gadget_init;', exports)

    def test_compatible_source_can_add_module_feature(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'compatible.json')
            result = patches.apply(source, version, self.directory / 'module.json', ['zygisk-loader'])
            self.assertEqual(sum(item['status'] == 'applied' for item in result['files']), 2)
            self.assertEqual(patches.prepare(source, version, ['zygisk-loader'])[0], [])
            with self.assertRaisesRegex(ValueError, 'source drift'):
                patches.prepare(source, version)

    def test_duplicate_feature_and_source_report_path_fail(self):
        source = self.source('16.7.19')
        before = (source / 'subprojects/frida-core/server/server.vala').read_bytes()
        with self.assertRaisesRegex(ValueError, 'duplicate features'):
            patches.prepare(source, '16.7.19', ['zygisk-loader', 'zygisk-loader'])
        with self.assertRaisesRegex(ValueError, 'outside source'):
            patches.apply(source, '16.7.19', source / 'subprojects/frida-core/server/server.vala')
        self.assertEqual((source / 'subprojects/frida-core/server/server.vala').read_bytes(), before)

    def test_unknown_art_option_is_rejected(self):
        source = self.source('16.7.19')
        with self.assertRaisesRegex(ValueError, 'unsupported features'):
            patches.prepare(source, '16.7.19', ['disable-all-art'])

    def test_exported_diffs_equal_recipes(self):
        for version in patches.VERSIONS:
            for feature in (None, 'exit-monitor-off', 'signal-interposition-off', 'zygisk-loader'):
                path = ROOT / 'patches' / version / ((feature or 'compatible') + '.patch')
                self.assertEqual(path.read_text(encoding='utf-8'), patches.export_diff(version, feature))

    def test_unified_patch_replay_no_fuzz(self):
        tool = shutil.which('patch')
        if not tool:
            self.skipTest('patch tool unavailable')
        for version in patches.VERSIONS:
            source = self.source(version)
            patch = ROOT / 'patches' / version / 'compatible.patch'
            result = subprocess.run([tool, '-p1', '--fuzz=0', '--batch', '--input', str(patch)],
                                    cwd=source, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            pending, _, _ = patches.prepare(source, version)
            self.assertEqual(pending, [])


if __name__ == '__main__':
    unittest.main()
