#!/usr/bin/env python3
import importlib.util
import itertools
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

    def source(self, version, name=None):
        source = self.directory / version / name if name else self.directory / version
        shutil.copytree(ROOT / 'tests/fixtures' / version, source)
        return source

    def test_default_and_repeat_for_both_versions(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            first = patches.apply(source, version, self.directory / (version + '.json'))
            recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            expected = {item['path'] for item in recipe['files'] if item['edits']}
            self.assertEqual({item['path'] for item in first['files'] if item['status'] == 'applied'}, expected)
            paths = {
                'subprojects/frida-core/server/server.vala',
                'subprojects/frida-core/src/linux/linux-host-session.vala',
                'subprojects/frida-core/lib/gadget/gadget-glue.c',
                'subprojects/frida-gum/bindings/gumjs/gumscriptscheduler.c',
                'subprojects/frida-core/src/linux/frida-helper-process.vala',
                'subprojects/frida-core/src/linux/frida-helper-backend.vala',
                'subprojects/frida-gum/gum/gum.c',
                'subprojects/frida-core/src/frida-glue.c',
                'subprojects/frida-core/lib/gadget/gadget.vala',
                'subprojects/frida-core/lib/gadget/meson.build',
                'subprojects/frida-core/lib/gadget/gadget-darwin.m',
                'subprojects/frida-core/meson.build',
                'subprojects/frida-core/compat/build.py',
                'subprojects/frida-core/lib/payload/portal-client.vala',
                'subprojects/frida-core/src/droidy/injector.vala',
                'subprojects/frida-core/src/fruity/injector.vala',
            }
            if version.startswith('17.'):
                paths.update({'subprojects/frida-core/src/linux/helpers/zymbiote.c',
                              'subprojects/frida-core/src/linux/mapped-agent.vala'})
            self.assertEqual(expected, paths)
            second = patches.apply(source, version, self.directory / (version + '.json'))
            self.assertNotIn('applied', [item['status'] for item in second['files']])
            linux = (source / 'subprojects/frida-core/src/linux/linux-host-session.vala').read_text(encoding='utf-8')
            self.assertIn('frida_agent_main', linux)
            self.assertEqual(linux.count('"nianchu-agent-arm.so"'), 2)
            self.assertEqual(linux.count('"nianchu-agent-arm64.so"'), 2)

    def test_helper_names_keep_memfd_and_file_creation_paths(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'helper.json')
            text = (source / 'subprojects/frida-core/src/linux/frida-helper-process.vala').read_text(encoding='utf-8')
            self.assertIn('make_temporary_helper ("nianchu-helper-32", blob32.data)', text)
            self.assertIn('make_temporary_helper ("nianchu-helper-64", blob64.data)', text)
            self.assertNotIn('"frida-helper-32"', text)
            self.assertNotIn('"frida-helper-64"', text)
            self.assertIn('new MemoryHelperFile (name, new Bytes.static (data))', text)
            self.assertIn('TemporaryFile.from_stream (name,', text)
            self.assertIn('MemoryFileDescriptor.from_bytes (name, bytes)', text)
            self.assertIn('string socket_path = "/nianchu-" + Uuid.string_random ();', text)
            self.assertIn('string socket_address = "unix:abstract=" + socket_path;', text)
            self.assertIn('helper_file.path, socket_address', text)
            address = 'socket_path, -1, ABSTRACT' if version.startswith('16.') else 'socket_path.to_utf8 (), ABSTRACT'
            self.assertIn('new UnixSocketAddress.with_type (' + address + ')', text)

    def test_fallback_name_keeps_loader_layout_and_connection(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'fallback.json')
            text = (source / 'subprojects/frida-core/src/linux/frida-helper-backend.vala').read_text(encoding='utf-8')
            self.assertIn('return "/nianchu-" + Uuid.string_random ();', text)
            self.assertNotIn('return "/frida-"', text)
            self.assertEqual(text.count('string fallback_address = make_fallback_address ();'), 2)
            self.assertIn('data_size += fallback_address.data.length + 1;', text)
            self.assertIn('write_memory_string (loader_base + loader_layout.fallback_address_offset, fallback_address)', text)
            self.assertIn('write_memory (loader_base + loader_layout.fallback_address_offset, fallback_address.data)', text)
            self.assertIn('fallback_address_offset', text)
            address = 'fallback_address, -1,' if version.startswith('16.') else 'fallback_address.to_utf8 (),'
            self.assertIn('new UnixSocketAddress.with_type (' + address, text)
            self.assertIn('socket.bind (server_address, true)', text)
            self.assertIn('frida_ctrl.send_fd (spec.library_so.get_fd (), cancellable)', text)

    def test_android_17_dex_name_preserves_start_and_cleanup(self):
        source = self.source('17.25.2')
        patches.apply(source, '17.25.2', self.directory / 'dex.json')
        text = (source / 'subprojects/frida-core/src/linux/linux-host-session.vala').read_text(encoding='utf-8')
        self.assertIn('"/data/local/tmp/nianchu-helper-" + instance_id + ".dex"', text)
        self.assertNotIn('"/data/local/tmp/frida-helper-"', text)
        self.assertIn('FileUtils.set_data (helper_path,', text)
        self.assertIn('Posix.chmod (helper_path, 0644)', text)
        self.assertIn('yield service.start (helper_path, cancellable)', text)
        self.assertIn('finally {\n\t\t\t\t\tPosix.unlink (helper_path);', text)

    def test_embedded_prgname_only_changes_existing_assignment(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'prgname.json')
            relative = 'subprojects/frida-gum/gum/gum.c'
            base = (ROOT / 'tests/fixtures' / version / relative).read_text(encoding='utf-8')
            text = (source / relative).read_text(encoding='utf-8')
            self.assertEqual(text, base.replace('g_set_prgname ("frida");', 'g_set_prgname ("nianchu");'))
            self.assertEqual(text.count('g_set_prgname ('), 1)

    def test_main_loop_label_only_changes_existing_thread_creation(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'main-loop.json')
            relative = 'subprojects/frida-core/src/frida-glue.c'
            base = (ROOT / 'tests/fixtures' / version / relative).read_bytes()
            actual = (source / relative).read_bytes()
            self.assertEqual(actual, base.replace(b'g_thread_new ("frida-main-loop",', b'g_thread_new ("nianchu-main",'))
            self.assertIn(b'g_thread_join (main_thread);', actual)
            self.assertEqual(actual.count(b'g_set_prgname'), base.count(b'g_set_prgname'))

    def test_zymbiote_socket_template_and_host_remain_in_sync(self):
        source = self.source('17.25.2')
        patches.apply(source, '17.25.2', self.directory / 'zymbiote.json')
        host = (source / 'subprojects/frida-core/src/linux/linux-host-session.vala').read_text(encoding='utf-8')
        payload = (source / 'subprojects/frida-core/src/linux/helpers/zymbiote.c').read_text(encoding='utf-8')
        template = '/nianchu-zymbiote-' + '0' * 32
        self.assertIn('string name = "/nianchu-zymbiote-" + Uuid.string_random ().replace ("-", "");', host)
        self.assertIn('memmem (payload_template, "' + template + '".data)', host)
        self.assertIn('.socket_path = "' + template + '",', payload)
        self.assertLess(len(template.encode()) + 1, 64)
        self.assertIn('char socket_path[64];', payload)
        self.assertIn('payload.write_string (cursor, server_name);\n\t\t\tcursor += 64;', host)
        self.assertNotIn('/frida-zymbiote-', host + payload)
        self.assertIn('addr.sun_path[1u + i] = zymbiote.socket_path[i];', payload)

    def test_mapper_label_keeps_blob_and_entrypoint_resolution(self):
        source = self.source('17.25.2')
        patches.apply(source, '17.25.2', self.directory / 'mapper.json')
        relative = 'subprojects/frida-core/src/linux/mapped-agent.vala'
        base = (ROOT / 'tests/fixtures/17.25.2' / relative).read_text(encoding='utf-8')
        text = (source / relative).read_text(encoding='utf-8')
        self.assertEqual(text, base.replace('Gum.Mapper.new_take_blob ("frida-agent.so",',
                                           'Gum.Mapper.new_take_blob ("nianchu-agent.so",'))
        self.assertIn('Gum.Address entrypoint_address = mapper.resolve (entrypoint);', text)

    def test_helper_drift_prevents_any_source_changes(self):
        source = self.source('16.7.19')
        path = source / 'subprojects/frida-core/src/linux/frida-helper-backend.vala'
        path.write_bytes(path.read_bytes() + b'\n// unexpected drift\n')
        before = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
        with self.assertRaisesRegex(ValueError, 'source drift'):
            patches.apply(source, '16.7.19', self.directory / 'drift.json')
        self.assertEqual(before, {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()})

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

    def test_agent_entrypoint_definition_exports_and_consumers_match(self):
        manifest = json.loads((ROOT / 'patches/entrypoint-files.json').read_text(encoding='utf-8'))
        for version in patches.VERSIONS:
            source = self.source(version)
            feature = 'agent-entrypoint-rename'
            result = patches.apply(source, version, self.directory / 'entry.json', [feature])
            recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            expected = {'subprojects/frida-core/' + path for path in manifest[version]}
            self.assertEqual(len(expected), 24 if version.startswith('16.') else 26)
            self.assertEqual({item['path'] for item in recipe['files'] if feature in item['optional']}, expected)
            for relative, sha in manifest[version].items():
                path = 'subprojects/frida-core/' + relative
                base = (ROOT / 'tests/fixtures' / version / path).read_bytes()
                self.assertEqual(patches.digest(base), sha)
                entry = next(item for item in recipe['files'] if item['path'] == path)
                compatible = patches.transform(base, entry['edits'])
                actual = (source / path).read_bytes()
                text = actual.decode('utf-8')
                if relative == 'lib/agent/agent.vala':
                    self.assertEqual(actual, compatible.replace(b'\tpublic void main (string agent_parameters,',
                        b'\t[CCode (cname = "nianchu_agent_main")]\n\tpublic void main (string agent_parameters,'))
                    self.assertEqual(text.count('[CCode (cname = "nianchu_agent_main")]'), 1)
                else:
                    self.assertGreater(compatible.count(b'frida_agent_main'), 0)
                    self.assertEqual(actual, compatible.replace(b'frida_agent_main', b'nianchu_agent_main'))
                self.assertNotIn('frida_agent_main', text)
            core = source / 'subprojects/frida-core'
            glue = (core / 'lib/agent/agent-glue.c').read_text(encoding='utf-8')
            self.assertIn('JNI_OnLoad (JavaVM * vm, void * reserved)', glue)
            self.assertIn('nianchu_agent_main (state->agent_parameters, &state->unload_policy, state->injector_state);', glue)
            exports = (core / 'lib/agent/frida-agent-android.version').read_text(encoding='utf-8')
            self.assertIn('    nianchu_agent_main;\n    JNI_OnLoad;', exports)
            meson = (core / 'lib/agent/meson.build').read_text(encoding='utf-8')
            self.assertIn('-Wl,-exported_symbol,_nianchu_agent_main', meson)
            self.assertIn("vala_header: 'frida-agent.h'", meson)
            container = (core / 'src/agent-container.vala').read_text(encoding='utf-8')
            self.assertIn('container.module.symbol ("nianchu_agent_main", out main_func_symbol)', container)
            self.assertEqual(patches.prepare(source, version, [feature])[0], [])
            self.assertIn(feature, result['features'])
            with self.assertRaisesRegex(ValueError, 'source drift'):
                patches.prepare(source, version)

    def test_all_feature_combinations_repeat_increment_and_reverse_order(self):
        for version in patches.VERSIONS:
            recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            features = recipe['features']
            for size in range(len(features) + 1):
                for index, selected in enumerate(itertools.combinations(features, size)):
                    with self.subTest(version=version, features=selected):
                        direct = self.source(version, 'direct-' + str(size) + '-' + str(index))
                        incremental = self.source(version, 'incremental-' + str(size) + '-' + str(index))
                        patches.apply(direct, version, self.directory / 'direct.json', selected)
                        patches.apply(incremental, version, self.directory / 'compatible.json')
                        patches.apply(incremental, version, self.directory / 'incremental.json', list(reversed(selected)))
                        self.assertEqual({p.relative_to(direct): p.read_bytes() for p in direct.rglob('*') if p.is_file()},
                                         {p.relative_to(incremental): p.read_bytes() for p in incremental.rglob('*') if p.is_file()})
                        repeated = patches.apply(direct, version, self.directory / 'repeat.json', selected)
                        self.assertNotIn('applied', [item['status'] for item in repeated['files']])
                        self.assertEqual(patches.prepare(incremental, version, selected)[0], [])
                        shutil.rmtree(direct)
                        shutil.rmtree(incremental)

    def test_every_entrypoint_file_is_required_before_any_write(self):
        manifest = json.loads((ROOT / 'patches/entrypoint-files.json').read_text(encoding='utf-8'))
        for version in patches.VERSIONS:
            source = self.source(version)
            for relative in manifest[version]:
                with self.subTest(version=version, path=relative):
                    path = source / 'subprojects/frida-core' / relative
                    original = path.read_bytes()
                    path.unlink()
                    before = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
                    try:
                        with self.assertRaisesRegex(ValueError, 'required regular source file missing'):
                            patches.apply(source, version, self.directory / 'missing-entry.json', ['agent-entrypoint-rename'])
                        self.assertEqual(before, {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()})
                    finally:
                        path.write_bytes(original)

    def test_entrypoint_drift_and_duplicate_feature_fail_before_writes(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            feature = 'agent-entrypoint-rename'
            with self.assertRaisesRegex(ValueError, 'duplicate features'):
                patches.prepare(source, version, [feature, feature])
            path = source / 'subprojects/frida-core/lib/agent/frida-agent-android.version'
            path.write_bytes(path.read_bytes().replace(b'frida_agent_main', b'unexpected_agent_main'))
            before = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
            with self.assertRaisesRegex(ValueError, 'source drift'):
                patches.apply(source, version, self.directory / 'entry-drift.json', [feature])
            self.assertEqual(before, {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()})

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
            recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            for feature in (None, *recipe['features']):
                path = ROOT / 'patches' / version / ((feature or 'compatible') + '.patch')
                self.assertEqual(path.read_bytes(), patches.export_diff(version, feature).encode('utf-8'))

    def test_unified_patch_replay_no_fuzz(self):
        tool = shutil.which('patch')
        if not tool:
            self.skipTest('patch tool unavailable')
        for version in patches.VERSIONS:
            recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            features = recipe['features']
            for size in range(len(features) + 1):
                for index, selected in enumerate(itertools.combinations(features, size)):
                    orders = [selected]
                    if len(selected) > 1:
                        orders.append(tuple(reversed(selected)))
                    for order_index, order in enumerate(orders):
                        with self.subTest(version=version, features=order):
                            source = self.source(version, 'replay-' + str(size) + '-' + str(index) + '-' + str(order_index))
                            for feature in (None, *order):
                                patch = ROOT / 'patches' / version / ((feature or 'compatible') + '.patch')
                                result = subprocess.run([tool, '--binary', '-p1', '--fuzz=0', '--batch', '--input', str(patch)],
                                                        cwd=source, capture_output=True, text=True)
                                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                                self.assertNotIn('offset', result.stdout.lower())
                                self.assertNotIn('fuzz', result.stdout.lower())
                            self.assertEqual(patches.prepare(source, version, selected)[0], [])
                            shutil.rmtree(source)


if __name__ == '__main__':
    unittest.main()
