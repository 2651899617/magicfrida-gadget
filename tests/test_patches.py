#!/usr/bin/env python3
"""Pinned source profiles and patch replay, not Android/device execution."""
import base64
import importlib.util
import itertools
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('patches', ROOT / 'scripts/apply_patches.py')
patches = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patches)

DEFAULT_FEATURES = ['exit-monitor-off', 'signal-interposition-off',
                    'agent-entrypoint-rename', 'gadget-json-config']
FEATURES = ['exit-monitor-off', 'signal-interposition-off', 'zygisk-loader',
            'agent-entrypoint-rename', 'gadget-json-config']


def recipe_for(version):
    return json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))


def snapshot(source):
    return {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}


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
            recipe = recipe_for(version)
            self.assertEqual(recipe['features'], FEATURES)
            self.assertEqual(recipe['default_features'], DEFAULT_FEATURES)
            effective = patches.selected_features(recipe)
            self.assertEqual(effective, DEFAULT_FEATURES)
            self.assertEqual(first['features'], effective)
            expected = {
                item['path'] for item in recipe['files']
                if item['edits'] or any(item['optional'].get(feature) for feature in effective)
            }
            self.assertEqual({item['path'] for item in first['files'] if item['status'] == 'applied'}, expected)
            for entry in recipe['files']:
                base = (ROOT / 'tests/fixtures' / version / entry['path']).read_bytes()
                self.assertEqual((source / entry['path']).read_bytes(), patches.profile_bytes(base, entry, effective))
            self.assertEqual(patches.prepare(source, version)[0], [])
            second = patches.apply(source, version, self.directory / (version + '.json'))
            self.assertEqual(second['features'], effective)
            self.assertNotIn('applied', [item['status'] for item in second['files']])

    def test_selected_features_merges_mandatory_defaults_without_duplicates(self):
        for version in patches.VERSIONS:
            recipe = recipe_for(version)
            self.assertEqual(patches.selected_features(recipe), DEFAULT_FEATURES)
            self.assertEqual(patches.selected_features(recipe, list(reversed(DEFAULT_FEATURES))), DEFAULT_FEATURES)
            self.assertEqual(patches.selected_features(recipe, FEATURES), DEFAULT_FEATURES + ['zygisk-loader'])
            self.assertEqual(patches.selected_features(recipe, ['zygisk-loader', *DEFAULT_FEATURES]),
                             DEFAULT_FEATURES + ['zygisk-loader'])
            self.assertEqual(recipe['default_features'], DEFAULT_FEATURES)

    def test_default_preserves_random_server_directory_and_shared_agent_prefix(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'random-names.json')
            server = (source / 'subprojects/frida-core/server/server.vala').read_text(encoding='utf-8')
            self.assertIn('private static string DEFAULT_DIRECTORY;', server)
            self.assertIn('private static int main (string[] args) {\n\t\tDEFAULT_DIRECTORY = GLib.Uuid.string_random ();', server)
            self.assertEqual(server.count('DEFAULT_DIRECTORY = GLib.Uuid.string_random ();'), 1)
            self.assertIn('TemporaryDirectory.always_use ((directory != null) ? directory : DEFAULT_DIRECTORY);', server)
            self.assertNotIn('"re.frida.server"', server)
            self.assertNotIn('"nianchu.server"', server)
            linux = (source / 'subprojects/frida-core/src/linux/linux-host-session.vala').read_text(encoding='utf-8')
            self.assertIn('private string agent_prefix;', linux)
            self.assertEqual(linux.count('agent_prefix = GLib.Uuid.string_random ();'), 1)
            self.assertIn('agent_prefix = GLib.Uuid.string_random ();\n\t\t\tagent = new AgentDescriptor '
                          '(PathTemplate (agent_prefix + "-<arch>.so"),', linux)
            for arch in ('arm', 'arm64'):
                self.assertIn('new AgentResource (agent_prefix + "-' + arch + '.so",', linux)
                self.assertIn('name = agent_prefix + "-' + arch + '.so";', linux)
                self.assertEqual(linux.count('agent_prefix + "-' + arch + '.so"'), 2)
                self.assertNotIn('"frida-agent-' + arch + '.so"', linux)
                self.assertNotIn('"nianchu-agent-' + arch + '.so"', linux)
            self.assertIn('get_emulated_agent_path (uint pid) throws Error {\n\t\t\tstring name;', linux)
            self.assertIn('AgentResource? resource = agent.resources.first_match (r => r.name == name);', linux)
            self.assertIn('return resource.get_file ().path;', linux)
            self.assertIn('string entrypoint = "nianchu_agent_main";', linux)
            self.assertNotIn('frida_agent_main', linux)

    def test_full_reference_manifest_hashes_and_default_edits(self):
        manifest = json.loads((ROOT / 'patches/fullpatch-files.json').read_text(encoding='utf-8'))
        for version in patches.VERSIONS:
            recipe = recipe_for(version)
            entries = {entry['path']: entry for entry in recipe['files']}
            self.assertEqual(len(manifest[version]), 7 if version.startswith('16.') else 8)
            for relative, sha in manifest[version].items():
                with self.subTest(version=version, path=relative):
                    path = 'subprojects/frida-core/' + relative
                    base = (ROOT / 'tests/fixtures' / version / path).read_bytes()
                    entry = entries[path]
                    self.assertEqual(patches.digest(base), sha)
                    self.assertEqual(entry['upstream_sha256'], sha)
                    self.assertTrue(entry['edits'])
                    self.assertNotEqual(patches.profile_bytes(base, entry, patches.selected_features(recipe)), base)

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

    def test_main_loop_label_and_core_prgname_init(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'main-loop.json')
            relative = 'subprojects/frida-core/src/frida-glue.c'
            base = (ROOT / 'tests/fixtures' / version / relative).read_bytes()
            actual = (source / relative).read_bytes()
            expected = base.replace(b'g_thread_new ("frida-main-loop",', b'g_thread_new ("nianchu-main",')
            expected = expected.replace(b'\n    if (runtime == FRIDA_RUNTIME_OTHER)\n',
                                        b'\n    g_set_prgname ("nianchu");\n\n    if (runtime == FRIDA_RUNTIME_OTHER)\n')
            self.assertEqual(actual, expected)
            self.assertIn(b'g_thread_join (main_thread);', actual)
            self.assertEqual(actual.count(b'g_set_prgname'), base.count(b'g_set_prgname') + 1)
            self.assertLess(actual.index(b'g_set_prgname ("nianchu");'), actual.index(b'g_thread_new ("nianchu-main",'))

    def test_memfd_reference_label_keeps_creation_flags_and_writes(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'memfd.json')
            relative = ('src/linux/frida-helper-backend.vala' if version.startswith('16.') else 'lib/base/linux.vala')
            syscall = 'SysCall.memfd_create' if version.startswith('16.') else 'LinuxSyscall.MEMFD_CREATE'
            text = (source / 'subprojects/frida-core' / relative).read_text(encoding='utf-8')
            self.assertIn('return Linux.syscall (' + syscall + ', "nianchu-cache", flags);', text)
            self.assertNotIn('return Linux.syscall (' + syscall + ', name, flags);', text)
            self.assertIn('private int memfd_create (string name, uint flags)', text)
            self.assertIn('new FileDescriptor (memfd_create (name, 0))', text)
            self.assertIn('Posix.write (fd.handle,', text)

    def test_rpc_double_base64_keeps_wire_marker_and_consumers(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'rpc.json')
            text = (source / 'subprojects/frida-core/lib/base/rpc.vala').read_text(encoding='utf-8')
            match = re.search(r'GLib\.Base64\.decode \(\(string\) GLib\.Base64\.decode \("([A-Za-z0-9+/=]+)"\)\)', text)
            self.assertIsNotNone(match)
            self.assertEqual(base64.b64decode(base64.b64decode(match[1])), b'frida:rpc')
            self.assertIn('private string get_rpc_marker (bool quoted = false)', text)
            self.assertIn('return quoted ? "\\\"" + marker + "\\\"" : marker;', text)
            for consumer in ('.add_string_value (get_rpc_marker ())', 'json.index_of (get_rpc_marker (true))',
                             'type != get_rpc_marker ()'):
                self.assertIn(consumer, text)
            self.assertNotIn('frida:rpc', text)
            self.assertIn('yield peer.post_rpc_message (raw_request, data, cancellable);', text)
            self.assertIn('pending_responses.unset (request_id, out response)', text)

    def test_android_root_temp_directory_and_freebsd_fifo_consumers(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'temp-directory.json')
            relative = 'subprojects/frida-core/src/linux/system-linux.c'
            base = (ROOT / 'tests/fixtures' / version / relative).read_bytes()
            actual = (source / relative).read_bytes()
            self.assertEqual(actual, base.replace(b'return g_strdup ("/data/local/tmp");',
                                                  b'return g_strdup ("/system/lib64");'))
            self.assertIn(b'g_get_tmp_dir ()', actual)
            fifo = (source / 'subprojects/frida-core/src/freebsd/binjector-glue.c').read_text(encoding='utf-8')
            self.assertIn('g_strdup_printf ("%s/%p%u", self->temp_path, self, self->id)', fifo)
            self.assertNotIn('"%s/binjector-%u"', fifo)
            for consumer in ('mkfifo (self->fifo_path, mode);', 'chmod (self->fifo_path, mode);',
                             'open (self->fifo_path, O_RDONLY | O_NONBLOCK)', 'unlink (self->fifo_path);',
                             'strcpy (data->fifo_path, params->fifo_path);'):
                self.assertIn(consumer, fifo)

    def test_adb_unsolicited_commands_break_without_changing_other_protocol_paths(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'adb.json')
            relative = ('src/droidy/droidy-client.vala' if version.startswith('16.') else 'src/adb.vala')
            base = (ROOT / 'tests/fixtures' / version / 'subprojects/frida-core' / relative).read_text(encoding='utf-8')
            text = (source / 'subprojects/frida-core' / relative).read_text(encoding='utf-8')
            old = 'throw new Error.PROTOCOL ("Unexpected command");'
            new = 'break; /* Ignore unsolicited OPEN/CLSE/WRTE as in the reference patch. */'
            self.assertEqual(text, base.replace(old, new))
            self.assertIn('case "OPEN":\n\t\t\t\t\t\tcase "CLSE":\n\t\t\t\t\t\tcase "WRTE":\n\t\t\t\t\t\t\t' + new, text)
            self.assertNotIn(old, text)

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

    def test_default_exit_has_no_dangling_windows_call(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            result = patches.apply(source, version, self.directory / 'exit.json')
            self.assertIn('exit-monitor-off', result['features'])
            text = (source / 'subprojects/frida-core/lib/payload/exit-monitor.vala').read_text(encoding='utf-8')
            start = text.index('\t\tconstruct {')
            end = text.index('\t\tpublic override void dispose', start)
            self.assertNotIn('listener);', text[start:end])
            self.assertNotIn('interceptor.attach', text[start:end])
            self.assertIn('interceptor.detach (this);', text[end:])
            self.assertEqual(patches.prepare(source, version, ['exit-monitor-off'])[0], [])

    def test_default_signal_backend_is_not_attached_or_detached(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            result = patches.apply(source, version, self.directory / 'signal.json')
            self.assertIn('signal-interposition-off', result['features'])
            text = (source / 'subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c').read_text(encoding='utf-8')
            create = text[text.index('\ngum_exceptor_backend_new ('):text.index('\ngum_exceptor_backend_attach (')]
            dispose = text[text.index('\ngum_exceptor_backend_dispose ('):text.index('\ngum_exceptor_backend_new (')]
            self.assertNotIn('gum_exceptor_backend_attach (backend);', create)
            self.assertNotIn('gum_exceptor_backend_detach (self);', dispose)
            self.assertIn('backend->handler = handler;', create)
            self.assertIn('backend->handler_data = user_data;', create)
            self.assertIn('g_object_unref (self->interceptor);', dispose)
            self.assertIn('G_OBJECT_CLASS (gum_exceptor_backend_parent_class)->dispose (object);', dispose)
            for api in ('signal', 'sigaction'):
                self.assertNotIn('gum_interceptor_replace (interceptor, gum_original_' + api + ',', text)
                self.assertNotIn('gum_interceptor_revert (interceptor, gum_original_' + api + ');', text)
            # The dormant functions remain in source; their presence is not handler installation.
            self.assertIn('gum_original_sigaction (sig, &action, old_handler)', text)
            self.assertIn('gum_original_sigaction (sig, old_handler, NULL)', text)
            self.assertEqual(patches.prepare(source, version, ['signal-interposition-off'])[0], [])

    def test_default_process_attach_and_spawn_consumers_survive_signal_backend_changes(self):
        for version in patches.VERSIONS:
            source = self.source(version)
            patches.apply(source, version, self.directory / 'process-consumers.json')
            relative = 'subprojects/frida-core/src/linux/linux-host-session.vala'
            base = (ROOT / 'tests/fixtures' / version / relative).read_text(encoding='utf-8')
            text = (source / relative).read_text(encoding='utf-8')
            attach_start = 'protected override async Future<IOStream> perform_attach_to ('
            attach_end = '\n\t\tprotected override string? get_emulated_agent_path '
            spawn_start = 'public override async uint spawn ('
            spawn_end = '\n\t\tprotected override '

            def block(value, start, end):
                begin = value.index(start)
                return value[begin:value.index(end, begin)]

            attach = block(text, attach_start, attach_end)
            self.assertEqual(attach, block(base, attach_start, attach_end).replace('frida_agent_main', 'nianchu_agent_main'))
            self.assertEqual(block(text, spawn_start, spawn_end), block(base, spawn_start, spawn_end))
            for consumer in ('linjector.inject_library_resource (pid, agent, entrypoint,',
                             'linjector.inject_library_file_with_template (pid, PathTemplate (',
                             'linjector.request_control_channel (id, cancellable)', 'return stream_request.future;'):
                self.assertIn(consumer, attach)
            self.assertIn('return yield helper.spawn (program, options,', text)
            self.assertIn('return yield robo_launcher.spawn (program, options, cancellable);', text)
            self.assertNotIn('gum_exceptor_backend', attach)

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

    def test_default_agent_entrypoint_definition_exports_and_consumers_match(self):
        manifest = json.loads((ROOT / 'patches/entrypoint-files.json').read_text(encoding='utf-8'))
        for version in patches.VERSIONS:
            source = self.source(version)
            feature = 'agent-entrypoint-rename'
            result = patches.apply(source, version, self.directory / 'entry.json')
            recipe = recipe_for(version)
            expected = {'subprojects/frida-core/' + path for path in manifest[version]}
            self.assertEqual(len(expected), 24 if version.startswith('16.') else 26)
            self.assertEqual({item['path'] for item in recipe['files'] if feature in item['optional']}, expected)
            for relative, sha in manifest[version].items():
                path = 'subprojects/frida-core/' + relative
                base = (ROOT / 'tests/fixtures' / version / path).read_bytes()
                self.assertEqual(patches.digest(base), sha)
                entry = next(item for item in recipe['files'] if item['path'] == path)
                edits_only = patches.transform(base, entry['edits'])
                actual = (source / path).read_bytes()
                self.assertEqual(actual, patches.profile_bytes(base, entry, patches.selected_features(recipe)))
                text = actual.decode('utf-8')
                if relative == 'lib/agent/agent.vala':
                    self.assertEqual(actual, edits_only.replace(b'\tpublic void main (string agent_parameters,',
                        b'\t[CCode (cname = "nianchu_agent_main")]\n\tpublic void main (string agent_parameters,'))
                    self.assertEqual(text.count('[CCode (cname = "nianchu_agent_main")]'), 1)
                else:
                    self.assertGreater(edits_only.count(b'frida_agent_main'), 0)
                    self.assertEqual(actual, edits_only.replace(b'frida_agent_main', b'nianchu_agent_main'))
                self.assertNotIn('frida_agent_main', text)
                if relative.endswith('.def'):
                    self.assertIn(b'EXPORTS\r\n', base)
                    self.assertEqual(actual.count(b'\r\n'), base.count(b'\r\n'))
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
            self.assertEqual(patches.prepare(source, version)[0], [])
            self.assertEqual(patches.prepare(source, version, [feature])[0], [])
            self.assertIn(feature, result['features'])
            repeated = patches.apply(source, version, self.directory / 'explicit-entry.json', [feature])
            self.assertEqual(repeated['features'], result['features'])
            self.assertNotIn('applied', [item['status'] for item in repeated['files']])

    def test_all_feature_combinations_repeat_increment_and_reverse_order(self):
        # All explicit subsets exercise API idempotency; they yield only default and Zygisk profiles.
        for version in patches.VERSIONS:
            recipe = recipe_for(version)
            features = recipe['features']
            baseline = self.source(version, 'baseline')
            patches.apply(baseline, version, self.directory / 'baseline.json')
            profiles = {'default': snapshot(baseline)}
            for size in range(len(features) + 1):
                for index, selected in enumerate(itertools.combinations(features, size)):
                    with self.subTest(version=version, features=selected):
                        direct = self.source(version, 'direct-' + str(size) + '-' + str(index))
                        incremental = self.source(version, 'incremental-' + str(size) + '-' + str(index))
                        result = patches.apply(direct, version, self.directory / 'direct.json', selected)
                        patches.apply(incremental, version, self.directory / 'compatible.json')
                        reverse_result = patches.apply(incremental, version, self.directory / 'incremental.json', list(reversed(selected)))
                        actual = snapshot(direct)
                        self.assertEqual(actual, snapshot(incremental))
                        effective = patches.selected_features(recipe, selected)
                        self.assertEqual(result['features'], effective)
                        self.assertEqual(reverse_result['features'], effective)
                        self.assertEqual(len(effective), len(set(effective)))
                        profile = 'zygisk' if 'zygisk-loader' in selected else 'default'
                        if profile in profiles:
                            self.assertEqual(actual, profiles[profile])
                        else:
                            profiles[profile] = actual
                        repeated = patches.apply(direct, version, self.directory / 'repeat.json', selected)
                        self.assertNotIn('applied', [item['status'] for item in repeated['files']])
                        self.assertEqual(patches.prepare(incremental, version, selected)[0], [])
                        shutil.rmtree(direct)
                        shutil.rmtree(incremental)
            self.assertEqual(set(profiles), {'default', 'zygisk'})
            differences = {path for path in profiles['default'] if profiles['default'][path] != profiles['zygisk'][path]}
            self.assertEqual(differences, {Path('subprojects/frida-core/lib/gadget/gadget-glue.c'),
                                          Path('subprojects/frida-core/lib/gadget/frida-gadget.version')})

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
                            patches.apply(source, version, self.directory / 'missing-entry.json')
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
                patches.apply(source, version, self.directory / 'entry-drift.json')
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
            recipe = recipe_for(version)
            features = recipe['features']
            replayed_profiles = set()
            for size in range(len(features) + 1):
                for selected in itertools.combinations(features, size):
                    orders = [selected]
                    if len(selected) > 1:
                        orders.append(tuple(reversed(selected)))
                    for order in orders:
                        effective = patches.selected_features(recipe, order)
                        self.assertEqual(effective, patches.selected_features(recipe, selected))
                        self.assertEqual(effective[:len(DEFAULT_FEATURES)], DEFAULT_FEATURES)
                        self.assertEqual(len(effective), len(set(effective)))
                        # Replay each distinct effective profile once, not each spelling of its defaults.
                        key = tuple(effective)
                        if key in replayed_profiles:
                            continue
                        replayed_profiles.add(key)
                        with self.subTest(version=version, features=effective):
                            source = self.source(version, 'replay-' + str(len(replayed_profiles)))
                            for feature in (None, *effective):
                                patch = ROOT / 'patches' / version / ((feature or 'compatible') + '.patch')
                                result = subprocess.run([tool, '--binary', '-p1', '--fuzz=0', '--batch', '--input', str(patch)],
                                                        cwd=source, capture_output=True, text=True)
                                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                                self.assertNotIn('offset', result.stdout.lower())
                                self.assertNotIn('fuzz', result.stdout.lower())
                            for entry in recipe['files']:
                                base = (ROOT / 'tests/fixtures' / version / entry['path']).read_bytes()
                                self.assertEqual((source / entry['path']).read_bytes(),
                                                 patches.profile_bytes(base, entry, effective))
                            self.assertEqual(patches.prepare(source, version, order)[0], [])
                            shutil.rmtree(source)
            self.assertEqual(replayed_profiles, {tuple(DEFAULT_FEATURES), tuple(DEFAULT_FEATURES + ['zygisk-loader'])})


if __name__ == '__main__':
    unittest.main()
