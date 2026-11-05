#!/usr/bin/env python3
"""Pinned Gadget source contracts and restricted models, not Vala/Android tests."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import posixpath
import re
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('patches', ROOT / 'scripts/apply_patches.py')
patches = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patches)
CORE = 'subprojects/frida-core/'


def source(version, relative, features=()):
    recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
    entry = next(item for item in recipe['files'] if item['path'] == CORE + relative)
    base = (ROOT / 'tests/fixtures' / version / entry['path']).read_bytes()
    data = patches.transform(base, entry['edits'])
    for feature in features:
        data = patches.transform(data, entry['optional'].get(feature, []))
    return base.decode('utf-8'), data.decode('utf-8'), entry


def function(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def android_block(text):
    load = function(text, '\tprivate Config load_config (Location location)', '\tprivate Config parse_config ')
    return function(load, '#if ANDROID\n', '#endif').removeprefix('#if ANDROID\n')


def lookup_model(text):
    # Translate only the pinned fallback's small statement vocabulary; reject anything else.
    statements = []
    indent = 1
    for line in android_block(text).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('}'):
            indent -= 1
            line = line[1:].strip()
        if not line:
            continue
        if line == 'string json_path;':
            continue
        if line == "var ext_index = config_path.last_index_of_char ('.');":
            statement = "ext_index = config_path.rfind('.')"
        elif line in ('if (ext_index != -1) {', 'else if (ext_index != -1) {'):
            statement = ('elif' if line.startswith('else') else 'if') + ' ext_index != -1:'
        elif line == 'else {':
            statement = 'else:'
        elif re.fullmatch(r'if \(!?FileUtils.test \((config_path|json_path), FileTest.EXISTS\)\) \{', line):
            variable = re.search(r'\((config_path|json_path),', line)[1]
            statement = 'if ' + variable + (' not in existing:' if '!FileUtils' in line else ' in existing:')
        elif re.fullmatch(r'(config_path|json_path) = (config_path\[0:ext_index\] \+ "\.(json|config\.so)"|config_path \+ "\.(json|config\.so)"|json_path);', line):
            statement = line[:-1]
        else:
            raise ValueError('unsupported Gadget model statement: ' + line)
        statements.append('    ' * indent + statement)
        if line.endswith('{'):
            indent += 1
    if indent != 1:
        raise ValueError('unbalanced Gadget model block')
    code = 'def choose(config_path, existing):\n' + '\n'.join(statements) + '\n    return config_path\n'
    namespace = {}
    exec(compile(code, '<pinned Gadget fallback model>', 'exec'), namespace)
    return namespace['choose']


class GadgetTests(unittest.TestCase):
    def test_complete_gadget_manifest_and_original_hashes(self):
        manifest = json.loads((ROOT / 'patches/gadget-files.json').read_text(encoding='utf-8'))
        for version in patches.VERSIONS:
            self.assertEqual(len(manifest[version]), 8)
            for relative, sha in manifest[version].items():
                base, actual, entry = source(version, relative)
                self.assertEqual(hashlib.sha256(base.encode()).hexdigest(), sha)
                self.assertEqual(entry['upstream_sha256'], sha)
                self.assertNotEqual(base, actual)
            _, _, entry = source(version, 'lib/gadget/gadget.vala')
            self.assertEqual(set(entry['optional']), {'gadget-json-config'})

    def test_listener_labels_and_fruity_consumer_all_ports(self):
        for version in patches.VERSIONS:
            base, actual, _ = source(version, 'lib/gadget/gadget.vala')
            self.assertEqual(actual, base.replace('"frida-gadget-tcp-%u"', '"nianchu-t%u"')
                             .replace('"frida-gadget-unix"', '"nianchu-unix"'))
            label = re.search(r'Environment.set_thread_name \("([^"]+)"\.printf \(listen_port\)\)', actual)[1]
            old, fruity, _ = source(version, 'src/fruity/injector.vala')
            pattern = re.search(r'if \(/(.+)/\.match \(name, 0, out info\)\)', fruity)[1]
            self.assertEqual(fruity, old.replace(r'/^frida-gadget-tcp-(\d+)$/', r'/^(?:frida-gadget-tcp-|nianchu-t)(\d+)$/'))
            self.assertIn('string raw_port = info.fetch (1);', fruity)
            self.assertIn('uint64.from_string (raw_port, out port, radix, 1, uint16.MAX);', fruity)
            for port in range(1, 65536):
                name = label % port
                self.assertLessEqual(len(name.encode()), 15)
                self.assertEqual(re.fullmatch(pattern, name)[1], str(port))
                self.assertEqual(re.fullmatch(pattern, 'frida-gadget-tcp-' + str(port))[1], str(port))
            self.assertEqual(len((label % 65535).encode()), 14)
            self.assertLessEqual(len(b'nianchu-unix'), 15)
            for name in ('nianchu-t', 'nianchu-t12junk', 'prefix-nianchu-t12', 'nianchu-unix'):
                self.assertIsNone(re.fullmatch(pattern, name))

    def test_generated_header_build_chain_and_init_order(self):
        for version in patches.VERSIONS:
            base, meson, _ = source(version, 'lib/gadget/meson.build')
            expected = base.replace("shared_library('frida-gadget-raw',", "shared_library('nianchu-gadget-raw',")
            expected = expected.replace("vala_header: 'frida-gadget.h'", "vala_header: 'nianchu-gadget.h'")
            expected = expected.replace("custom_target('frida-gadget-modulated',", "custom_target('nianchu-gadget-modulated',")
            expected = expected.replace("output: 'libfrida-gadget-modulated'", "output: 'libnianchu-gadget-modulated'")
            self.assertEqual(meson, expected)
            for item in ("input: raw_gadget", "input: modulated_gadget", "custom_target('frida-gadget',",
                         "output: need_universal_gadget ? f'@gadget_name@-@host_abi@' : gadget_name",
                         "command: post_process + ['shared-library', identity]", "install: not need_universal_gadget",
                         "'frida_on_load', 'last'", "'frida_on_unload', 'last'"):
                self.assertIn(item, meson)
            init = 'frida_init_memory' if version.startswith('16.') else 'frida_libc_shim_init'
            deinit = 'frida_deinit_memory' if version.startswith('16.') else 'frida_libc_shim_deinit'
            self.assertIn("'constructor', '" + init + "', 'first'", meson)
            self.assertIn("'destructor', '" + deinit + "', 'first'", meson)
            for relative in ('lib/gadget/gadget-glue.c', 'lib/gadget/gadget-darwin.m'):
                old, text, _ = source(version, relative)
                expected = old.replace('#include "frida-gadget.h"', '#include "nianchu-gadget.h"')
                if relative.endswith('gadget-glue.c'):
                    expected = expected.replace('g_thread_new ("frida-gadget",', 'g_thread_new ("nianchu-gadget",')
                self.assertEqual(text, expected)
                self.assertNotIn('#include "frida-gadget.h"', text)
                if relative.endswith('gadget-glue.c'):
                    naming = function(text, 'frida_gadget_environment_set_thread_name (const gchar * name)', '\n}\n')
                    self.assertIn('only implemented on i/macOS', naming)
                    self.assertNotIn('pthread_setname', naming)
                    self.assertNotIn('prctl', naming)
                else:
                    self.assertIn('pthread_setname_np (name);', text)
            _, glue, _ = source(version, 'lib/gadget/gadget-glue.c', ['zygisk-loader', 'gadget-json-config'])
            self.assertIn('frida_gadget_load (NULL, config_data, result);', glue)
            self.assertIn('#ifndef HAVE_ANDROID', glue)

    def test_elf_output_and_compat_preserve_platform_layout(self):
        for version in patches.VERSIONS:
            base, top, _ = source(version, 'meson.build')
            expression = "((host_os_family in ['windows', 'darwin']) ? 'frida-gadget' : 'nianchu-gadget') + shlib_suffix"
            self.assertEqual(top, base.replace("'frida-gadget' + shlib_suffix", expression))
            match = re.search(r"gadget_name = \(\(host_os_family in (\[[^]]+\])\) \? '([^']+)' : '([^']+)'\) \+ shlib_suffix", top)
            platforms = ast.literal_eval(match[1])
            for family, suffix, expected in (('linux', '.so', 'nianchu-gadget.so'), ('qnx', '.so', 'nianchu-gadget.so'),
                                             ('windows', '.dll', 'frida-gadget.dll'), ('darwin', '.dylib', 'frida-gadget.dylib')):
                self.assertEqual((match[2] if family in platforms else match[3]) + suffix, expected)
            old, compat, _ = source(version, 'compat/build.py')
            self.assertEqual(compat, old.replace('GADGET_FILE_ELF = Path("lib") / "gadget" / "frida-gadget.so"',
                                                'GADGET_FILE_ELF = Path("lib") / "gadget" / "nianchu-gadget.so"'))
            self.assertIn('GADGET_TARGET = "frida-gadget"', compat)
            self.assertIn('GADGET_FILE_WINDOWS = Path("lib") / "gadget" / "frida-gadget.dll"', compat)
            self.assertIn('GADGET_FILE_DARWIN = Path("lib") / "gadget" / "frida-gadget.dylib"', compat)
            ast.parse(compat)

    def test_droidy_staging_and_portal_only_change_branding(self):
        for version in patches.VERSIONS:
            old, text, _ = source(version, 'src/droidy/injector.vala')
            self.assertEqual(old.count('"/data/local/tmp/frida-gadget-"'), 2)
            self.assertEqual(text, old.replace('"/data/local/tmp/frida-gadget-"', '"/data/local/tmp/nianchu-gadget-"'))
            for item in ('Uuid.string_random ().replace ("-", "")', '"/gadget.so"', '"/gadget.config"',
                         '"frida:" + package', '"unix:" + unix_socket_path',
                         '"cp %s %s".printf (so_path_shared, so_path_app)',
                         '"cp %s %s".printf (config_path_shared, config_path_app)',
                         '"rm -f %s; rm -f %s".printf (so_path_shared, config_path_shared)',
                         '} finally {\n\t\t\t\tshell.close.begin ();'):
                self.assertIn(item, text)
            self.assertIn(('Droidy.FileSync' if version.startswith('16.') else 'AdbFileSync') + '.send', text)
            old, portal, _ = source(version, 'lib/payload/portal-client.vala')
            self.assertEqual(portal, old.replace('Emulated realm is not supported by frida-gadget',
                                                'Emulated realm is not supported by nianchu-gadget'))
            self.assertIn('throw new Error.NOT_SUPPORTED (', portal)

    def test_json_feature_is_scoped_to_android_gadget_lookup(self):
        for version in patches.VERSIONS:
            _, compatible, entry = source(version, 'lib/gadget/gadget.vala')
            _, featured, _ = source(version, 'lib/gadget/gadget.vala', ['gadget-json-config'])
            edits = entry['optional']['gadget-json-config']
            self.assertEqual(len(edits), 1)
            self.assertEqual(android_block(compatible).strip(), edits[0]['old'].strip())
            self.assertEqual(android_block(featured).strip(), edits[0]['new'].strip())
            self.assertEqual(featured.replace(android_block(featured), android_block(compatible)), compatible)
            self.assertIn('config = (config_data != null)\n\t\t\t\t? parse_config (config_data)\n\t\t\t\t: load_config (location);', featured)
            self.assertIn('return Path.build_filename (dirname, stem + ".config");', featured)
            self.assertIn('derive_config_path_from_file_path (script_path)', featured)
            self.assertIn('config_path = Path.build_filename (resource_dir, "config.json");', featured)
            self.assertIn('if (gadget_path == null)\n\t\t\treturn new Config ();', featured)
            self.assertNotIn('FileUtils.set_', android_block(featured))

    def test_android_fallback_source_model_priority_and_missing(self):
        for version in patches.VERSIONS:
            _, default, _ = source(version, 'lib/gadget/gadget.vala')
            _, featured, _ = source(version, 'lib/gadget/gadget.vala', ['gadget-json-config'])
            choose_default, choose_json = lookup_model(default), lookup_model(featured)
            for path in ('/tmp/libnianchu-gadget.so', '/tmp/gadget', '/tmp/gadget.debug.so', '/tmp/.gadget'):
                filename = posixpath.basename(path)
                stem = filename[:filename.rfind('.')] if '.' in filename else filename
                prefix = posixpath.join(posixpath.dirname(path), stem)
                config, json_path, fallback = prefix + '.config', prefix + '.json', prefix + '.config.so'
                self.assertEqual(choose_json(config, {config, json_path, fallback}), config)
                self.assertEqual(choose_json(config, {json_path, fallback}), json_path)
                self.assertEqual(choose_json(config, {fallback}), fallback)
                self.assertEqual(choose_json(config, set()), fallback)
                self.assertEqual(choose_default(config, {json_path, fallback}), fallback)
                self.assertEqual(choose_default(config, {config, json_path, fallback}), config)
            self.assertEqual(choose_json('extensionless', {'extensionless.json'}), 'extensionless.json')
            self.assertEqual(choose_json('extensionless', set()), 'extensionless.config.so')
            self.assertEqual(choose_default('extensionless', set()), 'extensionless.config.so')
        print('PASS Gadget config source model: restricted fallback translation; no Vala/Android execution')

    def test_config_errors_and_inline_priority_source_model(self):
        for version in patches.VERSIONS:
            _, featured, _ = source(version, 'lib/gadget/gadget.vala', ['gadget-json-config'])
            load = function(featured, '\tprivate Config load_config (Location location)', '\tprivate Config parse_config ')
            self.assertIn('if (e is FileError.NOENT)\n\t\t\t\treturn new Config ();', load)
            self.assertIn('throw new Error.PERMISSION_DENIED ("%s", e.message);', load)
            self.assertIn('throw new Error.INVALID_ARGUMENT ("Invalid config: %s", e.message);', load)
            choose = lookup_model(featured)
            reads = []

            def model(files, inline=None):
                if inline is not None:
                    return json.loads(inline)
                selected = choose('/tmp/gadget.config', set(files))
                reads.append(selected)
                if selected not in files:
                    return {}
                value = files[selected]
                if isinstance(value, PermissionError):
                    raise value
                return json.loads(value)

            self.assertEqual(model({'/tmp/gadget.json': '{"interaction": {"type": "listen"}}'}),
                             {'interaction': {'type': 'listen'}})
            self.assertEqual(model({}), {})
            with self.assertRaises(json.JSONDecodeError):
                model({'/tmp/gadget.json': 'invalid', '/tmp/gadget.config.so': '{}'})
            with self.assertRaises(PermissionError):
                model({'/tmp/gadget.json': PermissionError(), '/tmp/gadget.config.so': '{}'})
            reads.clear()
            self.assertEqual(model({'/tmp/gadget.config': 'invalid'}, '{"interaction": {"type": "script"}}'),
                             {'interaction': {'type': 'script'}})
            self.assertEqual(reads, [])
            with self.assertRaises(json.JSONDecodeError):
                model({'/tmp/gadget.config': '{}'}, 'invalid-inline')
            self.assertEqual(reads, [])

    def test_missing_and_drifted_gadget_files_fail_before_writes(self):
        manifest = json.loads((ROOT / 'patches/gadget-files.json').read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for version in patches.VERSIONS:
                root = directory / version
                shutil.copytree(ROOT / 'tests/fixtures' / version, root)
                for relative in manifest[version]:
                    path = root / CORE / relative
                    original = path.read_bytes()
                    for missing in (False, True):
                        with self.subTest(version=version, path=relative, missing=missing):
                            if missing:
                                path.unlink()
                            else:
                                path.write_bytes(original + b'\n// drift\n')
                            before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                            with self.assertRaises(ValueError):
                                patches.apply(root, version, directory / 'failure.json', ['gadget-json-config'])
                            self.assertEqual(before, {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()})
                            path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
