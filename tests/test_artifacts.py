#!/usr/bin/env python3
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('collector', ROOT / 'scripts/collect_artifacts.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
spec = importlib.util.spec_from_file_location('patches', ROOT / 'scripts/apply_patches.py')
patches = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patches)
TARGETS = {'server': 'frida-server', 'gadget': 'frida-gadget'}
FINAL_FILENAMES = {'server': 'server', 'gadget': 'nianchu-gadget.so'}


def fixture(version='16.7.19'):
    strings = b'\0.shstrtab\0.rodata\0'
    # Keep this synthetic ELF only in temporary tests; never a release artifact.
    tokens = b're.frida\0re/frida\0frida:rpc\0frida_agent_main\0' + version.encode() + b'\0'
    phoff, shoff, offset = 64, 128, 320
    data = bytearray(offset + len(strings) + len(tokens))
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, b'\x7fELF\x02\x01\x01' + b'\0' * 9,
                     3, 183, 1, 0, phoff, shoff, 0, 64, 56, 1, 64, 3, 1)
    struct.pack_into('<IIQQQQQQ', data, phoff, 1, 5, 0, 0, 0, len(data), len(data), 0x1000)
    struct.pack_into('<IIQQQQIIQQ', data, shoff + 64, 1, 3, 0, 0, offset, len(strings), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, shoff + 128, 11, 1, 2, offset + len(strings),
                     offset + len(strings), len(tokens), 0, 0, 1, 0)
    data[offset:offset + len(strings)] = strings
    data[offset + len(strings):] = tokens
    return bytes(data)


def write_json(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def collection_fixture(self, name='case', version='16.7.19', features=()):
        root = self.directory / name
        build = root / 'build'
        (build / 'meson-info').mkdir(parents=True)
        items = []
        for kind, target in TARGETS.items():
            filename = FINAL_FILENAMES[kind]
            (build / filename).write_bytes(fixture(version))
            items.append({'name': target, 'type': 'custom', 'installed': True, 'filename': [filename]})
        intro = build / 'meson-info/intro-targets.json'
        write_json(intro, items)
        expected = next(item for item in json.loads((ROOT / 'versions.json').read_text(encoding='utf-8'))['versions']
                        if item['version'] == version)
        # Mock the complete schema actually emitted by verify_source.verify().
        # Its run().strip() removes only the first healthy status line's leading space.
        lines = [' ' + sha + ' ' + path + ' (mock-pinned)' for path, sha in expected['submodules'].items()]
        lines[0] = lines[0].lstrip()
        source = {'schema': 1, 'version': version, 'commit': expected['commit'],
                  'submodules': copy.deepcopy(expected['submodules']), 'ndk_revision': expected['ndk_revision'],
                  'python': '3.13.0', 'node': 'v22.0.0', 'npm': '10.0.0', 'git': 'git version 2.47.0',
                  'submodule_status': lines, 'runtime_tested': False}
        source_path = root / 'source-report.json'
        write_json(source_path, source)
        fixture_source = root / 'fixture-source'
        shutil.copytree(ROOT / 'tests/fixtures' / version, fixture_source)
        patch_path = root / 'patch-report.json'
        patch_report = patches.apply(fixture_source, version, patch_path, features)
        return SimpleNamespace(root=root, build=build, intro=intro, items=items, expected=expected, source=source,
                               source_path=source_path, fixture_source=fixture_source, patch_path=patch_path,
                               patches=patch_report, version=version)

    def collect(self, context, output='out'):
        return collector.collect(context.build, context.version, context.root / output,
                                 context.source_path, context.patch_path)

    def assert_rejected(self, context, message=None):
        assertion = self.assertRaisesRegex(ValueError, message) if message else self.assertRaises(ValueError)
        with assertion:
            self.collect(context)
        self.assertFalse((context.root / 'out').exists())

    def test_read_only_audit_and_markers(self):
        data = fixture()
        before = data[:]
        result = collector.elf.audit(data)
        self.assertEqual(data, before)
        self.assertFalse(result['binary_modified'])
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['protected_markers'], {marker.decode(): 1 for marker in collector.elf.PROTECTED})

    def test_malformed_elf_fails(self):
        for data in (b'', b'\x7fELF', fixture()[:200], b'not ELF' * 20):
            with self.assertRaises(ValueError):
                collector.elf.audit(data)
        data = bytearray(fixture())
        struct.pack_into('<Q', data, 40, 0xffffffffffffffff)
        with self.assertRaises(ValueError):
            collector.elf.audit(data)

    def test_bad_symbol_link_fails(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 128 + 128 + 4, 11)
        struct.pack_into('<Q', data, 128 + 128 + 56, 24)
        with self.assertRaises(ValueError):
            collector.elf.audit(data)

    def test_both_targets_required(self):
        with self.assertRaises(ValueError):
            collector.final_outputs([], TARGETS)
        item = {'name': 'frida-gadget', 'type': 'custom', 'installed': True, 'filename': ['gadget.so']}
        with self.assertRaises(ValueError):
            collector.final_outputs([item], TARGETS)
        for targets in ({}, {'gadget': 'frida-gadget'}, {'server': 'same', 'gadget': 'same'},
                        {**TARGETS, 'raw': 'raw'}, {'server': None, 'gadget': 'frida-gadget'}):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                collector.final_outputs([item], targets)

    def test_raw_or_duplicate_targets_fail(self):
        context = self.collection_fixture()
        for updates in ({'type': 'shared library'}, {'installed': False}, {'installed': 1},
                        {'filename': []}, {'filename': ['raw.so', 'extra.so']}, {'filename': 'raw.so'},
                        {'filename': [None]}, {'filename': ['']}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                items = copy.deepcopy(context.items)
                items[0].update(updates)
                collector.final_outputs(items, TARGETS)
        with self.assertRaises(ValueError):
            collector.final_outputs(context.items + [context.items[0]], TARGETS)
        for items in (None, {}, [None]):
            with self.subTest(items=items), self.assertRaises(ValueError):
                collector.final_outputs(items, TARGETS)

    def test_collection_provenance_and_byte_identity(self):
        for version in patches.VERSIONS:
            with self.subTest(version=version):
                context = self.collection_fixture(version, version)
                report = self.collect(context)
                self.assertEqual(set(report['artifacts']), {'server', 'gadget'})
                self.assertEqual(report['source'], context.source)
                self.assertEqual(report['patches'], context.patches)
                self.assertFalse(report['binary_modified'])
                self.assertEqual(report['validation'], {'build_outputs': 'verified', 'protocol_handshake': 'not-tested',
                                                       'zygisk_load': 'not-tested', 'app_detection': 'not-tested'})
                for kind, artifact in report['artifacts'].items():
                    self.assertNotIn('gadget-zygisk', artifact['file'])
                    self.assertEqual((context.root / 'out' / artifact['file']).read_bytes(), fixture(version))
                    self.assertEqual((context.build / FINAL_FILENAMES[kind]).read_bytes(), fixture(version))
                    self.assertEqual(artifact['sha256'], hashlib.sha256(fixture(version)).hexdigest())
                    self.assertEqual(artifact['final_target'], TARGETS[kind])
                    self.assertFalse(artifact['binary_modified'])
                    self.assertEqual(artifact['protected_markers'], {token.decode(): 1 for token in collector.elf.PROTECTED})
                self.assertEqual(json.loads((context.root / 'out/manifest.json').read_text(encoding='utf-8')), report)

    def test_current_spec_features_and_repeat_reports_accepted(self):
        for version in patches.VERSIONS:
            recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            features = recipe['features']
            selections = [()] + [(feature,) for feature in features] + [tuple(features), tuple(reversed(features))]
            for index, selection in enumerate(selections):
                with self.subTest(version=version, features=selection):
                    context = self.collection_fixture(version + '-' + str(index), version, selection)
                    for item in context.patches['files']:
                        self.assertEqual(item['result_sha256'], hashlib.sha256(
                            (context.fixture_source / item['path']).read_bytes()).hexdigest())
                    report = self.collect(context)
                    self.assertEqual('gadget-zygisk' in report['artifacts']['gadget']['file'],
                                     'zygisk-loader' in selection)
                    context.patches = patches.apply(context.fixture_source, version, context.patch_path, selection)
                    self.assertNotIn('applied', [item['status'] for item in context.patches['files']])
                    self.collect(context, 'repeat-out')

    def test_entrypoint_artifact_identity_and_module_payload_contract(self):
        spec = importlib.util.spec_from_file_location('module_builder', ROOT / 'scripts/build_module.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        for version in patches.VERSIONS:
            for index, features in enumerate(((), ('agent-entrypoint-rename',), ('zygisk-loader',),
                                              ('zygisk-loader', 'agent-entrypoint-rename'))):
                with self.subTest(version=version, features=features):
                    context = self.collection_fixture(version + '-entry-' + str(index), version, features)
                    report = self.collect(context)
                    renamed = 'agent-entrypoint-rename' in context.patches['features']
                    for kind, artifact in report['artifacts'].items():
                        self.assertEqual('-entry-renamed-' in artifact['file'], renamed)
                        entry = artifact['agent_entrypoint']
                        self.assertEqual(entry['symbol'], ('nianchu_agent_main' if renamed else 'frida_agent_main')
                                         if kind == 'server' else None)
                        self.assertEqual(entry['scope'], 'embedded-agent' if kind == 'server' else 'not-applicable-gadget')
                        self.assertEqual(entry['final_symbol_lookup'], 'not-tested' if kind == 'server' else 'not-applicable')
                        self.assertEqual(artifact['protected_markers']['frida_agent_main'], 1)
                    if 'zygisk-loader' in features:
                        manifest = context.root / 'out/manifest.json'
                        payload, binary, provenance = builder.payload_from_manifest(manifest)
                        self.assertEqual(payload.name, report['artifacts']['gadget']['file'])
                        self.assertEqual(binary, fixture(version))
                        self.assertEqual(provenance, report)
                        wrong = copy.deepcopy(report)
                        wrong['artifacts']['gadget']['file'] = wrong['artifacts']['gadget']['file'].replace(
                            'gadget-zygisk', 'gadget-zygisk-entry-renamed') if not renamed else \
                            wrong['artifacts']['gadget']['file'].replace('-entry-renamed', '')
                        write_json(manifest, wrong)
                        with self.assertRaisesRegex(ValueError, 'invalid final Gadget name'):
                            builder.payload_from_manifest(manifest)

    def test_json_gadget_and_server_identities(self):
        for version in patches.VERSIONS:
            for index, features in enumerate((('gadget-json-config',),
                                              ('gadget-json-config', 'agent-entrypoint-rename'),
                                              ('zygisk-loader', 'gadget-json-config'),
                                              ('zygisk-loader', 'agent-entrypoint-rename', 'gadget-json-config'))):
                with self.subTest(version=version, features=features):
                    context = self.collection_fixture(version + '-json-' + str(index), version, features)
                    report = self.collect(context)
                    gadget = report['artifacts']['gadget']
                    server = report['artifacts']['server']
                    variant = '-entry-renamed' if 'agent-entrypoint-rename' in context.patches['features'] else ''
                    label = 'gadget-zygisk' if 'zygisk-loader' in features else 'gadget'
                    self.assertEqual(gadget['file'], 'nianchu-' + label + variant + '-json-config-' + version + '-android-arm64.so')
                    self.assertEqual(server['file'], 'nianchu-server' + variant + '-' + version + '-android-arm64')
                    self.assertEqual(gadget['final_filename'], 'nianchu-gadget.so')
                    self.assertEqual(server['gadget_config_lookup'], 'not-applicable')
                    self.assertEqual(gadget['gadget_config_lookup'], {
                        'android_sidecars': ['.config', '.json', '.config.so'],
                        'inline_config': 'takes-precedence', 'source_contract': 'verified', 'runtime_lookup': 'not-tested'})

    def test_module_rejects_wrong_json_identity_and_lookup_contract(self):
        spec = importlib.util.spec_from_file_location('module_builder', ROOT / 'scripts/build_module.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        for version in patches.VERSIONS:
            for enabled in (False, True):
                features = ['zygisk-loader', 'agent-entrypoint-rename'] + (['gadget-json-config'] if enabled else [])
                context = self.collection_fixture(version + '-contract-' + str(enabled), version, features)
                report = self.collect(context)
                manifest = context.root / 'out/manifest.json'
                self.assertEqual(builder.payload_from_manifest(manifest)[1], fixture(version))
                artifact = report['artifacts']['gadget']
                wrong_name = artifact['file'].replace('-json-config', '') if enabled else artifact['file'].replace(
                    '-entry-renamed-', '-entry-renamed-json-config-')
                variants = [('file', wrong_name, 'invalid final Gadget name'),
                            ('final_filename', 'frida-gadget.so', 'final Gadget target/filename'),
                            ('final_filename', 'libnianchu-gadget-raw.so', 'final Gadget target/filename'),
                            ('final_target', 'nianchu-gadget-modulated', 'final Gadget target/filename'),
                            ('gadget_config_lookup', 'not-applicable', 'config lookup contract'),
                            ('gadget_config_lookup', {**artifact['gadget_config_lookup'], 'runtime_lookup': 'verified'}, 'config lookup contract'),
                            ('gadget_config_lookup', {**artifact['gadget_config_lookup'], 'android_sidecars': ['.json']}, 'config lookup contract')]
                for field, value, message in variants:
                    with self.subTest(version=version, enabled=enabled, field=field, value=value):
                        wrong = copy.deepcopy(report)
                        wrong['artifacts']['gadget'][field] = value
                        write_json(manifest, wrong)
                        with self.assertRaisesRegex(ValueError, message):
                            builder.payload_from_manifest(manifest)
                wrong = copy.deepcopy(report)
                del wrong['artifacts']['gadget']['gadget_config_lookup']
                write_json(manifest, wrong)
                with self.assertRaisesRegex(ValueError, 'config lookup contract'):
                    builder.payload_from_manifest(manifest)

    def test_final_gadget_filename_must_be_actual_source_output(self):
        context = self.collection_fixture()
        with mock.patch.object(collector.Path, 'is_symlink', autospec=True,
                               side_effect=lambda path: path.name == 'nianchu-gadget.so'):
            self.assert_rejected(context, 'must not be a symlink')
        original_resolve = collector.Path.resolve

        def resolve(path, *args, **kwargs):
            if path == context.build / 'nianchu-gadget.so':
                return context.build / 'libnianchu-gadget-raw.so'
            return original_resolve(path, *args, **kwargs)

        with mock.patch.object(collector.Path, 'resolve', autospec=True, side_effect=resolve):
            self.assert_rejected(context, 'resolved final Gadget filename')
        for filename in ('frida-gadget.so', 'libnianchu-gadget-raw.so', 'libnianchu-gadget-modulated.so', 'gadget'):
            with self.subTest(filename=filename):
                (context.build / filename).write_bytes(fixture())
                items = copy.deepcopy(context.items)
                items[1]['filename'] = [filename]
                write_json(context.intro, items)
                self.assert_rejected(context, 'final Gadget filename')

    def test_json_module_zip_model_keeps_internal_payload(self):
        spec = importlib.util.spec_from_file_location('module_builder', ROOT / 'scripts/build_module.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        for version in patches.VERSIONS:
            for renamed in (False, True):
                features = ['zygisk-loader', 'gadget-json-config'] + (['agent-entrypoint-rename'] if renamed else [])
                context = self.collection_fixture(version + '-zip-' + str(renamed), version, features)
                report = self.collect(context)
                ndk = context.root / 'model-ndk'
                ndk.mkdir()
                (ndk / 'source.properties').write_text('Pkg.Revision = ' + context.expected['ndk_revision'], encoding='utf-8')

                def run(*args):
                    if str(args[0]).endswith(('clang++', 'clang++.exe')):
                        args[args.index('-o') + 1].write_bytes(b'SOURCE MODEL ONLY - NOT A WRAPPER ELF')
                        return ''
                    if '--dyn-syms' in args:
                        symbol = 'zygisk_module_entry' if args[-1].name == 'arm64-v8a.so' else 'nianchu_gadget_init'
                        return '1: 0 0 FUNC GLOBAL DEFAULT 1 ' + symbol + '\n'
                    self.assertIn('--dynamic', args)
                    return '(NEEDED) Shared library: [libc.so]\n'

                out = context.root / 'module-model'
                with mock.patch.object(builder, 'run', side_effect=run), mock.patch('builtins.print'):
                    built = builder.build(ndk, out, context.root / 'out/manifest.json')
                variant = collector.artifact_variant('gadget', context.patches['features']).removesuffix('-json-config')
                archive = out / ('nianchu-zygisk' + variant + '-json-config-' + version + '-android-arm64.zip')
                with zipfile.ZipFile(archive) as package:
                    self.assertEqual(package.read('gadget/libnianchu-gadget.so'), fixture(version))
                    self.assertFalse(any(name.endswith(('.json', '.config.so')) and name.startswith('gadget/')
                                         for name in package.namelist()))
                    self.assertEqual(json.loads(package.read('build-report.json'))['gadget_manifest'], report)
                self.assertEqual(built['zygisk_load'], 'not-tested')
        print('PASS module zip source model: compiler/readelf stubbed; no real wrapper or Android claim')

    def test_rewrite_collection_and_module_entry_model(self):
        # Consumer model: the ELF algorithm itself is tested independently.
        spec = importlib.util.spec_from_file_location('module_builder', ROOT / 'scripts/build_module.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        for version in patches.VERSIONS:
            context = self.collection_fixture(version + '-rewrite', version, ['zygisk-loader'])
            original = fixture(version)
            rewritten = original.replace(b'frida:rpc', b'other:rpc')
            entry = 'nianchu_ABCDEF_init'

            def rewrite(data, kind):
                self.assertEqual(data, original)
                return rewritten, {'kind': kind, 'initialization_symbol': entry,
                                   'before': collector.elf.audit(data), 'after': collector.elf.audit(rewritten)}

            def validate(data, report, kind):
                if (not isinstance(report, dict) or report.get('kind') != kind
                        or report.get('after') != collector.elf.audit(data)
                        or report.get('initialization_symbol') != entry):
                    raise ValueError('invalid model rewrite report')

            with mock.patch.object(collector.elf, 'rewrite', side_effect=rewrite), \
                    mock.patch.object(collector.elf, 'validate_rewrite_report', side_effect=validate), \
                    mock.patch.object(collector.elf, 'verify_embedded_agents', return_value=[{'model': True}]):
                report = collector.collect(context.build, version, context.root / 'out',
                                           context.source_path, context.patch_path, True)
            self.assertTrue(report['binary_modified'])
            for kind, artifact in report['artifacts'].items():
                self.assertIn('-elf-rewritten-', artifact['file'])
                self.assertEqual('-json-config-' in artifact['file'], kind == 'gadget')
                self.assertEqual((context.build / FINAL_FILENAMES[kind]).read_bytes(), original)
                self.assertEqual((context.root / 'out' / artifact['file']).read_bytes(), rewritten)
                sidecar = context.root / 'out' / (artifact['file'] + '.rewrite.json')
                self.assertEqual(json.loads(sidecar.read_text()), artifact['elf_rewrite'])
            manifest = context.root / 'out/manifest.json'
            ndk = context.root / 'model-ndk'
            ndk.mkdir()
            (ndk / 'source.properties').write_text('Pkg.Revision = ' + context.expected['ndk_revision'])
            out = context.root / 'module-model'

            def run(*args):
                if str(args[0]).endswith(('clang++', 'clang++.exe')):
                    self.assertIn(out / 'module.cpp', args)
                    self.assertIn('-I' + str(ROOT / 'module/src'), args)
                    self.assertIn('"' + entry + '"', (out / 'module.cpp').read_text())
                    args[args.index('-o') + 1].write_bytes(b'MODEL WRAPPER')
                    return ''
                if '--dyn-syms' in args:
                    symbol = 'zygisk_module_entry' if args[-1].name == 'arm64-v8a.so' else entry
                    return '1: 0 0 FUNC GLOBAL DEFAULT 1 ' + symbol + '\n'
                return '(NEEDED) Shared library: [libc.so]\n'

            with mock.patch.object(builder.collector.elf, 'validate_rewrite_report', side_effect=validate), \
                    mock.patch.object(builder, 'run', side_effect=run), mock.patch('builtins.print'):
                built = builder.build(ndk, out, manifest)
                self.assertEqual(built['initialization_symbol'], entry)
                self.assertEqual(built['compiled_source_sha256'], hashlib.sha256((out / 'module.cpp').read_bytes()).hexdigest())
                archive = next(out.glob('*.zip'))
                self.assertIn('-elf-rewritten-json-config-', archive.name)
                with zipfile.ZipFile(archive) as package:
                    self.assertEqual(package.read('gadget/libnianchu-gadget.so'), rewritten)
                for field, value in (('elf_rewrite', None), ('binary_modified', False)):
                    wrong = copy.deepcopy(report)
                    wrong['artifacts']['gadget'][field] = value
                    write_json(manifest, wrong)
                    with self.assertRaises(ValueError):
                        builder.payload_from_manifest(manifest)

    def test_rewritten_collection_rejects_unverified_embedded_agent(self):
        context = self.collection_fixture('bad-agent')
        with mock.patch.object(collector.elf, 'rewrite', side_effect=lambda data, kind: (data, {})), \
                mock.patch.object(collector.elf, 'validate_rewrite_report'), \
                mock.patch.object(collector.elf, 'verify_embedded_agents',
                                  side_effect=ValueError('unpatched FridaAgentStopReason')):
            with self.assertRaisesRegex(ValueError, 'unpatched FridaAgentStopReason'):
                collector.collect(context.build, context.version, context.root / 'out',
                                  context.source_path, context.patch_path, True)
        self.assertFalse((context.root / 'out').exists())

    def test_single_applied_record_regression(self):
        context = self.collection_fixture()
        # This was previously accepted despite having no complete file or hash evidence.
        write_json(context.patch_path, {'version': context.version, 'dry_run': False,
                                        'files': [{'status': 'applied'}]})
        self.assert_rejected(context)
        report = copy.deepcopy(context.patches)
        report['files'] = [report['files'][0]]
        write_json(context.patch_path, report)
        self.assert_rejected(context, 'file set')

    def test_patch_file_set_and_record_types_rejected(self):
        context = self.collection_fixture()
        files = context.patches['files']
        extra = {**files[0], 'path': 'unexpected/source.c'}
        variants = [None, {}, [], files[:-1], files + [extra], files + [files[0]],
                    files[:-1] + [files[0]], [None] + files[1:],
                    [{key: value for key, value in files[0].items() if key != 'path'}] + files[1:],
                    [{**files[0], 'path': []}] + files[1:]]
        for index, variant in enumerate(variants):
            with self.subTest(index=index):
                report = copy.deepcopy(context.patches)
                report['files'] = variant
                write_json(context.patch_path, report)
                self.assert_rejected(context)

    def test_patch_metadata_required_and_strict(self):
        context = self.collection_fixture()
        for field in context.patches:
            with self.subTest(missing=field):
                report = copy.deepcopy(context.patches)
                del report[field]
                write_json(context.patch_path, report)
                self.assert_rejected(context)
        variants = {'schema': [0, 2, True, '1'], 'version': ['17.25.2', None],
                    'profile': ['', 'other', None], 'dry_run': [True, 0, None],
                    'binary_rewriting': [True, 0], 'runtime_tested': [True, 0],
                    'java_bridge': [{}, {**context.patches['java_bridge'], 'modified': not context.patches['java_bridge']['modified']}],
                    'features': [None, {}, '', ['unknown-feature'], ['exit-monitor-off', 'exit-monitor-off'], [None]]}
        for field, values in variants.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    report = copy.deepcopy(context.patches)
                    report[field] = value
                    write_json(context.patch_path, report)
                    self.assert_rejected(context)
        for report in (None, [], 'report'):
            with self.subTest(report=report):
                write_json(context.patch_path, report)
                self.assert_rejected(context)

    def test_real_dry_run_report_rejected(self):
        context = self.collection_fixture()
        patches.apply(context.fixture_source, context.version, context.patch_path, dry_run=True)
        self.assert_rejected(context, 'applied version/profile')

    def test_patch_hashes_required_for_every_file(self):
        context = self.collection_fixture()
        for index, item in enumerate(context.patches['files']):
            for field in ('upstream_sha256', 'result_sha256'):
                for value in (None, '', 'bad', '0' * 64, 'A' * 64, [], 0):
                    with self.subTest(path=item['path'], field=field, value=value):
                        report = copy.deepcopy(context.patches)
                        report['files'][index][field] = value
                        write_json(context.patch_path, report)
                        self.assert_rejected(context, 'hash mismatch')
                with self.subTest(path=item['path'], missing=field):
                    report = copy.deepcopy(context.patches)
                    del report['files'][index][field]
                    write_json(context.patch_path, report)
                    self.assert_rejected(context, 'hash mismatch')

    def test_valid_but_wrong_recipe_hashes_rejected(self):
        context = self.collection_fixture()
        other = self.collection_fixture('other', '17.25.2')
        for field in ('upstream_sha256', 'result_sha256'):
            with self.subTest(field=field):
                report = copy.deepcopy(context.patches)
                report['files'][0][field] = other.patches['files'][0][field]
                write_json(context.patch_path, report)
                self.assert_rejected(context, 'hash mismatch')
        report = copy.deepcopy(context.patches)
        report['files'][0]['result_sha256'] = report['files'][0]['upstream_sha256']
        write_json(context.patch_path, report)
        self.assert_rejected(context, 'hash mismatch')

    def test_feature_claim_must_match_recipe_hash(self):
        for version in patches.VERSIONS:
            recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            for feature in recipe['features']:
                with self.subTest(version=version, feature=feature):
                    context = self.collection_fixture(version + '-' + feature, version)
                    report = copy.deepcopy(context.patches)
                    report['features'] = [feature]
                    write_json(context.patch_path, report)
                    self.assert_rejected(context, 'hash mismatch')
                    featured = self.collection_fixture(version + '-' + feature + '-enabled', version, [feature])
                    report = copy.deepcopy(featured.patches)
                    report['features'] = []
                    write_json(featured.patch_path, report)
                    self.assert_rejected(featured, 'hash mismatch')

    def test_patch_status_must_match_changed_or_guard_file(self):
        context = self.collection_fixture()
        for index, item in enumerate(context.patches['files']):
            values = [None, 'failed', 'dry-run', 'applied' if item['status'] == 'verified-unchanged' else 'verified-unchanged']
            for value in values:
                with self.subTest(path=item['path'], status=value):
                    report = copy.deepcopy(context.patches)
                    report['files'][index]['status'] = value
                    write_json(context.patch_path, report)
                    self.assert_rejected(context, 'patch status')

    def test_source_report_requires_actual_verifier_fields(self):
        context = self.collection_fixture()
        write_json(context.source_path, context.expected)
        self.assert_rejected(context, 'schema')
        for field in context.source:
            with self.subTest(missing=field):
                report = copy.deepcopy(context.source)
                del report[field]
                if field in ('python', 'node', 'npm', 'git'):
                    report['toolchain'] = {field: context.source[field]}
                write_json(context.source_path, report)
                self.assert_rejected(context)
        for report in (None, [], 'report'):
            with self.subTest(report=report):
                write_json(context.source_path, report)
                self.assert_rejected(context)

    def test_source_metadata_and_toolchain_rejected(self):
        context = self.collection_fixture()
        variants = {'schema': [0, 2, True, '1'], 'version': ['17.25.2', None],
                    'commit': ['0' * 40, None], 'ndk_revision': ['0.0.0', None],
                    'submodules': [{}, [], {**context.source['submodules'], 'releng': '0' * 40}],
                    'runtime_tested': [True, 0]}
        variants.update({field: [None, '', '   ', [], 22, 'version\nextra', 'version\rextra']
                         for field in ('python', 'node', 'npm', 'git')})
        for field, values in variants.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    report = copy.deepcopy(context.source)
                    report[field] = value
                    write_json(context.source_path, report)
                    self.assert_rejected(context)

    def test_source_submodule_status_rejected(self):
        context = self.collection_fixture()
        lines = context.source['submodule_status']
        path, sha = next(iter(context.source['submodules'].items()))
        healthy = ' ' + sha + ' ' + path
        variants = [None, '', {}, [], lines[:-1], lines + [lines[0]],
                    [None] + lines[1:], [''] + lines[1:], ['garbage'] + lines[1:],
                    ['0' * 40 + ' ' + path] + lines[1:], [' ' + 'f' * 39 + ' ' + path] + lines[1:]]
        variants += [[prefix + healthy[1:]] + lines[1:] for prefix in ('-', '+', 'U')]
        for index, variant in enumerate(variants):
            with self.subTest(index=index):
                report = copy.deepcopy(context.source)
                report['submodule_status'] = variant
                write_json(context.source_path, report)
                self.assert_rejected(context, 'submodule_status')

    def test_recursive_healthy_submodule_status_accepted(self):
        context = self.collection_fixture()
        context.source['submodule_status'] = [' ' + sha + ' ' + path for path, sha in context.source['submodules'].items()]
        context.source['submodule_status'].append(' ' + 'a' * 40 + ' subprojects/frida-core/nested (heads/mock)')
        write_json(context.source_path, context.source)
        self.collect(context)

    def test_outputs_must_exist_inside_build_and_be_distinct(self):
        context = self.collection_fixture()
        outside = context.root / 'outside'
        outside.write_bytes(fixture())
        folder = context.build / 'folder'
        folder.mkdir()
        for filename in ('missing', str(folder), str(outside), '../outside', 'gadget'):
            with self.subTest(filename=filename):
                items = copy.deepcopy(context.items)
                items[0]['filename'] = [filename]
                write_json(context.intro, items)
                self.assert_rejected(context)
        for items in (context.items[:1], context.items + [context.items[0]]):
            write_json(context.intro, items)
            self.assert_rejected(context)

    def test_absolute_final_paths_accepted(self):
        context = self.collection_fixture()
        for item in context.items:
            item['filename'] = [str(context.build / item['filename'][0])]
        write_json(context.intro, context.items)
        self.collect(context)

    def test_missing_version_or_invalid_final_elf_rejected(self):
        context = self.collection_fixture()
        for kind in TARGETS:
            for data in (b'not ELF', fixture('wrong-version')):
                with self.subTest(kind=kind, data=data[:7]):
                    (context.build / FINAL_FILENAMES[kind]).write_bytes(data)
                    self.assert_rejected(context)
            (context.build / FINAL_FILENAMES[kind]).write_bytes(fixture())

    def test_copy_corruption_and_source_race_rejected(self):
        context = self.collection_fixture()
        original_copy = shutil.copyfile

        def corrupt_copy(source, destination):
            original_copy(source, destination)
            destination.write_bytes(destination.read_bytes() + b'corrupt')

        with mock.patch.object(collector.shutil, 'copyfile', side_effect=corrupt_copy):
            with self.assertRaisesRegex(ValueError, 'byte identity'):
                self.collect(context)
        self.assertFalse((context.root / 'out/manifest.json').exists())
        for kind in TARGETS:
            self.assertEqual((context.build / FINAL_FILENAMES[kind]).read_bytes(), fixture())

        def mutate_source(source, destination):
            original_copy(source, destination)
            source.write_bytes(source.read_bytes() + b'changed-during-copy')

        with mock.patch.object(collector.shutil, 'copyfile', side_effect=mutate_source):
            with self.assertRaisesRegex(ValueError, 'byte identity'):
                self.collect(context, 'race-out')
        self.assertFalse((context.root / 'race-out/manifest.json').exists())

    def test_existing_output_not_overwritten(self):
        context = self.collection_fixture()
        output = context.root / 'out'
        output.mkdir()
        sentinel = output / 'keep'
        sentinel.write_bytes(b'unchanged')
        with self.assertRaisesRegex(ValueError, 'must not exist'):
            self.collect(context)
        self.assertEqual(sentinel.read_bytes(), b'unchanged')
        self.assertFalse((output / 'manifest.json').exists())


if __name__ == '__main__':
    unittest.main()
