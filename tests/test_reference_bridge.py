#!/usr/bin/env python3
"""Reference hook patch and isolated bundle contracts; no Android runtime tests."""

import base64
import difflib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/java-bridge'


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bridge = load_script('reference_bridge_test_patcher', 'patch_reference_bridge.py')
builder = load_script('reference_bridge_test_builder', 'build_reference_bridge.py')
TARGET = 'lib/android.js'
REMOVED = (b'  Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);\n'
           b'  Interceptor.flush();\n')
EXPECTED_PATCHED_SHA256 = {
    '6.3.9': 'bcc4ea4b6840834689d97f345737aa3c4c65e00bc99eebddf13d340491ebf342',
    '7.0.13': 'f7aa948853da310094f87ed77d58d3cea8c72776143057a6ff26bf8f7284c8e4',
}


def snapshot(directory):
    return {path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob('*') if path.is_file()}


class ReferenceBridgeTests(unittest.TestCase):
    version = '6.3.9'

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / 'node_modules/frida-java-bridge'
        shutil.copytree(FIXTURES / self.version, self.source)
        self.report = self.directory / 'reports/reference.json'
        self.original = snapshot(self.source)

    def apply(self):
        return bridge.patch(self.source, self.version, self.report)

    def assert_preflight_rejects(self, pattern):
        before = snapshot(self.source)
        with mock.patch.object(bridge, 'stage_bytes') as stage, \
                mock.patch.object(bridge, 'atomic_write') as write:
            with self.assertRaisesRegex(ValueError, pattern):
                self.apply()
            stage.assert_not_called()
            write.assert_not_called()
        self.assertEqual(snapshot(self.source), before)
        self.assertFalse(self.report.exists())
        self.assertFalse(self.report.parent.exists())

    def test_exact_two_line_deletion_and_actual_report(self):
        inventory = bridge.load_inventory(self.version)
        self.assertEqual(bridge.package_hashes(self.original), inventory)
        report = self.apply()
        expected = self.original[TARGET].replace(REMOVED, b'', 1)
        self.assertEqual(snapshot(self.source), dict(self.original, **{TARGET: expected}))
        self.assertEqual(hashlib.sha256(expected).hexdigest(), EXPECTED_PATCHED_SHA256[self.version])
        changes = [line for line in difflib.ndiff(self.original[TARGET].decode().splitlines(True),
                                                expected.decode().splitlines(True))
                   if line.startswith(('+ ', '- '))]
        self.assertEqual(changes, ['- ' + line for line in REMOVED.decode().splitlines(True)])
        self.assertEqual(report['author'], 'nianchu')
        self.assertEqual(report['profile'], 'reference-disable-art-prettymethod-hook')
        self.assertEqual(report['status'], 'patched')
        self.assertEqual(report['changed_files'], [TARGET])
        self.assertEqual(report['patch_files'], [TARGET])
        self.assertEqual(report['before'], inventory)
        self.assertEqual(report['after'], bridge.package_hashes(snapshot(self.source)))
        self.assertEqual(report['source'], str(self.source.resolve()))
        self.assertFalse(report['runtime_tested'])
        self.assertFalse(report['package_executed'])
        self.assertEqual(json.loads(self.report.read_bytes()), report)
        self.assertEqual((self.source / 'lib/class-factory.js').read_bytes(), self.original['lib/class-factory.js'])

    def test_idempotent_full_patched_group_does_not_rewrite_source(self):
        first = self.apply()
        before = snapshot(self.source)
        modified_at = (self.source / TARGET).stat().st_mtime_ns
        with mock.patch.object(bridge, 'atomic_write', wraps=bridge.atomic_write) as write:
            second = self.apply()
            write.assert_not_called()
        self.assertEqual(snapshot(self.source), before)
        self.assertEqual((self.source / TARGET).stat().st_mtime_ns, modified_at)
        self.assertEqual(second['status'], 'already-patched')
        self.assertEqual(second['state_before'], 'patched')
        self.assertEqual(second['changed_files'], [])
        self.assertEqual(second['before'], first['after'])
        self.assertEqual(second['after'], second['before'])
        self.assertEqual(json.loads(self.report.read_bytes()), second)

    def test_every_original_file_hash_is_checked_before_any_write(self):
        for relative, original in self.original.items():
            with self.subTest(file=relative):
                path = self.source / relative
                path.write_bytes(original + b'\n')
                self.assert_preflight_rejects('source drift')
                path.write_bytes(original)

    def test_every_missing_file_is_rejected_before_any_write(self):
        for relative, original in self.original.items():
            with self.subTest(file=relative):
                path = self.source / relative
                path.unlink()
                self.assert_preflight_rejects('file set mismatch.*missing=')
                path.write_bytes(original)

    def test_package_local_extras_are_not_hidden_as_npm_metadata(self):
        for relative in ('extra.js', '.package-lock.json', 'node_modules/injected/index.js'):
            with self.subTest(file=relative):
                path = self.source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'// unexpected\n')
                self.assert_preflight_rejects('file set mismatch.*extra=')
                path.unlink()

    def test_sibling_dependencies_and_parent_npm_metadata_are_untouched(self):
        sibling = self.source.parent / 'jssha/index.js'
        sibling.parent.mkdir()
        sibling.write_bytes(b'// not part of frida-java-bridge\n')
        parent_lock = self.source.parent / '.package-lock.json'
        parent_lock.write_bytes(b'{"lockfileVersion":3}\n')
        sibling_before = sibling.read_bytes()
        lock_before = parent_lock.read_bytes()
        self.apply()
        self.assertEqual(sibling.read_bytes(), sibling_before)
        self.assertEqual(parent_lock.read_bytes(), lock_before)

    def test_half_deleted_hook_is_not_considered_already_patched(self):
        path = self.source / TARGET
        for removed_line in REMOVED.splitlines(True):
            with self.subTest(line=removed_line):
                path.write_bytes(self.original[TARGET].replace(removed_line, b'', 1))
                self.assert_preflight_rejects('source drift')
        path.write_bytes(self.original[TARGET])

    def test_crlf_normalization_is_source_drift_not_fuzzy_patch(self):
        (self.source / TARGET).write_bytes(self.original[TARGET].replace(b'\n', b'\r\n'))
        self.assert_preflight_rejects('source drift')

    def test_legacy_direct_art_gc_group_is_not_accepted(self):
        recipe = json.loads((ROOT / 'patches/java-bridge' / self.version / 'spec.json').read_bytes())
        for entry in recipe['files']:
            path = self.source / entry['path']
            data = path.read_bytes()
            for edit in entry['edits']:
                old = edit['old'].encode()
                self.assertEqual(data.count(old), edit['count'])
                data = data.replace(old, edit['new'].encode(), edit['count'])
            path.write_bytes(data)
        self.assert_preflight_rejects('source drift')

    def test_patched_target_plus_unrelated_drift_fails_full_group_preflight(self):
        (self.source / TARGET).write_bytes(self.original[TARGET].replace(REMOVED, b'', 1))
        last_file = self.source / 'lib/vm.js'
        last_file.write_bytes(self.original['lib/vm.js'] + b'\n// late drift\n')
        self.assert_preflight_rejects('source drift.*lib/vm.js')

    def test_report_inside_package_or_directory_is_rejected_before_patch(self):
        for report in (self.source / 'report.json', self.source / TARGET, self.directory):
            with self.subTest(report=report):
                with self.assertRaisesRegex(ValueError, 'external|regular file'):
                    bridge.patch(self.source, self.version, report)
                self.assertEqual(snapshot(self.source), self.original)
        self.assertFalse((self.source / 'report.json').exists())

    def test_existing_report_survives_failed_preflight(self):
        self.report.parent.mkdir()
        self.report.write_bytes(b'previous successful report\n')
        (self.source / 'lib/vm.js').write_bytes(b'drift')
        with self.assertRaisesRegex(ValueError, 'source drift'):
            self.apply()
        self.assertEqual(self.report.read_bytes(), b'previous successful report\n')
        self.assertEqual((self.source / TARGET).read_bytes(), self.original[TARGET])

    def test_report_io_failure_occurs_before_target_write(self):
        with mock.patch.object(bridge, 'stage_bytes', side_effect=PermissionError('report denied')), \
                mock.patch.object(bridge, 'atomic_write') as write:
            with self.assertRaisesRegex(PermissionError, 'report denied'):
                self.apply()
            write.assert_not_called()
        self.assertEqual(snapshot(self.source), self.original)
        self.assertFalse(self.report.exists())

    def test_atomic_replace_error_does_not_publish_report_or_leave_staged_files(self):
        with mock.patch.object(bridge.os, 'replace', side_effect=OSError('replace denied')):
            with self.assertRaisesRegex(OSError, 'replace denied'):
                self.apply()
        self.assertEqual(snapshot(self.source), self.original)
        self.assertFalse(self.report.exists())
        self.assertEqual(list(self.report.parent.iterdir()), [])

    def test_inventory_data_cannot_silently_change_its_pins(self):
        root = self.directory / 'tampered-inventory'
        path = root / 'patches/java-bridge' / self.version / 'spec.json'
        path.parent.mkdir(parents=True)
        recipe = json.loads((ROOT / 'patches/java-bridge' / self.version / 'spec.json').read_bytes())
        recipe['package_files']['lib/vm.js'] = '0' * 64
        path.write_bytes(bridge.json_bytes(recipe))
        with mock.patch.object(bridge, 'ROOT', root):
            self.assert_preflight_rejects('pinned official bridge inventory')

    def test_package_symlink_is_rejected(self):
        link = self.directory / 'bridge-link'
        try:
            link.symlink_to(self.source, target_is_directory=True)
        except OSError as error:
            self.skipTest('symlink creation is unavailable: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'symlinks or junctions'):
            bridge.patch(link, self.version, self.report)
        self.assertEqual(snapshot(self.source), self.original)

    def test_cli_requires_all_arguments_propagates_drift_and_is_idempotent(self):
        script = ROOT / 'scripts/patch_reference_bridge.py'

        def invoke(arguments):
            return subprocess.run([sys.executable, '-I', str(script), *arguments],
                                  cwd=self.directory, capture_output=True, text=True,
                                  encoding='utf-8', errors='replace', timeout=30)

        arguments = ['--source', str(self.source), '--version', self.version, '--report', str(self.report)]
        for omitted in ('--source', '--version', '--report'):
            index = arguments.index(omitted)
            result = invoke(arguments[:index] + arguments[index + 2:])
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(snapshot(self.source), self.original)
        result = invoke(arguments)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('runtime_tested=false', result.stdout)
        result = invoke(arguments)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('already-patched', result.stdout)
        before_report = self.report.read_bytes()
        (self.source / 'lib/vm.js').write_bytes(b'drift')
        result = invoke(arguments)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('FATAL:', result.stderr)
        self.assertEqual(self.report.read_bytes(), before_report)

    def test_patched_android_parses_without_executing_package_code(self):
        node = shutil.which('node')
        if node is None:
            self.skipTest('node unavailable for syntax-only check')
        self.apply()
        result = subprocess.run([node, '--check', str(self.source / TARGET)],
                                cwd=self.directory, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ReferenceBridge7Tests(ReferenceBridgeTests):
    version = '7.0.13'


class ReferenceBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.out = self.directory / 'nianchu build 空间'
        self.work = self.directory / 'safe-work'

    def test_archive_all_three_hash_guards(self):
        data = b'fixed package archive bytes'
        pin = {'url': 'https://registry.npmjs.org/example',
               'sha256': hashlib.sha256(data).hexdigest(),
               'shasum': hashlib.sha1(data).hexdigest(),
               'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()}
        builder.verify_archive(data, pin)
        for field in ('sha256', 'shasum', 'integrity'):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, 'hash/integrity mismatch'):
                    builder.verify_archive(data, dict(pin, **{field: 'wrong'}))
        with self.assertRaisesRegex(ValueError, 'hash/integrity mismatch'):
            builder.verify_archive(data + b'drift', pin)

    def archive_with_members(self, members):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for name, content, kind in members:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(content) if kind == tarfile.REGTYPE else 0
                if kind == tarfile.SYMTYPE:
                    member.linkname = '/outside'
                archive.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
        return output.getvalue()

    def test_archive_reader_does_not_extract_and_rejects_unsafe_members(self):
        safe = self.archive_with_members([('package/lib/a.js', b'original', tarfile.REGTYPE)])
        self.assertEqual(builder.archive_files(safe), {'lib/a.js': b'original'})
        self.assertEqual(list(self.directory.iterdir()), [])
        for name, kind in (('package/../outside', tarfile.REGTYPE),
                           ('/package/absolute', tarfile.REGTYPE),
                           ('package/lib\\windows.js', tarfile.REGTYPE),
                           ('package/C:/drive.js', tarfile.REGTYPE),
                           ('package/x:stream', tarfile.REGTYPE),
                           ('package/trailing./x', tarfile.REGTYPE),
                           ('package/trailing /x', tarfile.REGTYPE),
                           ('other/lib/a.js', tarfile.REGTYPE),
                           ('package/lib/link.js', tarfile.SYMTYPE)):
            with self.subTest(name=name):
                unsafe = self.archive_with_members([(name, b'', kind)])
                with self.assertRaisesRegex(ValueError, 'unsafe|regular package files'):
                    builder.archive_files(unsafe)
        duplicate = self.archive_with_members([('package/a', b'a', tarfile.REGTYPE),
                                               ('package/a', b'b', tarfile.REGTYPE)])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            builder.archive_files(duplicate)
        self.assertEqual(list(self.directory.iterdir()), [])

    def lock_fixture(self):
        return {'lockfileVersion': 3, 'packages': {
            '': {'name': 'private-build', 'version': '1.0.0'},
            'node_modules/frida-java-bridge': {
                'version': '7.0.13', 'resolved': 'file:../downloads/bridge/package.tgz',
                'integrity': builder.bridge.SOURCE_PINS['7.0.13']['integrity'],
            },
            'node_modules/frida-compile': {
                'version': builder.COMPILER_VERSION, 'resolved': 'file:../downloads/compiler/package.tgz',
                'integrity': builder.COMPILER_PIN['integrity'],
            },
            'node_modules/@frida/net': {
                'version': '4.0.1', 'resolved': 'https://registry.npmjs.org/@frida/net/-/net-4.0.1.tgz',
                'integrity': 'sha512-' + base64.b64encode(b'fixture' * 8).decode(),
            },
        }}

    def test_dependency_lock_guards_versions_integrity_registry_and_links(self):
        pins = {'frida-java-bridge': ('7.0.13', builder.bridge.SOURCE_PINS['7.0.13']),
                'frida-compile': (builder.COMPILER_VERSION, builder.COMPILER_PIN)}
        lock = self.lock_fixture()
        self.assertEqual(len(builder.verify_lock(lock, pins)), 3)
        for relative, field, value in (
                ('node_modules/frida-java-bridge', 'version', '7.0.14'),
                ('node_modules/frida-compile', 'integrity', 'sha512-wrong'),
                ('node_modules/@frida/net', 'resolved', 'https://untrusted.example/net.tgz'),
                ('node_modules/@frida/net', 'integrity', ''),
                ('node_modules/@frida/net', 'integrity', None),
                ('node_modules/@frida/net', 'resolved', None),
                ('node_modules/@frida/net', 'link', True)):
            with self.subTest(relative=relative, field=field):
                changed = self.lock_fixture()
                changed['packages'][relative][field] = value
                with self.assertRaises(ValueError):
                    builder.verify_lock(changed, pins)

    def test_malformed_lock_is_rejected_with_a_validation_error(self):
        for lock in ([], {'lockfileVersion': 3, 'packages': {'node_modules/x': None}}):
            with self.subTest(lock=lock), self.assertRaises(ValueError):
                builder.verify_lock(lock, {})

    def test_nested_compiler_dependency_directory_is_checked_before_exclusion(self):
        package = self.directory / 'compiler'
        package.mkdir()
        (package / 'package.json').write_bytes(b'{}')
        (package / 'node_modules').mkdir()
        original = builder.bridge.checked_path

        def checked(path, label):
            if Path(path).name == 'node_modules':
                raise ValueError('symlinks or junctions')
            return original(path, label)

        with mock.patch.object(builder.bridge, 'checked_path', side_effect=checked):
            with self.assertRaisesRegex(ValueError, 'symlinks or junctions'):
                builder.verify_compiler(package, {'package.json': b'{}'})

    def test_compiler_work_root_avoids_url_escaping_without_changing_compiler(self):
        self.assertTrue(builder.compiler_path_safe(self.directory / 'ascii-safe'))
        self.assertFalse(builder.compiler_path_safe(self.directory / 'has space'))
        self.assertFalse(builder.compiler_path_safe(self.directory / '中文'))
        with mock.patch.object(builder.tempfile, 'gettempdir', return_value=str(self.directory)), \
                mock.patch.object(builder.tempfile, 'mkdtemp', return_value=str(self.work)) as create:
            result = builder.create_work_directory(self.out, None)
            self.assertEqual(result, self.work.resolve())
            self.assertEqual(create.call_args.kwargs['dir'], self.directory.resolve())
        for unsafe in (self.directory / 'unsafe space', self.out / 'nested'):
            with self.subTest(work=unsafe):
                with self.assertRaisesRegex(ValueError, 'URL escaping|new and separate'):
                    builder.create_work_directory(self.out, unsafe)
                self.assertFalse(unsafe.exists())
        self.work.mkdir()
        with self.assertRaisesRegex(ValueError, 'new and separate'):
            builder.create_work_directory(self.out, self.work)

    def test_compiler_own_inventory_drift_and_string_bin_contract(self):
        package = self.directory / 'compiler-package'
        package.mkdir()
        files = {
            'package.json': bridge.json_bytes({'name': 'frida-compile', 'version': '16.4.1',
                                               'bin': 'dist/cli.js'}),
            'dist/cli.js': b'// exact compiler\n',
        }
        for relative, data in files.items():
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.assertEqual(builder.verify_compiler(package, files), bridge.package_hashes(files))
        (package / 'dist/cli.js').write_bytes(b'// drifted compiler\n')
        with self.assertRaisesRegex(ValueError, 'inventory/hash mismatch'):
            builder.verify_compiler(package, files)
        (package / 'dist/cli.js').write_bytes(files['dist/cli.js'])
        (package / 'extra.js').write_bytes(b'// not in official compiler archive\n')
        with self.assertRaisesRegex(ValueError, 'inventory/hash mismatch'):
            builder.verify_compiler(package, files)

    def test_host_commands_always_check_exit_status(self):
        with mock.patch.object(builder.subprocess, 'run') as run:
            builder.run_checked(['node', 'compiler.js'], self.directory, {'controlled': 'yes'})
        self.assertTrue(run.call_args.kwargs['check'])
        self.assertEqual(run.call_args.kwargs['cwd'], self.directory)
        self.assertEqual(run.call_args.kwargs['env'], {'controlled': 'yes'})

    def test_existing_output_or_unsupported_version_never_starts_npm(self):
        self.out.mkdir()
        sentinel = self.out / 'keep'
        sentinel.write_bytes(b'unchanged')
        with mock.patch.object(builder, 'run_checked') as run:
            with self.assertRaisesRegex(ValueError, 'new independent'):
                builder.build(self.out)
            with self.assertRaisesRegex(ValueError, 'supports only'):
                builder.build(self.directory / 'unused', '6.3.9')
            run.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b'unchanged')

    def run_mock_build(self, *, fail_install=False, drift_during_compile=False):
        bridge_files = snapshot(FIXTURES / '7.0.13')
        compiler_files = {
            'package.json': bridge.json_bytes({'name': 'frida-compile', 'version': builder.COMPILER_VERSION,
                                               'type': 'module', 'bin': 'dist/cli.js'}),
            'dist/cli.js': b'// fixed compiler fixture; never executed\n',
        }
        commands = []

        def download(pin, directory):
            directory.mkdir(parents=True)
            archive = directory / 'package.tgz'
            archive.write_bytes(b'mocked verified archive')
            return archive, compiler_files if pin == builder.COMPILER_PIN else bridge_files

        def run(command, project, env):
            commands.append(command)
            if command[-1] == '--version':
                return subprocess.CompletedProcess(command, 0, '24.11.0\n', '')
            if 'install' in command:
                if fail_install:
                    raise subprocess.CalledProcessError(23, command, 'npm failed', '')
                (project / 'package-lock.json').write_bytes(bridge.json_bytes(self.lock_fixture()))
            elif 'ci' in command:
                shutil.copytree(FIXTURES / '7.0.13', project / 'node_modules/frida-java-bridge')
                for relative, data in compiler_files.items():
                    path = project / 'node_modules/frida-compile' / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            elif '-o' in command:
                source = project / 'node_modules/frida-java-bridge'
                self.assertEqual((source / TARGET).read_bytes(), bridge_files[TARGET].replace(REMOVED, b'', 1))
                self.assertEqual((project / 'entrypoint.js').read_bytes(), builder.ENTRYPOINT)
                self.assertEqual(command[-1], '-S')
                Path(command[command.index('-o') + 1]).write_bytes(b'// mock ESM bundle\nglobalThis.Java = Java;\n')
                if drift_during_compile:
                    (source / 'lib/vm.js').write_bytes(b'late drift')
            else:
                self.fail('unexpected command: ' + repr(command))
            return subprocess.CompletedProcess(command, 0, '', '')

        with mock.patch.object(builder, 'download_archive', side_effect=download), \
                mock.patch.object(builder, 'resolve_tool', return_value=Path(sys.executable)), \
                mock.patch.object(builder, 'npm_command', return_value=['npm']), \
                mock.patch.object(builder, 'run_checked', side_effect=run):
            manifest = builder.build(self.out, work_dir=self.work)
        return manifest, commands

    def test_mocked_build_publishes_manifest_only_for_verified_patched_input(self):
        manifest, commands = self.run_mock_build()
        stem = 'nianchu-java-bridge-7.0.13'
        self.assertEqual(manifest['author'], 'nianchu')
        self.assertEqual(manifest['compiler_version'], '16.4.1')
        self.assertEqual(manifest['bridge_after'][TARGET], EXPECTED_PATCHED_SHA256['7.0.13'])
        self.assertEqual(manifest['patch_files'], [TARGET])
        self.assertFalse(manifest['runtime_tested'])
        self.assertFalse(manifest['system_frida_modified'])
        self.assertFalse(manifest['python_packages_modified'])
        self.assertFalse(manifest['npm_lifecycle_scripts_executed'])
        for name, metadata in manifest['artifacts'].items():
            data = (self.out / name).read_bytes()
            self.assertEqual(bridge.digest(data), metadata['sha256'])
            self.assertEqual(len(data), metadata['size'])
        self.assertEqual(json.loads((self.out / (stem + '.manifest.json')).read_bytes()), manifest)
        self.assertEqual(manifest['build_work_directory'], str(self.work.resolve()))
        self.assertEqual(manifest['typescript_config'], builder.TSCONFIG)
        self.assertEqual(json.loads((self.work / 'project/tsconfig.json').read_bytes()), builder.TSCONFIG)
        package = json.loads((self.work / 'project/package.json').read_bytes())
        self.assertEqual(package['dependencies']['frida-java-bridge'], 'file:../downloads/bridge/package.tgz')
        self.assertEqual(package['dependencies']['frida-compile'], 'file:../downloads/compiler/package.tgz')
        for command in commands:
            if 'install' in command or 'ci' in command:
                self.assertIn('--ignore-scripts', command)
        self.assertTrue(any('ci' in command for command in commands))

    def test_failed_npm_command_does_not_publish_success_artifacts(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_mock_build(fail_install=True)
        self.assertEqual(list(self.out.glob('*.manifest.json')), [])
        self.assertEqual(list(self.out.glob('*.js')), [])

    def test_compile_time_package_drift_prevents_manifest_and_release_bundle(self):
        with self.assertRaisesRegex(ValueError, 'source drift'):
            self.run_mock_build(drift_during_compile=True)
        self.assertEqual(list(self.out.glob('*.manifest.json')), [])
        self.assertEqual(list(self.out.glob('*.js')), [])


if __name__ == '__main__':
    unittest.main()
