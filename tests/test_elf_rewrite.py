#!/usr/bin/env python3
"""Offline ELF regression tests; these do not execute Android code."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('elf_rewrite', ROOT / 'patches/rename.py')
elf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf)


def fixture(active_gnu=True):
    """ELF64 with a trailing section table, SysV hash and spare GNU buckets."""
    data = bytearray(1536 + 7 * 64)
    names = b'\0.shstrtab\0.dynstr\0.dynsym\0.hash\0.gnu.hash\0.dynamic\0'
    strings = b'\0frida_one\0frida_two\0'
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0,
                     b'\x7fELF\x02\x01\x01' + b'\0' * 9,
                     3, 183, 1, 0, 64, 1536, 0, 64, 56, 2, 64, 7, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 1024, 1024, 4096)
    tags = [(6, 448), (5, 384), (10, len(strings)), (4, 600)]
    if active_gnu:
        tags.append((0x6ffffef5, 640))
    tags.append((0, 0))
    struct.pack_into('<IIQQQQQQ', data, 120, 2, 6, 800, 800, 800,
                     16 * len(tags), 16 * len(tags), 8)
    data[256:256 + len(names)] = names
    data[384:384 + len(strings)] = strings
    for index, offset in ((1, 1), (2, 11)):
        struct.pack_into('<IBBHQQ', data, 448 + index * 24, offset, 0x12, 0, 1, 1024 + index, 1)
    struct.pack_into('<IIIIII', data, 600, 1, 3, 1, 0, 2, 0)
    struct.pack_into('<IIII', data, 640, 3, 1, 1, 5)
    for i, tag in enumerate(tags):
        struct.pack_into('<qQ', data, 800 + i * 16, *tag)
    sections = [('.shstrtab', 3, 256, len(names), 0, 0),
                ('.dynstr', 3, 384, len(strings), 0, 0),
                ('.dynsym', 11, 448, 72, 2, 24),
                ('.hash', 5, 600, 24, 3, 4),
                ('.gnu.hash', 0x6ffffff6, 640, 44, 3, 0),
                ('.dynamic', 6, 800, 16 * len(tags), 2, 16)]
    for i, (name, kind, offset, size, link, entrysize) in enumerate(sections, 1):
        struct.pack_into('<IIQQQQIIQQ', data, 1536 + i * 64,
                         names.index(name.encode()), kind, 2, offset, offset, size, link, 0, 8, entrysize)
    return elf.rebuild_gnu_hash(bytes(data))


def identifier_fixture(tokens, nested=b''):
    """Small real ELF layout with one allocated string section and optional asset."""
    names = b'\0.shstrtab\0.rodata\0'
    content = b'\0' + b'\0'.join(tokens) + b'\0'
    offset, shoff = 256, 128
    data = bytearray(offset + len(names) + len(content) + len(nested))
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0,
                     b'\x7fELF\x02\x01\x01' + b'\0' * 9,
                     3, 183, 1, 0, 64, shoff, 0, 64, 56, 1, 64, 2, 1)
    # A separate section-name table is appended before the two-table layout.
    # Three sections need 192 bytes; place them after the string payload.
    shoff = (len(data) + 7) & ~7
    data.extend(b'\0' * (shoff + 3 * 64 - len(data)))
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<H', data, 60, 3)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 4, 0, 0, 0, shoff, shoff, 4096)
    data[offset:offset + len(names)] = names
    string_start = offset + len(names)
    data[string_start:string_start + len(content)] = content
    data[string_start + len(content):string_start + len(content) + len(nested)] = nested
    struct.pack_into('<IIQQQQIIQQ', data, shoff + 64, 1, 3, 0, 0, offset, len(names), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, shoff + 128, names.index(b'.rodata'), 1, 2,
                     string_start, string_start, len(content) + len(nested), 0, 0, 1, 0)
    return bytes(data)


class ElfRewriteTests(unittest.TestCase):
    def test_internal_mapping_is_stable_bounded_and_preserves_public_contracts(self):
        public = [b'Friday', b'FridaAgentSession', b'FridaScriptRuntime', b'FRIDA_SCRIPT_RUNTIME_QJS',
                  *[name.encode() for name in elf.FUNCTIONAL_STRINGS]]
        data = identifier_fixture([b'FridaAgentRunner', b'FridaAgentRunner',
                                   b'prefixFridaAgentRunner', b'FridaAgentRunnerSuffix',
                                   b'frida_agent_runner_close_all_sessions_co', *public])
        output, records = elf.rewrite_identifiers(data)
        self.assertEqual(len(output), len(data))
        self.assertEqual(output.count(b'NnchuAgentRunner\0'), 2)
        self.assertIn(b'prefixFridaAgentRunner\0', output)
        self.assertIn(b'FridaAgentRunnerSuffix\0', output)
        self.assertIn(b'nnchu_agent_runner_close_all_sessions_co\0', output)
        for token in public:
            self.assertEqual(output.count(token), data.count(token))
        self.assertEqual(len(set(elf.TYPE_MAP.values())), len(elf.TYPE_MAP))
        runner = next(item for item in records if item['old'] == 'FridaAgentRunner')
        self.assertEqual(runner['count'], 2)
        self.assertEqual(elf.rewrite_identifiers(output)[0], output)
        for suffix in (b'version-16', b'version-17'):
            self.assertEqual(elf.rewrite_identifiers(data + suffix)[0].count(b'NnchuAgentRunner\0'), 2)
        self.assertNotIn('FridaAgentStopReason', elf.TYPE_MAP)

    def test_identifier_pass_protects_embedded_payload_and_reports_source_miss(self):
        nested = identifier_fixture([b'FridaAgentRunner', b'FridaAgentStopReason'])
        data = identifier_fixture([b'FridaAgentRunner'], nested=nested)
        output, records = elf.rewrite_identifiers(data)
        self.assertEqual(elf.embedded_elf_ranges(data), elf.embedded_elf_ranges(output))
        for start, stop in elf.embedded_elf_ranges(data):
            self.assertEqual(data[start:stop], output[start:stop])
        self.assertEqual(next(item for item in records if item['old'] == 'FridaAgentRunner')['count'], 1)
        self.assertEqual(elf.identifier_audit(output)['source_old_occurrences']['FridaAgentStopReason'], 1)
        with self.assertRaisesRegex(ValueError, 'embedded arm64 and arm32'):
            elf.verify_embedded_agents(output)

    def test_old_rewrite_report_profile_rejected(self):
        with self.assertRaisesRegex(ValueError, 'invalid ELF rewrite report'):
            elf.validate_rewrite_report(fixture(), {'schema': 1, 'profile': 'nianchu-reference-elf'}, 'helper')

    def test_single_bucket_gnu_rebuild_preserves_symbol_indexes(self):
        data = fixture()
        before = elf.Layout(data).symbols[11]
        renamed = data.replace(b'frida_one', b'other_one').replace(b'frida_two', b'other_two')
        with self.assertRaises(ValueError):
            elf.verify_hashes(renamed)
        result = elf.rebuild_gnu_hash(renamed)
        self.assertEqual(elf.verify_hashes(result)['tables'], {'sysv': 'verified', 'gnu': 'verified'})
        self.assertEqual(struct.unpack_from('<I', result, 640)[0], 1)
        self.assertEqual([s['value'] for s in elf.Layout(result).symbols[11]], [s['value'] for s in before])
        self.assertEqual(elf.rebuild_gnu_hash(result), result)
        self.assertEqual(len(result), len(data))

    def test_inactive_gnu_section_is_not_a_loader_hash(self):
        data = bytearray(fixture(active_gnu=False))
        data[640:684] = b'\xff' * 44
        self.assertEqual(elf.verify_hashes(bytes(data))['tables'], {'sysv': 'verified'})

    def test_active_hash_pointer_mismatch_rejected(self):
        data = bytearray(fixture())
        struct.pack_into('<Q', data, 800 + 4 * 16 + 8, 644)
        with self.assertRaisesRegex(ValueError, 'dynamic pointer does not match .gnu.hash'):
            elf.verify_hashes(bytes(data))

    def test_dynamic_hash_without_section_rejected(self):
        data = bytearray(fixture())
        # Remove the section name while keeping the active tag.
        struct.pack_into('<I', data, 1536 + 5 * 64, 0)
        with self.assertRaisesRegex(ValueError, 'dynamic pointer has no section'):
            elf.verify_hashes(bytes(data))

    def test_nested_section_table_is_protected(self):
        nested = bytearray(fixture())
        # Null section's unused sh_addr holds a marker past every section payload.
        nested[1536 + 16:1536 + 22] = b'gadget'
        outer = fixture() + b'gadget' + bytes(nested) + b'gadget'
        start = len(fixture()) + 6
        self.assertEqual(elf.embedded_elf_ranges(outer), [(start, start + len(nested))])
        result, count = elf.replace_equal(outer, b'gadget', b'ABCDEF')
        self.assertEqual(count, 2)
        self.assertEqual(result[start:start + len(nested)], nested)
        self.assertEqual(len(result), len(outer))

    def test_unequal_replacement_rejected(self):
        with self.assertRaisesRegex(ValueError, 'preserve byte length'):
            elf.replace_equal(fixture(), b'gadget', b'longer-name')

    def test_patched_embedders_repeat_both_asset_slots(self):
        # The inputs model ELF64; ARM32 machine-code coverage comes from CI.
        for version in ('16.7.19', '17.25.2'):
            profile = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
            for kind in ('helper', 'agent'):
                with self.subTest(version=version, kind=kind), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / 'input.so'
                    source.write_bytes(fixture().replace(b'frida_one', b'other_one'))
                    entry = next(item for item in profile['files']
                                 if item['path'].endswith('/embed-' + kind + '.py'))
                    text = (ROOT / 'tests/fixtures' / version / entry['path']).read_text(encoding='utf-8')
                    for edit in entry['edits']:
                        self.assertEqual(text.count(edit['old']), edit['count'])
                        text = text.replace(edit['old'], edit['new'])
                    namespace = {'__name__': 'embed_test'}
                    exec(compile(text, entry['path'], 'exec'), namespace)
                    resource_calls = []

                    def run(command, check):
                        if command[0] == 'resource-compiler':
                            resource_calls.append(command)
                        else:
                            self.assertEqual(elf.main(command[3:]), 0)

                    args = ['embed', 'android', 'arm64', 'gnu', 'resource-compiler',
                            '>>>', '', '<<<', str(root), str(root / 'private'), 'resources',
                            str(source), str(source), '', '']
                    if kind == 'agent':
                        args += ['', '']
                    with mock.patch.dict(os.environ, {'NIANCHU_ELF_REWRITER': str(ROOT / 'patches/rename.py')}), \
                            mock.patch('subprocess.run', side_effect=run), \
                            mock.patch.object(elf, 'AGENT_ENTRY', 'other_one'), \
                            contextlib.redirect_stdout(io.StringIO()):
                        namespace['main'](args)
                        before = {path.name: path.read_bytes() for path in (root / 'private').iterdir()}
                        namespace['main'](args)
                        self.assertEqual(before, {path.name: path.read_bytes()
                                                  for path in (root / 'private').iterdir()})
                        self.assertEqual(len(resource_calls), 2)
                        self.assertEqual(len(list((root / 'private').glob('*.rewrite.json'))), 2)

    def test_incremental_embed_recopy_and_report_publish_rollback(self):
        try:
            import lief  # noqa: F401
        except ImportError:
            self.skipTest('rewrite requires pinned LIEF')
        for kind in ('helper', 'agent'):
            for arch in ('32', '64'):
                with self.subTest(kind=kind, arch=arch), tempfile.TemporaryDirectory() as directory:
                    artifact = Path(directory) / ('frida-' + kind + '-' + arch)
                    sidecar = Path(str(artifact) + '.rewrite.json')
                    original = fixture()
                    # Agent reports require the supported initialization export.
                    if kind == 'agent':
                        original = original.replace(b'frida_one', b'other_one')
                        with mock.patch.object(elf, 'AGENT_ENTRY', 'other_one'):
                            self._check_incremental_rewrite(artifact, sidecar, original, kind)
                    else:
                        self._check_incremental_rewrite(artifact, sidecar, original, kind)

    def _check_incremental_rewrite(self, artifact, sidecar, original, kind):
        args = [str(artifact), '--rewrite', '--kind', kind, '--report', str(sidecar)]
        artifact.write_bytes(original)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(elf.main(args), 0)
            rewritten, saved = artifact.read_bytes(), sidecar.read_bytes()
            self.assertNotEqual(original, rewritten)
            self.assertEqual(elf.main(args), 0)
            self.assertEqual(artifact.read_bytes(), rewritten)
            # embed-agent/embed-helper overwrite the destination on each run.
            artifact.write_bytes(original)
            self.assertEqual(elf.main(args), 0)
            self.assertEqual(artifact.read_bytes(), rewritten)
            self.assertEqual(sidecar.read_bytes(), saved)
            artifact.write_bytes(original)
            replace = os.replace

            def fail_report(source, destination):
                if destination == sidecar:
                    raise OSError('injected sidecar publication failure')
                return replace(source, destination)

            with mock.patch.object(elf.os, 'replace', side_effect=fail_report):
                self.assertEqual(elf.main(args), 1)
            self.assertEqual(artifact.read_bytes(), original)
            self.assertEqual(sidecar.read_bytes(), saved)
            self.assertEqual(elf.main(args), 0)
            artifact.write_bytes(original + b'unrecognized-build')
            self.assertEqual(elf.main(args), 1)
            self.assertEqual(artifact.read_bytes(), original + b'unrecognized-build')
            self.assertEqual(sidecar.read_bytes(), saved)
            artifact.write_bytes(original)
            corrupt = json.loads(saved)
            corrupt['kind'] = 'server'
            sidecar.write_text(json.dumps(corrupt), encoding='utf-8')
            self.assertEqual(elf.main(args), 1)
            self.assertEqual(artifact.read_bytes(), original)

    def test_four_real_gadgets_in_memory(self):
        artifact_root = Path(os.environ.get('NIANCHU_ELF_SMOKE_ROOT', str(ROOT.parent / 'work')))
        files = [artifact_root / ('nianchu-build-41951726835-' + version) / 'files/out' / variant /
                 ('nianchu-gadget-' + ('zygisk-' if variant == 'zygisk' else '') + version + '-android-arm64.so')
                 for version in ('16.7.19', '17.25.2') for variant in ('compatible', 'zygisk')]
        if not all(path.is_file() for path in files):
            self.skipTest('real Gadget artifacts unavailable; set NIANCHU_ELF_SMOKE_ROOT')
        try:
            import lief  # noqa: F401
        except ImportError:
            self.skipTest('real rewrite requires pinned LIEF')
        for path in files:
            with self.subTest(artifact=str(path)):
                data = path.read_bytes()
                output, report = elf.rewrite(data, 'gadget', seed='memory-smoke')
                self.assertIs(elf.validate_rewrite_report(output, report, 'gadget'), report)
                self.assertFalse(report['runtime_tested'])
                self.assertEqual(report['before']['sha256'], elf.digest(data))
                self.assertEqual(elf.digest(path.read_bytes()), elf.digest(data))
                self.assertIn('sysv', report['hash_tables']['tables'])
                if path.parent.name == 'zygisk':
                    elf.Layout(output).exported(report['initialization_symbol'])
                else:
                    self.assertIsNone(report['initialization_symbol'])
                for start, stop in elf.embedded_elf_ranges(data):
                    self.assertIn(data[start:stop], output)


if __name__ == '__main__':
    unittest.main()
