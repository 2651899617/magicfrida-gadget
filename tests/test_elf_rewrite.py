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
    @staticmethod
    def raw_name_fixture(reference_tag=None, symbol_suffix=False):
        data = bytearray(fixture())
        old, new = elf.RAW_AGENT_OLD.encode() + b'\0', elf.RAW_AGENT_NEW.encode() + b'\0'
        prefix = b'\0frida_one\0frida_two\0'
        strings = prefix + new + old
        start = 1024
        data[start:start + len(strings)] = strings
        # Move the allocated dynamic string table into unused mapped space.
        struct.pack_into('<Q', data, 64 + 32, 1280)
        struct.pack_into('<Q', data, 64 + 40, 1280)
        struct.pack_into('<Q', data, 1536 + 2 * 64 + 16, start)
        struct.pack_into('<Q', data, 1536 + 2 * 64 + 24, start)
        struct.pack_into('<Q', data, 1536 + 2 * 64 + 32, len(strings))
        tags = [(6, 448), (5, start), (10, len(strings)), (4, 600),
                (0x6ffffef5, 640), (14, len(prefix))]
        old_index = len(prefix) + len(new)
        if reference_tag is not None:
            tags.append((reference_tag, old_index + 3))
        tags.append((0, 0))
        data[800:944] = b'\0' * 144
        for index, pair in enumerate(tags):
            struct.pack_into('<qQ', data, 800 + 16 * index, *pair)
        struct.pack_into('<Q', data, 120 + 32, 16 * len(tags))
        struct.pack_into('<Q', data, 120 + 40, 16 * len(tags))
        struct.pack_into('<Q', data, 1536 + 6 * 64 + 32, 16 * len(tags))
        if symbol_suffix:
            struct.pack_into('<I', data, 448 + 24, old_index + 3)
            # No stale hash is allowed to hide a reference-validation mistake.
            name = elf.Layout(bytes(data)).symbols[11][1]['name']
            self_check = name == elf.RAW_AGENT_SIGNATURE
            if not self_check:
                raise AssertionError('suffix fixture does not reference old raw name')
        return bytes(data), start + old_index

    @classmethod
    def gnu_version_fixture(cls, null_sections=False):
        """Two-record verneed/verdef chains, including non-first aux names."""
        data, old_position = cls.raw_name_fixture()
        data = bytearray(data)
        layout = elf.Layout(data)
        shoff = struct.unpack_from('<Q', data, 40)[0]
        strings = layout.by_name['.dynstr']
        content = bytearray(data[strings[4]:strings[4] + strings[5]])
        indices = {elf.RAW_AGENT_NEW: content.index(elf.RAW_AGENT_NEW.encode() + b'\0')}
        for name in ('libc.so', 'LIBC_1.0', 'LIBC_2.0', 'libm.so', 'LIBM_1.0',
                     'AGENT_1.0', 'AGENT_2.0'):
            indices[name] = len(content)
            content.extend(name.encode() + b'\0')
        data[strings[4]:strings[4] + len(content)] = content
        struct.pack_into('<Q', data, shoff + 2 * 64 + 32, len(content))
        names = layout.by_name['.shstrtab']
        content = data[names[4]:names[4] + names[5]] + b'.gnu.version_r\0.gnu.version_d\0.gnu.version\0'
        data[names[4]:names[4] + len(content)] = content
        struct.pack_into('<Q', data, shoff + 64 + 32, len(content))
        need, definition, versym = 1216, 1312, 1408
        data.extend(b'\0' * (3 * 64))
        struct.pack_into('<H', data, 60, len(layout.sections) + 3)
        for index, (name, kind, offset, size, link, info, align, stride) in enumerate((
                ('.gnu.version_r', 0 if null_sections else 0x6ffffffe, need, 80, 2, 2, 4, 0),
                ('.gnu.version_d', 0 if null_sections else 0x6ffffffd, definition, 64, 2, 2, 4, 0),
                ('.gnu.version', 0x6fffffff, versym, 6, 3, 0, 2, 2)), len(layout.sections)):
            struct.pack_into('<IIQQQQIIQQ', data, shoff + index * 64,
                             content.index(name.encode() + b'\0'), kind, 2, offset, offset,
                             size, link, info, align, stride)
        struct.pack_into('<Q', data, 64 + 32, shoff)
        struct.pack_into('<Q', data, 64 + 40, shoff)
        # DT_STRSZ includes all appended strings, not the padding before verneed.
        tags = [(tag, struct.unpack_from('<Q', data, shoff + 2 * 64 + 32)[0] if tag == 10 else value)
                for _, tag, value in elf.dynamic_entries(data, layout) if tag]
        tags += [(1, indices['libc.so']), (1, indices['libm.so'])]
        if not null_sections:
            tags += [(0x6ffffffe, need), (0x6fffffff, 2),
                     (0x6ffffffc, definition), (0x6ffffffd, 2), (0x6ffffff0, versym)]
        tags.append((0, 0))
        data[800:1024] = b'\0' * 224
        for index, pair in enumerate(tags):
            struct.pack_into('<qQ', data, 800 + index * 16, *pair)
        for field in (120 + 32, 120 + 40, shoff + 6 * 64 + 32):
            struct.pack_into('<Q', data, field, 16 * len(tags))
        struct.pack_into('<HHIII', data, need, 1, 2, indices['libc.so'], 16, 48)
        for offset, name, version, following in ((16, 'LIBC_1.0', 4, 16), (32, 'LIBC_2.0', 5, 0),
                                                  (64, 'LIBM_1.0', 6, 0)):
            struct.pack_into('<IHHII', data, need + offset, elf.sysv_hash(name), 0, version,
                             indices[name], following)
        struct.pack_into('<HHIII', data, need + 48, 1, 1, indices['libm.so'], 16, 0)
        struct.pack_into('<HHHHIII', data, definition, 1, 0, 2, 2, elf.sysv_hash('AGENT_1.0'), 20, 36)
        struct.pack_into('<II', data, definition + 20, indices['AGENT_1.0'], 8)
        struct.pack_into('<II', data, definition + 28, indices[elf.RAW_AGENT_NEW], 0)
        struct.pack_into('<HHHHIII', data, definition + 36, 1, 0, 3, 1, elf.sysv_hash('AGENT_2.0'), 20, 0)
        struct.pack_into('<II', data, definition + 56, indices['AGENT_2.0'], 0)
        struct.pack_into('<HHH', data, versym, 0, 2, 0x8003)
        fields = [('version-file', need + 4, 'libc.so'),
                  ('version-name', need + 24, 'LIBC_1.0'), ('version-name', need + 40, 'LIBC_2.0'),
                  ('version-file', need + 52, 'libm.so'), ('version-name', need + 72, 'LIBM_1.0'),
                  ('version-name', definition + 20, 'AGENT_1.0'),
                  ('version-name', definition + 28, elf.RAW_AGENT_NEW),
                  ('version-name', definition + 56, 'AGENT_2.0')]
        references = [{'index': indices[name], 'value': name, 'scope': scope, 'field': field,
                       'begin': strings[4] + indices[name],
                       'end': strings[4] + indices[name] + len(name.encode()) + 1}
                      for scope, field, name in fields]
        return bytes(data), old_position, references

    def test_gnu_version_cleanup_preserves_all_references_and_symbol_indexes(self):
        for null_sections in (False, True):
            with self.subTest(null_sections=null_sections):
                data, position, expected = self.gnu_version_fixture(null_sections)
                before = elf.Layout(data)
                contract = elf.dynstr_references(data)
                self.assertEqual([ref for ref in contract['references']
                                  if ref['scope'].startswith('version-')], expected)
                self.assertEqual(before.by_name['.gnu.version_r'][1], 0 if null_sections else 0x6ffffffe)
                self.assertEqual(before.by_name['.gnu.version_d'][1], 0 if null_sections else 0x6ffffffd)
                version_tags = {0x6ffffffe, 0x6fffffff, 0x6ffffffc, 0x6ffffffd, 0x6ffffff0}
                self.assertEqual({tag for _, tag, _ in contract['dynamic']} & version_tags,
                                 set() if null_sections else version_tags)
                output, records = elf.scrub_unused_raw_agent_names(data)
                self.assertEqual(output, data[:position] + b'\0' * 22 + data[position + 22:])
                self.assertEqual(records, [{'old': elf.RAW_AGENT_OLD, 'offset': position, 'size': 22,
                                           'scope': '.dynstr-unreferenced-NUL-string', 'action': 'zero-fill'}])
                self.assertEqual(elf.dynstr_references(output), contract)
                after = elf.Layout(output)
                self.assertEqual(after.sections, before.sections)
                self.assertEqual(after.programs, before.programs)
                self.assertEqual(after.symbols, before.symbols)
                versym = before.by_name['.gnu.version']
                self.assertEqual(struct.unpack_from('<HHH', output, versym[4]), (0, 2, 0x8003))
                self.assertEqual(elf.verify_hashes(output), elf.verify_hashes(data))
                self.assertEqual(elf.raw_agent_identity(output, True)['old_substring_occurrences'], 0)
                self.assertEqual(elf.scrub_unused_raw_agent_names(output), (output, []))

    def test_gnu_version_file_aux_and_suffix_references_prevent_cleanup(self):
        for null_sections in (False, True):
            original, position, references = self.gnu_version_fixture(null_sections)
            old_index = position - elf.Layout(original).by_name['.dynstr'][4]
            for reference in references:
                for suffix in (0, 3):
                    with self.subTest(null_sections=null_sections, field=reference['field'], suffix=suffix):
                        data = bytearray(original)
                        struct.pack_into('<I', data, reference['field'], old_index + suffix)
                        contract = elf.dynstr_references(bytes(data))
                        actual = next(ref for ref in contract['references'] if ref['field'] == reference['field'])
                        self.assertEqual(actual['scope'], reference['scope'])
                        self.assertEqual(actual['value'], elf.RAW_AGENT_OLD[suffix:])
                        self.assertEqual(actual['begin'], position + suffix)
                        self.assertEqual(actual['end'], position + 22)
                        with self.assertRaisesRegex(ValueError, 'referenced old raw Agent name must not be erased'):
                            elf.scrub_unused_raw_agent_names(bytes(data))

    def test_gnu_version_malformed_chains_prevent_cleanup(self):
        for null_sections in (False, True):
            original, _, _ = self.gnu_version_fixture(null_sections)
            layout = elf.Layout(original)
            for name, count, auxiliary, following, last, last_auxiliary, last_next in (
                    ('.gnu.version_r', 2, 8, 12, 48, 8, 76),
                    ('.gnu.version_d', 6, 12, 16, 36, 12, 60)):
                section = layout.by_name[name]
                cases = [('version', 0, '<H', 2), ('zero-count', count, '<H', 0),
                         ('short-count', count, '<H', 1), ('long-count', count, '<H', 3),
                         ('aux-outside-section', auxiliary, '<I', section[5]),
                         ('next-outside-section', following, '<I', section[5]),
                         ('unterminated-aux', last_next, '<I', 8),
                         ('aux-overlaps-header', last + last_auxiliary, '<I', 0),
                         ('next-overlaps-header', following, '<I', 4),
                         ('next-overlaps-earlier-aux', following, '<I', 16 if name.endswith('_r') else 20),
                         ('aux-chain-overlap', 28 if name.endswith('_r') else 24, '<I', 4)]
                for case, offset, fmt, value in cases:
                    with self.subTest(null_sections=null_sections, section=name, case=case):
                        data = bytearray(original)
                        struct.pack_into(fmt, data, section[4] + offset, value)
                        with self.assertRaises(ValueError):
                            elf.dynstr_references(bytes(data))
                        with self.assertRaises(ValueError):
                            elf.scrub_unused_raw_agent_names(bytes(data))

    def test_abandoned_dynstr_cleanup_preserves_layout_loader_and_hashes(self):
        data, position = self.raw_name_fixture()
        output, records = elf.scrub_unused_raw_agent_names(data)
        self.assertEqual(output, data[:position] + b'\0' * 22 + data[position + 22:])
        self.assertEqual(elf.dynstr_references(data), elf.dynstr_references(output))
        self.assertEqual(elf.verify_hashes(data), elf.verify_hashes(output))
        self.assertEqual(elf.Layout(data).sections, elf.Layout(output).sections)
        self.assertEqual(elf.Layout(data).programs, elf.Layout(output).programs)
        self.assertEqual(elf.raw_agent_identity(output, True)['old_substring_occurrences'], 0)
        self.assertEqual(records, [{'old': elf.RAW_AGENT_OLD, 'offset': position, 'size': 22,
                                   'scope': '.dynstr-unreferenced-NUL-string', 'action': 'zero-fill'}])
        self.assertEqual(elf.scrub_unused_raw_agent_names(output), (output, []))

    def test_dynstr_cleanup_rejects_live_soname_needed_and_suffix_references(self):
        for tag in (1, 14, 29, 0x7fffffff):
            with self.subTest(tag=tag):
                data, _ = self.raw_name_fixture(reference_tag=tag)
                with self.assertRaisesRegex(ValueError, 'active nianchu SONAME|referenced old raw'):
                    elf.scrub_unused_raw_agent_names(data)
        data, _ = self.raw_name_fixture(symbol_suffix=True)
        with self.assertRaisesRegex(ValueError, 'referenced old raw'):
            elf.scrub_unused_raw_agent_names(data)

    def test_raw_name_gate_covers_substrings_outside_dynstr_and_nested_agents(self):
        data = identifier_fixture([b'prefix' + elf.RAW_AGENT_SIGNATURE.encode() + b'suffix'])
        self.assertEqual(elf.scrub_unused_raw_agent_names(data), (data, []))
        with self.assertRaisesRegex(ValueError, 'old raw Agent name remains'):
            elf.raw_agent_identity(data)
        nested, _ = self.raw_name_fixture()
        data = identifier_fixture([b'outer'], nested=nested)
        self.assertEqual(elf.scrub_unused_raw_agent_names(data), (data, []))
        with self.assertRaisesRegex(ValueError, 'old raw Agent name remains'):
            elf.raw_agent_identity(data)

    def test_previous_schema2_report_cannot_bypass_raw_name_gate(self):
        with self.assertRaisesRegex(ValueError, 'invalid ELF rewrite report'):
            elf.validate_rewrite_report(fixture(), {'schema': 2, 'profile': 'nianchu-functional-identifiers-v2'}, 'helper')

    def test_lief_final_write_cleanup_report_and_incremental_validation(self):
        try:
            import lief  # noqa: F401
        except ImportError:
            self.skipTest('rewrite requires pinned LIEF')
        data, _ = self.raw_name_fixture()
        output, report = elf.rewrite(data, 'helper', seed='dynstr-regression')
        self.assertEqual(report['raw_agent_identity']['old_substring_occurrences'], 0)
        self.assertEqual(len(report['dynstr_cleanup']), 1)
        self.assertIs(elf.validate_rewrite_report(output, report, 'helper'), report)
        corrupted = dict(report, dynstr_cleanup=[dict(report['dynstr_cleanup'][0], offset=0)])
        with self.assertRaisesRegex(ValueError, 'cleanup record'):
            elf.validate_rewrite_report(output, corrupted, 'helper')

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
