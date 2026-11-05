#!/usr/bin/env python3
"""Offline ELF regression tests; these do not execute Android code."""
import importlib.util
import os
from pathlib import Path
import struct
import unittest

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


class ElfRewriteTests(unittest.TestCase):
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
