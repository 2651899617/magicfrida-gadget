#!/usr/bin/env python3
"""Exact full-readable-PT_LOAD model and publication threshold regression."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('readable_elf', ROOT / 'patches/rename.py')
elf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf)


def fixture(segments, bits=64):
    """Build independent ELF32/64 PT_LOADs whose order differs from offsets."""
    header_size, program_size, section_size = (64, 56, 64) if bits == 64 else (52, 32, 40)
    names = b'\0.shstrtab\0'
    program_offset = header_size
    names_offset = (header_size + len(segments) * program_size + 15) & ~15
    cursor = names_offset + len(names) + 16
    placed = []
    for flags, payload in reversed(segments):
        placed.append((flags, cursor, bytes(payload)))
        cursor += len(payload) + 16
    placed.reverse()
    section_offset = (cursor + 15) & ~15
    data = bytearray(section_offset + 2 * section_size)
    ident = b'\x7fELF' + bytes((2 if bits == 64 else 1, 1, 1)) + b'\0' * 9
    header_format = '<16sHHIQQQIHHHHHH' if bits == 64 else '<16sHHIIIIIHHHHHH'
    struct.pack_into(header_format, data, 0, ident, 3, 183 if bits == 64 else 40, 1,
                     0, program_offset, section_offset, 0, header_size, program_size,
                     len(segments), section_size, 2, 1)
    data[names_offset:names_offset + len(names)] = names
    for index, (flags, offset, payload) in enumerate(placed):
        if bits == 64:
            values = (1, flags, offset, 0x1000 + offset, 0, len(payload), len(payload) + 4096, 1)
            struct.pack_into('<IIQQQQQQ', data, program_offset + index * program_size, *values)
        else:
            values = (1, offset, 0x1000 + offset, 0, len(payload), len(payload) + 4096, flags, 1)
            struct.pack_into('<IIIIIIII', data, program_offset + index * program_size, *values)
        data[offset:offset + len(payload)] = payload
    struct.pack_into('<IIQQQQIIQQ' if bits == 64 else '<IIIIIIIIII',
                     data, section_offset + section_size, 1, 3, 0, 0,
                     names_offset, len(names), 0, 0, 1, 0)
    return bytes(data)


class ReadableLoadTests(unittest.TestCase):
    def test_original_ascii_boundaries(self):
        cases = (
            (b'\0frida\0ABCDE', [5, 5], 1),
            (b'\x01frida\x02ABCDE', [5, 5], 1),
            (b'\tfrida\nABCDE', [5, 5], 1),
            (b'\0frid', [], 0),
            (b'frid\x01', [4], 0),
            (b'frida', [5], 1),
            (b'abc\0ABCDE', [5], 0),
            (b'A' * 253 + b'frida' + b'B' * 254 + b'\0ABCDE', [256, 256, 5], 0),
            (b'fridaFRIDA\0ABCDE', [10, 5], 1),
            (b'\x12frida:rpc\x01ABCDE', [9, 5], 1),
        )
        for payload, lengths, hits in cases:
            with self.subTest(payload=payload[:24]):
                callbacks = list(elf.enumerate_readable_segment(payload, 0, len(payload)))
                self.assertEqual([len(item[1]) for item in callbacks], lengths)
                self.assertEqual(sum(elf.READABLE_LOAD_MARKER.search(item[1]) is not None for item in callbacks), hits)

    def test_threshold20_allowed_threshold21_rejected_for_both_architectures(self):
        for bits in (32, 64):
            for count in (20, 21):
                data = fixture([(4, b'FrIdA\0' * count + b'ABCDE')], bits)
                result = elf.readable_load_audit(data)
                self.assertEqual(result['total_frida_matching_callbacks'], count)
                self.assertEqual(result['below_threshold'], count == 20)
                self.assertEqual(result['architecture'], 'arm' if bits == 32 else 'aarch64')
                for kind in ('agent', 'gadget'):
                    if count == 20:
                        self.assertEqual(elf.require_readable_load_budget(data, kind), result)
                    else:
                        with self.assertRaisesRegex(ValueError, 'signature budget exceeded: 21 >= 21'):
                            elf.require_readable_load_budget(data, kind)
                # Server/helper reports retain real counts; only embedded Agents have the app threshold.
                self.assertEqual(elf.require_readable_load_budget(data, 'helper'), result)

    def test_nonzero_callbacks_required_but_zero_marker_matches_allowed(self):
        for bits in (32, 64):
            empty_scan = fixture([(4, b'\0' * 32)], bits)
            result = elf.readable_load_audit(empty_scan)
            self.assertGreater(result['total_readable_load_filesz'], 0)
            self.assertEqual(result['total_printable_string_callbacks'], 0)
            self.assertEqual(result['total_frida_matching_callbacks'], 0)
            for kind in ('agent', 'gadget'):
                with self.subTest(bits=bits, kind=kind):
                    with self.assertRaisesRegex(ValueError, 'no printable callbacks'):
                        elf.require_readable_load_budget(empty_scan, kind)
            self.assertEqual(elf.require_readable_load_budget(empty_scan, 'helper'), result)
            clean_scan = fixture([(4, b'nianchu-cache\0ABCDE')], bits)
            clean = elf.readable_load_audit(clean_scan)
            self.assertGreater(clean['total_printable_string_callbacks'], 0)
            self.assertEqual(clean['total_frida_matching_callbacks'], 0)
            for kind in ('agent', 'gadget'):
                self.assertEqual(elf.require_readable_load_budget(clean_scan, kind), clean)

    def test_program_header_order_filesz_and_read_permission(self):
        data = fixture([(4, b'frida-first\0'), (0, b'frida-unreadable\0'),
                        (5, b'frida-second\0'), (6, b'Frida-third\0')])
        result = elf.readable_load_audit(data)
        self.assertEqual([row['program_header_index'] for row in result['matches']], [0, 2, 3])
        self.assertEqual([row['text'] for row in result['matches']], ['frida-first', 'frida-second', 'Frida-third'])
        offsets = [row['file_offset'] for row in result['matches']]
        self.assertGreater(offsets[0], offsets[1])
        self.assertEqual(result['total_readable_load_filesz'], sum(len(p) for f, p in
                         [(4, b'frida-first\0'), (5, b'frida-second\0'), (6, b'Frida-third\0')]))
        self.assertEqual(result['total_frida_matching_callbacks'], 3)
        self.assertEqual(result['sha256'], elf.digest(data))

    def test_count_is_callbacks_not_marker_occurrences(self):
        result = elf.readable_load_audit(fixture([(4, b'fridaFRIDAfrida\0frida\0')]))
        self.assertEqual(result['total_frida_matching_callbacks'], 2)
        self.assertEqual(result['total_marker_occurrences_inside_matching_callbacks'], 4)
        self.assertEqual(result['matches'][0]['marker_occurrences'], 3)

    def test_synthetic_report_v3_rejected_before_content_validation(self):
        data = fixture([(4, b'ABCDE')])
        with self.assertRaisesRegex(ValueError, 'invalid ELF rewrite report'):
            elf.validate_rewrite_report(data, {'schema': 3, 'profile': 'nianchu-functional-identifiers-v3'}, 'agent')

    def test_bad_ranges_and_empty_readable_segments_rejected(self):
        for start, size in ((-1, 1), (0, -1), (0, 6)):
            with self.assertRaisesRegex(ValueError, 'file boundary'):
                list(elf.enumerate_readable_segment(b'ABCDE', start, size))
        for data in (fixture([(0, b'frida')]), fixture([(4, b'')])):
            with self.assertRaisesRegex(ValueError, 'nonempty readable PT_LOAD'):
                elf.readable_load_audit(data)

    def test_report_mismatch_rejected_with_actual_hashes_preserved(self):
        # The existing ELF fixture exercises real LIEF and report validation, with a small budget.
        try:
            import lief  # noqa: F401
        except ImportError:
            self.skipTest('requires pinned LIEF')
        fixture_spec = importlib.util.spec_from_file_location('report_fixture', ROOT / 'tests/test_elf_rewrite.py')
        fixtures = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixtures)
        output, report = elf.rewrite(fixtures.fixture(), 'helper', seed='readable-report')
        self.assertEqual(report['schema'], 4)
        self.assertEqual(report['readable_load_strings'], elf.readable_load_audit(output))
        self.assertIs(elf.validate_rewrite_report(output, report, 'helper'), report)
        damaged = copy.deepcopy(report)
        damaged['readable_load_strings']['total_frida_matching_callbacks'] += 1
        with self.assertRaisesRegex(ValueError, 'readable PT_LOAD signature report mismatch'):
            elf.validate_rewrite_report(output, damaged, 'helper')
        damaged = copy.deepcopy(report)
        damaged.pop('readable_load_strings')
        with self.assertRaisesRegex(ValueError, 'readable PT_LOAD signature report mismatch'):
            elf.validate_rewrite_report(output, damaged, 'helper')


if __name__ == '__main__':
    unittest.main()
