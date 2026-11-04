#!/usr/bin/env python3
"""Read-only ELF audit. The old whole-file binary renaming is disabled."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

PROTECTED = (b're.frida', b're/frida', b'frida:rpc', b'frida_agent_main')


def audit(data):
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('expected little-endian ELF64')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    _, kind, machine, version, _, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, shstrings = header
    if kind not in (2, 3) or machine != 183 or version != 1 or ehsize != 64:
        raise ValueError('expected AArch64 executable/shared object')
    if not phnum or phnum == 0xffff or phsize != 56:
        raise ValueError('unsupported program table')
    if not shnum or shsize != 64 or shstrings == 0xffff or shstrings >= shnum:
        raise ValueError('unsupported section table')

    def bounds(offset, size):
        if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
            raise ValueError('ELF range exceeds file boundary')

    bounds(phoff, phsize * phnum)
    bounds(shoff, shsize * shnum)
    loads = 0
    for index in range(phnum):
        p = struct.unpack_from('<IIQQQQQQ', data, phoff + index * phsize)
        bounds(p[2], p[5])
        if p[0] == 1:
            loads += 1
            if p[5] > p[6]:
                raise ValueError('PT_LOAD filesz exceeds memsz')
        if p[7] not in (0, 1) and p[7] & (p[7] - 1):
            raise ValueError('invalid segment alignment')
    if not loads:
        raise ValueError('missing PT_LOAD')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize) for i in range(shnum)]
    for section in sections:
        if section[1] != 8:
            bounds(section[4], section[5])
        if section[6] >= shnum:
            raise ValueError('invalid section link')
    string_section = sections[shstrings]
    if string_section[1] != 3:
        raise ValueError('section names are not a string table')
    strings = data[string_section[4]:string_section[4] + string_section[5]]
    for section in sections:
        name = section[0]
        if name >= len(strings) or strings.find(b'\0', name) < 0:
            raise ValueError('invalid section name')
        if section[1] in (2, 11):
            if section[9] != 24 or section[5] % 24 or sections[section[6]][1] != 3:
                raise ValueError('invalid symbol table')
            names = sections[section[6]]
            table = data[names[4]:names[4] + names[5]]
            for pos in range(section[4], section[4] + section[5], 24):
                symbol_name = struct.unpack_from('<I', data, pos)[0]
                if symbol_name >= len(table) or table.find(b'\0', symbol_name) < 0:
                    raise ValueError('invalid symbol name')
    return {
        'architecture': 'aarch64', 'elf_type': kind, 'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(), 'binary_modified': False,
        'checks': 'ELF bounds only; no runtime, hash-table lookup or protocol handshake claim',
        'protected_markers': {token.decode(): data.count(token) for token in PROTECTED},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    try:
        result = audit(args.artifact.read_bytes())
        text = json.dumps(result, indent=2) + '\n'
        if args.report:
            if args.report.resolve() == args.artifact.resolve():
                raise ValueError('report cannot overwrite artifact')
            args.report.write_text(text, encoding='utf-8')
        print(text, end='')
    except (OSError, ValueError, struct.error) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
