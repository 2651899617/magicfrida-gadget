#!/usr/bin/env python3
"""Audit ELF files and apply the reference symbol/rodata/raw-string rewrite recipe."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import sys

# These are protocol audit counters, not exclusions from the rewrite recipe.
PROTECTED = (b're.frida', b're/frida', b'frida:rpc', b'frida_agent_main')
RODATA_STRINGS = ('FridaScriptEngine', 'GLib-GIO', 'GDBusProxy', 'GumScript')
PATH_STRINGS = (
    'gum-js-loop', 'gmain', 'gdbus', 'frida-gadget', './lib/android', 'gadget',
    'art::JavaVMExt::AddGlobalRef', 'art::ClassLinker::VisitClassLoaders',
    'pool_spawner', 'pool_spoiler', 'frida-inject',
)
CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
LIEF_VERSION = '0.17.6'
KINDS = ('agent', 'helper', 'server', 'gadget')
AGENT_ENTRY = 'nianchu_agent_main'
GADGET_ENTRY = 'nianchu_gadget_init'


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Layout:
    """Small bounded reader used independently of LIEF's builder and name lookup."""
    def __init__(self, data):
        self.data = data
        if len(data) < 52 or data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5:7] != b'\x01\x01':
            raise ValueError('expected little-endian ELF32/ELF64')
        self.bits = 64 if data[4] == 2 else 32
        header_fmt = '<16sHHIQQQIHHHHHH' if self.bits == 64 else '<16sHHIIIIIHHHHHH'
        self.bounds(0, struct.calcsize(header_fmt))
        header = struct.unpack_from(header_fmt, data)
        _, self.kind, self.machine, version, self.entry, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, shstrings = header
        if self.kind not in (2, 3) or version != 1 or ehsize != (64 if self.bits == 64 else 52):
            raise ValueError('expected executable/shared ELF object')
        if self.machine not in ({183, 62} if self.bits == 64 else {40, 3}):
            raise ValueError('unsupported Android ELF architecture')
        if not phnum or phnum == 0xffff or phsize != (56 if self.bits == 64 else 32):
            raise ValueError('unsupported program table')
        if not shnum or shsize != (64 if self.bits == 64 else 40) or shstrings == 0xffff or shstrings >= shnum:
            raise ValueError('unsupported section table')
        self.bounds(phoff, phsize * phnum)
        self.bounds(shoff, shsize * shnum)
        self.programs = []
        for i in range(phnum):
            if self.bits == 64:
                p = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
            else:
                v = struct.unpack_from('<IIIIIIII', data, phoff + i * phsize)
                p = (v[0], v[6], v[1], v[2], v[3], v[4], v[5], v[7])
            self.bounds(p[2], p[5])
            if p[0] == 1 and p[5] > p[6]:
                raise ValueError('PT_LOAD filesz exceeds memsz')
            if p[7] not in (0, 1) and p[7] & (p[7] - 1):
                raise ValueError('invalid segment alignment')
            self.programs.append(p)
        if not any(p[0] == 1 for p in self.programs):
            raise ValueError('missing PT_LOAD')
        self.sections = [struct.unpack_from('<IIQQQQIIQQ' if self.bits == 64 else '<IIIIIIIIII',
                                            data, shoff + i * shsize) for i in range(shnum)]
        for s in self.sections:
            if s[1] != 8:
                self.bounds(s[4], s[5])
            if s[6] >= shnum:
                raise ValueError('invalid section link')
        self.extent = max([ehsize, phoff + phsize * phnum, shoff + shsize * shnum] +
                          [p[2] + p[5] for p in self.programs] +
                          [s[4] + s[5] for s in self.sections if s[1] != 8])
        names = self.sections[shstrings]
        if names[1] != 3:
            raise ValueError('section names are not a string table')
        self.by_name = {}
        for s in self.sections:
            name = self.string(names, s[0])
            if name and name in self.by_name:
                raise ValueError('duplicate ELF section name')
            self.by_name[name] = s
        self.symbols = {}
        for s in self.sections:
            if s[1] not in (2, 11):
                continue
            size = 24 if self.bits == 64 else 16
            if s[9] != size or s[5] % size or self.sections[s[6]][1] != 3:
                raise ValueError('invalid symbol table')
            symbols = []
            for pos in range(s[4], s[4] + s[5], size):
                if self.bits == 64:
                    name, info, other, index, value, length = struct.unpack_from('<IBBHQQ', data, pos)
                else:
                    name, value, length, info, other, index = struct.unpack_from('<IIIBBH', data, pos)
                symbols.append({'name': self.string(self.sections[s[6]], name), 'value': value,
                                'size': length, 'binding': info >> 4, 'type': info & 15,
                                'visibility': other & 3, 'index': index})
            self.symbols[s[1]] = symbols

    def bounds(self, offset, size):
        if offset < 0 or size < 0 or offset > len(self.data) or size > len(self.data) - offset:
            raise ValueError('ELF range exceeds file boundary')

    def string(self, section, offset):
        if offset >= section[5]:
            raise ValueError('invalid symbol or section name')
        start = section[4] + offset
        end = self.data.find(b'\0', start, section[4] + section[5])
        if end < 0:
            raise ValueError('unterminated ELF string')
        return self.data[start:end].decode('utf-8', errors='surrogateescape')

    def u32(self, offset):
        self.bounds(offset, 4)
        return struct.unpack_from('<I', self.data, offset)[0]

    def exported(self, name):
        result = [s for s in self.symbols.get(11, []) if s['name'] == name and s['index'] != 0
                  and s['binding'] in (1, 2) and s['visibility'] == 0]
        if len(result) != 1:
            raise ValueError('expected one defined dynamic export: ' + name)
        return result[0]


def audit(data, arm64=True):
    layout = Layout(data)
    if arm64 and (layout.bits != 64 or layout.machine != 183):
        raise ValueError('expected AArch64 executable/shared object')
    return {'architecture': {183: 'aarch64', 40: 'arm', 62: 'x86_64', 3: 'x86'}[layout.machine],
            'elf_type': layout.kind, 'size': len(data), 'sha256': digest(data), 'binary_modified': False,
            'checks': 'ELF bounds only; no runtime, hash-table lookup or protocol handshake claim',
            'protected_markers': {token.decode(): data.count(token) for token in PROTECTED}}


def sysv_hash(name):
    h = 0
    for byte in name.encode('utf-8', errors='surrogateescape'):
        h = (h << 4) + byte
        high = h & 0xf0000000
        if high:
            h ^= high >> 24
        h &= ~high
    return h & 0xffffffff


def gnu_hash(name):
    h = 5381
    for byte in name.encode('utf-8', errors='surrogateescape'):
        h = ((h << 5) + h + byte) & 0xffffffff
    return h


def verify_hashes(data):
    layout = Layout(data)
    symbols = layout.symbols.get(11, [])
    dynamic = {}
    for segment in layout.programs:
        if segment[0] != 2:
            continue
        stride = 16 if layout.bits == 64 else 8
        if segment[5] % stride:
            raise ValueError('invalid PT_DYNAMIC size')
        for position in range(segment[2], segment[2] + segment[5], stride):
            tag, value = struct.unpack_from('<qQ' if layout.bits == 64 else '<iI', data, position)
            if tag == 0:
                break
            dynamic[tag] = value
    for tag, name in ((4, '.hash'), (0x6ffffef5, '.gnu.hash'), (5, '.dynstr'), (6, '.dynsym')):
        section = layout.by_name.get(name)
        # A stale hash section may remain after the linker disables its tag.
        # Only PT_DYNAMIC selects loader hash tables; dynstr/dynsym stay required.
        if section is not None and (tag in dynamic or tag in (5, 6)) and dynamic.get(tag) != section[3]:
            raise ValueError('dynamic pointer does not match ' + name)
        if section is None and tag in dynamic:
            raise ValueError('dynamic pointer has no section: ' + name)
    if '.dynstr' in layout.by_name and dynamic.get(10) != layout.by_name['.dynstr'][5]:
        raise ValueError('DT_STRSZ does not match .dynstr')
    checked = {}
    section = layout.by_name.get('.hash')
    if section and 4 in dynamic:
        nbucket, nchain = struct.unpack_from('<II', data, section[4])
        if not nbucket or nchain != len(symbols) or 8 + 4 * (nbucket + nchain) > section[5]:
            raise ValueError('invalid SysV hash table')
        buckets = section[4] + 8
        chains = buckets + 4 * nbucket
        for i, symbol in enumerate(symbols):
            if not symbol['name'] or symbol['binding'] == 0:
                continue
            current = layout.u32(buckets + 4 * (sysv_hash(symbol['name']) % nbucket))
            visited = set()
            while current:
                if current >= nchain or current in visited:
                    raise ValueError('invalid SysV hash chain')
                visited.add(current)
                if current == i:
                    break
                current = layout.u32(chains + 4 * current)
            if not current:
                raise ValueError('SysV hash lookup failed: ' + symbol['name'])
        checked['sysv'] = 'verified'
    section = layout.by_name.get('.gnu.hash')
    if section and 0x6ffffef5 in dynamic:
        nbucket, symoffset, bloom_size, shift = struct.unpack_from('<IIII', data, section[4])
        word_size, word_bits = layout.bits // 8, layout.bits
        minimum = 16 + word_size * bloom_size + 4 * nbucket
        if not nbucket or not bloom_size or bloom_size & (bloom_size - 1) or symoffset > len(symbols) or minimum > section[5]:
            raise ValueError('invalid GNU hash table')
        bloom = section[4] + 16
        buckets = bloom + word_size * bloom_size
        chains = buckets + 4 * nbucket
        for i in range(symoffset, len(symbols)):
            name = symbols[i]['name']
            if not name:
                continue
            h = gnu_hash(name)
            word_offset = bloom + word_size * ((h // word_bits) % bloom_size)
            word = struct.unpack_from('<Q' if layout.bits == 64 else '<I', data, word_offset)[0]
            mask = (1 << (h % word_bits)) | (1 << ((h >> shift) % word_bits))
            if word & mask != mask:
                raise ValueError('GNU bloom lookup failed: ' + name)
            current = layout.u32(buckets + 4 * (h % nbucket))
            if current < symoffset:
                raise ValueError('GNU bucket lookup failed: ' + name)
            while current < len(symbols):
                chain_offset = chains + 4 * (current - symoffset)
                if chain_offset + 4 > section[4] + section[5]:
                    raise ValueError('GNU chain exceeds section')
                value = layout.u32(chain_offset)
                if current == i and value & 0xfffffffe == h & 0xfffffffe:
                    break
                if value & 1:
                    raise ValueError('GNU hash lookup failed: ' + name)
                current += 1
            else:
                raise ValueError('invalid GNU hash chain')
        checked['gnu'] = 'verified'
    return {'tables': checked, 'dynamic_symbols': len(symbols), 'lookup': 'verified' if checked else 'not-present'}


def rebuild_gnu_hash(data):
    """Rebuild in place without reordering dynsym/relocation/version indexes."""
    layout = Layout(data)
    section = layout.by_name.get('.gnu.hash')
    if section is None:
        return data
    _, symoffset, bloom_size, shift = struct.unpack_from('<IIII', data, section[4])
    symbols = layout.symbols.get(11, [])
    word_size, word_bits = layout.bits // 8, layout.bits
    required = 16 + word_size * bloom_size + 4 + 4 * (len(symbols) - symoffset)
    if (not bloom_size or bloom_size & (bloom_size - 1) or symoffset > len(symbols)
            or shift >= 32 or required > section[5]):
        raise ValueError('unsupported GNU hash rebuild layout')
    output = bytearray(data)
    base = section[4]
    output[base:base + section[5]] = b'\0' * section[5]
    struct.pack_into('<IIII', output, base, 1, symoffset, bloom_size, shift)
    bloom = base + 16
    bucket = bloom + word_size * bloom_size
    struct.pack_into('<I', output, bucket, symoffset if len(symbols) > symoffset else 0)
    word_format = '<Q' if layout.bits == 64 else '<I'
    for index in range(symoffset, len(symbols)):
        value = gnu_hash(symbols[index]['name'])
        position = bloom + word_size * ((value // word_bits) % bloom_size)
        word = struct.unpack_from(word_format, output, position)[0]
        word |= (1 << (value % word_bits)) | (1 << ((value >> shift) % word_bits))
        struct.pack_into(word_format, output, position, word)
        struct.pack_into('<I', output, bucket + 4 + 4 * (index - symoffset),
                         (value & 0xfffffffe) | (index == len(symbols) - 1))
    return bytes(output)


def embedded_elf_ranges(data):
    """Locate nested ELF objects so an outer pass cannot mutate their bytes."""
    result = []
    position = data.find(b'\x7fELF', 4)
    while position != -1:
        try:
            nested = Layout(data[position:])
            result.append((position, position + nested.extent))
        except (ValueError, struct.error):
            pass
        position = data.find(b'\x7fELF', position + 4)
    return result


def replace_equal(data, old, new):
    if len(old) != len(new):
        raise ValueError('raw ELF replacements must preserve byte length')
    protected = embedded_elf_ranges(data)
    output = bytearray(data)
    count = 0
    position = data.find(old)
    while position != -1:
        end = position + len(old)
        if not any(position < stop and end > start for start, stop in protected):
            output[position:end] = new
            count += 1
        position = data.find(old, end)
    return bytes(output), count


def rewrite(data, kind, seed=None):
    if kind not in KINDS:
        raise ValueError('unsupported rewrite kind')
    before = audit(data, arm64=False)
    import lief
    if not lief.__version__.startswith(LIEF_VERSION + '-') and lief.__version__ != LIEF_VERSION:
        raise ValueError('expected LIEF ' + LIEF_VERSION + '; got ' + lief.__version__)
    binary = lief.ELF.parse(data)
    if binary is None:
        raise ValueError('LIEF ELF parse failed')
    seed = seed or os.environ.get('NIANCHU_ELF_REWRITE_SEED') or before['sha256']
    rng = random.Random(seed + ':' + kind + ':' + before['sha256'])
    sample = lambda length: ''.join(rng.sample(CHARSET, length))
    random_name = sample(5)
    symbol_changes = []
    for symbol in binary.symbols:
        old = symbol.name
        new = AGENT_ENTRY if old == 'frida_agent_main' else old.replace('frida', random_name).replace('FRIDA', random_name)
        if old != new:
            symbol.name = new
            symbol_changes.append({'old': old, 'new': new})
    # The author's fixed libwzdnb-agent is replaced by our full brand through
    # the ELF dynamic string builder, so the two extra bytes never shift code.
    brands = []
    for entry in binary.dynamic_entries:
        if isinstance(entry, lief.ELF.DynamicSharedObject) and 'libfrida-agent' in entry.name:
            old = entry.name
            entry.name = old.replace('libfrida-agent', 'libnianchu-agent')
            brands.append({'old': old, 'new': entry.name, 'scope': 'DT_SONAME'})
    rodata_changes = []
    nested_ranges = embedded_elf_ranges(data)
    for section in binary.sections:
        if section.name != '.rodata':
            continue
        for token in RODATA_STRINGS:
            value = sample(len(token))
            for offset in section.search_all(token):
                start = section.offset + offset
                if any(start < stop and start + len(token) > begin for begin, stop in nested_ranges):
                    continue
                binary.patch_address(section.virtual_address + offset, list(value.encode()), lief.Binary.VA_TYPES.VA)
                rodata_changes.append({'old': token, 'new': value, 'section': section.name,
                                       'file_offset_before': section.offset + offset,
                                       'virtual_address_before': section.virtual_address + offset})
    libraries = list(binary.libraries)
    config = lief.ELF.Builder.config_t()
    stage = binary.write_to_bytes(config)
    path_changes = []
    for token in PATH_STRINGS:
        value = sample(len(token))
        stage, count = replace_equal(stage, token.encode(), value.encode())
        path_changes.append({'old': token, 'new': value, 'count': count, 'scope': 'whole-ELF-equal-length'})
    # Whole-file replacements can touch .dynstr/.strtab. Parse and rebuild
    # afterwards so GNU/SysV hashes and relocation symbol indexes agree.
    rebuilt = lief.ELF.parse(stage)
    if rebuilt is None:
        raise ValueError('LIEF parse after raw rewrite failed')
    output = rebuild_gnu_hash(rebuilt.write_to_bytes(config))
    after = audit(output, arm64=False)
    hashes = verify_hashes(output)
    final = lief.ELF.parse(output)
    if final is None or list(final.libraries) != libraries:
        raise ValueError('ELF dynamic dependency contract changed')
    symbol_map = {item['old']: item['new'] for item in symbol_changes}
    original_init = GADGET_ENTRY if kind == 'gadget' else AGENT_ENTRY if kind == 'agent' else None
    init = original_init
    if init:
        for item in path_changes:
            init = init.replace(item['old'], item['new'])
        if kind == 'agent':
            Layout(output).exported(init)
        elif any(s.name == GADGET_ENTRY for s in binary.dynamic_symbols):
            Layout(output).exported(init)
        else:
            init = None
    for old, new in symbol_map.items():
        if any(s.name == old for s in final.symbols):
            raise ValueError('old renamed symbol remains: ' + old)
    report = {'schema': 1, 'profile': 'nianchu-reference-elf', 'kind': kind,
              'lief_version': LIEF_VERSION, 'seed': seed, 'before': before, 'after': after,
              'binary_modified': data != output, 'random_symbol_token': random_name,
              'symbols': symbol_changes, 'rodata': rodata_changes, 'raw_strings': path_changes,
              'brand_strings': brands, 'hash_tables': hashes, 'initialization_symbol': init,
              'needed': libraries, 'runtime_tested': False,
              'nested_elf_ranges': embedded_elf_ranges(data),
              'residual_markers': {s: output.count(s.encode()) for s in (*RODATA_STRINGS, *PATH_STRINGS, 'libfrida-agent')}}
    return output, report


def validate_rewrite_report(data, report, kind):
    if (not isinstance(report, dict) or report.get('schema') != 1 or report.get('profile') != 'nianchu-reference-elf'
            or report.get('kind') != kind or report.get('lief_version') != LIEF_VERSION
            or report.get('runtime_tested') is not False or report.get('binary_modified') is not True):
        raise ValueError('invalid ELF rewrite report')
    after = audit(data, arm64=False)
    if report.get('after') != after or report.get('hash_tables') != verify_hashes(data):
        raise ValueError('ELF rewrite report hash/size/table mismatch')
    before = report.get('before')
    if not isinstance(before, dict) or before.get('sha256') == after['sha256'] or not isinstance(before.get('sha256'), str):
        raise ValueError('invalid original ELF identity')
    if len(before['sha256']) != 64 or any(c not in '0123456789abcdef' for c in before['sha256']):
        raise ValueError('invalid original ELF hash')
    raw = report.get('raw_strings')
    if not isinstance(raw, list) or [s.get('old') for s in raw] != list(PATH_STRINGS):
        raise ValueError('incomplete reference raw-string recipe')
    for item in raw:
        value = item.get('new')
        if (not isinstance(value, str) or len(value) != len(item['old']) or len(set(value)) != len(value)
                or any(c not in CHARSET for c in value) or type(item.get('count')) is not int or item['count'] < 0):
            raise ValueError('invalid equal-length random string record')
    init = report.get('initialization_symbol')
    layout = Layout(data)
    if kind == 'agent' and init != AGENT_ENTRY:
        raise ValueError('agent initialization symbol mismatch')
    expected_gadget = GADGET_ENTRY
    for item in raw:
        expected_gadget = expected_gadget.replace(item['old'], item['new'])
    if kind == 'gadget':
        exports = [s for s in layout.symbols.get(11, []) if s['name'] == expected_gadget and s['index'] != 0]
        if init != (expected_gadget if exports else None):
            raise ValueError('Gadget initialization symbol mismatch')
    if kind in ('helper', 'server') and init is not None:
        raise ValueError('unexpected initialization symbol')
    if init is not None:
        layout.exported(init)
    import lief
    parsed = lief.ELF.parse(data)
    if parsed is None or report.get('needed') != list(parsed.libraries):
        raise ValueError('ELF dependency report mismatch')
    residual = {s: data.count(s.encode()) for s in (*RODATA_STRINGS, *PATH_STRINGS, 'libfrida-agent')}
    if report.get('residual_markers') != residual:
        raise ValueError('ELF residual marker report mismatch')
    if not isinstance(report.get('symbols'), list) or not isinstance(report.get('rodata'), list):
        raise ValueError('invalid rewrite records')
    final_names = {s.name for s in parsed.symbols}
    for item in report['symbols']:
        if not isinstance(item, dict) or not isinstance(item.get('new'), str):
            raise ValueError('invalid symbol rewrite record')
        name = item['new']
        for replacement in raw:
            name = name.replace(replacement['old'], replacement['new'])
        if name not in final_names:
            raise ValueError('rewritten symbol missing: ' + name)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--rewrite', action='store_true')
    parser.add_argument('--kind', choices=KINDS)
    args = parser.parse_args(argv)
    try:
        if args.artifact.is_symlink() or not args.artifact.is_file():
            raise ValueError('artifact must be a regular non-symlink file')
        if args.report and args.report.resolve() == args.artifact.resolve():
            raise ValueError('report cannot overwrite artifact')
        if args.rewrite and (not args.kind or not args.report):
            raise ValueError('rewrite requires --kind and --report')
        data = args.artifact.read_bytes()
        if args.rewrite:
            # Embedders recopy the original ELF on incremental builds while
            # leaving the previous sidecar in place. Accept only either identity.
            saved = None
            if args.report.exists():
                saved = json.loads(args.report.read_text(encoding='utf-8'))
                if isinstance(saved, dict) and saved.get('after') == audit(data, arm64=False):
                    validate_rewrite_report(data, saved, args.kind)
                    result = saved
                else:
                    if not isinstance(saved, dict) or saved.get('before') != audit(data, arm64=False):
                        raise ValueError('ELF matches neither original nor rewritten report identity')
                    output, result = rewrite(data, args.kind, seed=saved.get('seed'))
                    # Reconstructing the recorded output must also validate the
                    # complete old report before replacing either file.
                    validate_rewrite_report(output, saved, args.kind)
            else:
                output, result = rewrite(data, args.kind)
            if saved is None or result is not saved:
                temporary = args.artifact.with_name(args.artifact.name + '.nianchu-rewrite-tmp')
                report_temporary = args.report.with_name(args.report.name + '.nianchu-rewrite-tmp')
                mode = args.artifact.stat().st_mode & 0o777
                try:
                    args.report.parent.mkdir(parents=True, exist_ok=True)
                    with temporary.open('xb') as stream:
                        stream.write(output)
                    temporary.chmod(mode)
                    with report_temporary.open('x', encoding='utf-8', newline='\n') as stream:
                        json.dump(result, stream, indent=2)
                        stream.write('\n')
                    if args.artifact.read_bytes() != data:
                        raise ValueError('input ELF changed during rewriting')
                    os.replace(temporary, args.artifact)
                    try:
                        os.replace(report_temporary, args.report)
                    except OSError:
                        # Restore the input if publishing its sidecar fails.
                        with temporary.open('xb') as stream:
                            stream.write(data)
                        temporary.chmod(mode)
                        os.replace(temporary, args.artifact)
                        raise
                finally:
                    if temporary.exists():
                        temporary.unlink()
                    if report_temporary.exists():
                        report_temporary.unlink()

        else:
            result = audit(data)
            if args.report:
                args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'kind': args.kind, 'size': result.get('after', result)['size'],
                          'sha256': result.get('after', result)['sha256'],
                          'binary_modified': result['binary_modified'],
                          'initialization_symbol': result.get('initialization_symbol')}, indent=2))
    except (OSError, ValueError, struct.error, ImportError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
