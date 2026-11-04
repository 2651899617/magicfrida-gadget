#!/usr/bin/env python3
"""Build an arm64 Zygisk wrapper; packaging requires final Gadget provenance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    if result.stdout:
        print(result.stdout, end='')
    if result.stderr:
        print(result.stderr, end='', file=sys.stderr)
    result.check_returncode()
    return result.stdout


def payload_from_manifest(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    module = importlib.util.spec_from_file_location('collector', ROOT / 'scripts/collect_artifacts.py')
    collector = importlib.util.module_from_spec(module)
    module.loader.exec_module(collector)
    version = data['version']
    expected = next(v for v in json.loads((ROOT / 'versions.json').read_text(encoding='utf-8'))['versions']
                    if v['version'] == version)
    collector.validate_source_report(data['source'], expected)
    collector.validate_patch_report(data['patches'], expected)
    if 'zygisk-loader' not in data['patches']['features']:
        raise ValueError('module requires zygisk-loader source feature')
    artifact = data['artifacts']['gadget']
    name = artifact['file']
    if Path(name).name != name or name != 'nianchu-gadget-zygisk-' + version + '-android-arm64.so':
        raise ValueError('invalid final Gadget name')
    payload = path.parent / name
    if payload.is_symlink() or not payload.is_file():
        raise ValueError('payload must be a regular file')
    binary = payload.read_bytes()
    audit = collector.elf.audit(binary)
    if audit['sha256'] != artifact['sha256'] or audit['size'] != artifact['size']:
        raise ValueError('Gadget provenance hash/size mismatch')
    if artifact['final_target'] != expected['targets']['gadget']:
        raise ValueError('not a final Gadget target')
    if version.encode() not in binary or data.get('binary_modified') is not False:
        raise ValueError('invalid Gadget manifest/version')
    return payload, binary, data


def build(ndk, out, manifest=None):
    if out.exists():
        raise ValueError('build output must not exist')
    props = (ndk / 'source.properties').read_text(encoding='utf-8')
    revision = re.search(r'^Pkg\.Revision\s*=\s*(\S+)\s*$', props, re.M)
    if not revision or revision[1] not in ('25.2.9519653', '29.0.14206865'):
        raise ValueError('unverified wrapper NDK revision')
    host = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
    suffix = '.exe' if os.name == 'nt' else ''
    tools = ndk / 'toolchains/llvm/prebuilt' / host / 'bin'
    payload, binary, provenance = payload_from_manifest(manifest) if manifest else (None, b'', None)
    if provenance:
        expected_ndk = next(v['ndk_revision'] for v in json.loads((ROOT / 'versions.json').read_text(encoding='utf-8'))['versions']
                            if v['version'] == provenance['version'])
        if revision[1] != expected_ndk:
            raise ValueError('wrapper NDK does not match selected Frida version')
    out.mkdir(parents=True)
    header = out / 'payload.hpp'
    digest = hashlib.sha256(binary).digest()
    header.write_text('#pragma once\n#include <stdint.h>\nstatic const uint64_t NIANCHU_PAYLOAD_SIZE = ' +
                      str(len(binary)) + ';\nstatic const unsigned char NIANCHU_PAYLOAD_SHA256[32] = {' +
                      ','.join(str(x) for x in digest) + '};\n', encoding='utf-8')
    library = out / 'arm64-v8a.so'
    compiler = tools / ('clang++' + suffix)
    run(compiler, '--target=aarch64-linux-android26', '-std=c++17', '-shared', '-fPIC', '-O2',
        '-fno-exceptions', '-fno-rtti', '-fno-threadsafe-statics', '-nostdlib++', '-fvisibility=hidden', '-Wall', '-Wextra', '-Werror',
        '-Wl,--no-undefined', '-Wl,-z,relro,-z,now', '-I' + str(ROOT / 'module/include'),
        '-I' + str(out), ROOT / 'module/src/module.cpp', '-llog', '-ldl', '-o', library)
    readelf = tools / ('llvm-readelf' + suffix)
    symbols = run(readelf, '--dyn-syms', '--wide', library)
    if not re.search(r'\bGLOBAL\s+DEFAULT\s+\d+\s+zygisk_module_entry\s*$', symbols, re.M):
        raise ValueError('real exported Zygisk module entry missing')
    dynamic = run(readelf, '--dynamic', library)
    needed = re.findall(r'\(NEEDED\).*?\[([^]]+)\]', dynamic)
    if not needed or set(needed) - {'libc.so', 'libdl.so', 'liblog.so', 'libm.so'}:
        raise ValueError('unexpected native dependency: ' + repr(needed))
    if payload:
        payload_symbols = run(readelf, '--dyn-syms', '--wide', payload)
        if not re.search(r'\bGLOBAL\s+DEFAULT\s+\d+\s+nianchu_gadget_init(?:@@?\S+)?\s*$', payload_symbols, re.M):
            raise ValueError('final Gadget explicit initialization entry missing')
    report = {'schema': 1, 'compile_only': manifest is None, 'ndk_revision': revision[1],
              'api': 5, 'android_min_api': 26, 'dependencies': needed,
              'wrapper_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
              'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted((ROOT / 'module').rglob('*')) if p.is_file()},
              'gadget_manifest': provenance, 'zygisk_load': 'not-tested', 'app_detection': 'not-tested'}
    (out / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    if payload:
        version = provenance['version']
        name = out / ('nianchu-zygisk-' + version + '-android-arm64.zip')
        with zipfile.ZipFile(name, 'w', zipfile.ZIP_DEFLATED) as archive:
            for source, destination in ((library, 'zygisk/arm64-v8a.so'),
                                        (payload, 'gadget/libnianchu-gadget.so'),
                                        (ROOT / 'module/targets.conf', 'targets.conf'),
                                        (ROOT / 'module/customize.sh', 'customize.sh'),
                                        (out / 'build-report.json', 'build-report.json'),
                                        (ROOT / 'module/README.md', 'README.md'),
                                        (ROOT / 'module/include/zygisk.hpp', 'NOTICE/zygisk.hpp')):
                archive.write(source, destination)
            for source in sorted((ROOT / 'NOTICE').rglob('*')):
                if source.is_file():
                    archive.write(source, 'NOTICE/' + source.relative_to(ROOT / 'NOTICE').as_posix())
            archive.writestr('module.prop', 'id=nianchu_gadget\nname=nianchu Gadget ' + version +
                             '\nversion=' + version + '\nversionCode=1\nauthor=nianchu\n' +
                             'description=Explicit target scoped Gadget loader; runtime validation required\n')
    print('PASS: wrapper build and ELF checks; ' + ('compile-only, no Gadget/zip' if not payload else 'package built, not device tested'))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    try:
        build(args.ndk.resolve(), args.out.resolve(), args.manifest.resolve() if args.manifest else None)
    except (OSError, ValueError, KeyError, StopIteration, subprocess.CalledProcessError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
