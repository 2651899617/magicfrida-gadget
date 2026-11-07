#!/usr/bin/env python3
"""Outline one Android Frida C/C++ object without modifying its source tree.

Meson's Android compiler array is prefixed with::

    PYTHON -I WRAPPER --config CONFIG --language c|cpp --build-root BUILD -- CC ...

Only core/gum object compilations are intercepted. Compiler probes, assembly,
third-party projects, and links are executed once with their original argv.
The outliner is a separate trusted script, never imported from the source tree.
"""
import sys

if __name__ == '__main__' and not sys.flags.isolated:
    raise SystemExit('string outline compiler must be launched with Python -I')

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

WRAPPER_VERSION = '1.1'
CONFIG_SCHEMA = 1
CPP_HEADER_POLICY = 'explicit-cpp-header-origins-v1'
_SOURCE_LANGUAGES = {'.c': 'c', '.C': 'cpp', '.cc': 'cpp', '.cp': 'cpp',
                     '.cpp': 'cpp', '.cxx': 'cpp', '.c++': 'cpp'}
_VALUE_OPTIONS = {
    '-o', '-x', '-I', '-D', '-U', '-B', '-F', '-L', '-l', '-isystem', '-iquote',
    '-idirafter', '-include', '-imacros', '-include-pch', '-iprefix',
    '-iwithprefix', '-iwithprefixbefore', '-isysroot', '--sysroot', '-target',
    '--target', '-arch', '-Xclang', '-Xpreprocessor', '-Xassembler', '-Xlinker',
    '-MF', '-MT', '-MQ', '-MJ', '-dependency-file', '-resource-dir',
    '-gcc-toolchain', '--gcc-toolchain', '-fmodule-map-file', '-fmodule-file',
    '-working-directory', '--serialize-diagnostics', '-serialize-diagnostics',
}
_DEP_MODES = {'-MD', '-MMD'}
_DEP_SWITCHES = _DEP_MODES | {'-MP', '-MG', '-M', '-MM'}
_DEP_VALUES = {'-MF', '-MT', '-MQ', '-dependency-file'}


class OutlineBuildError(RuntimeError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def absolute_path(value, cwd=None):
    path = Path(value)
    if not path.is_absolute():
        path = (Path.cwd() if cwd is None else cwd) / path
    return path.absolute()


def is_within(path, root):
    return path.resolve().is_relative_to(root.resolve())


def outside_source(path, source_root, label):
    if is_within(path, source_root):
        raise OutlineBuildError(f'{label} must be outside the complete source tree: {path}')


def write_atomic(path, data):
    """Replace an owned state/report file, never follow an existing symlink."""
    path = Path(path)
    if path.is_symlink():
        raise OutlineBuildError(f'refusing to replace symlink: {path}')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix='.' + path.name + '-', dir=path.parent,
                                     delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_config(path):
    path = absolute_path(path)
    config = json.loads(path.read_text(encoding='utf-8'))
    if config.get('schema') != CONFIG_SCHEMA or config.get('wrapper_version') != WRAPPER_VERSION:
        raise OutlineBuildError('unsupported string outline configuration/version')
    source_root = absolute_path(config['source_root']).resolve()
    outside_source(path, source_root, 'configuration')
    for name in ('python', 'wrapper', 'outliner', 'work_root', 'report_dir', 'identity_cache'):
        value = absolute_path(config[name])
        outside_source(value, source_root, name)
        config[name] = str(value)
    config['source_root'] = str(source_root)
    config['config_path'] = str(path)
    if config['response_format'] not in {'gnu', 'windows'}:
        raise OutlineBuildError('unsupported response-file format')
    if config['version'] not in {'16.7.19', '17.25.2'}:
        raise OutlineBuildError('unsupported pinned Frida version')
    if config.get('cpp_header_policy') != CPP_HEADER_POLICY:
        raise OutlineBuildError('unsupported C++ header origin policy; prepare again')
    actual_wrapper = Path(__file__).absolute()
    if actual_wrapper.resolve() != Path(config['wrapper']).resolve():
        raise OutlineBuildError('executed wrapper path differs from installed configuration')
    if sha256(actual_wrapper.read_bytes()) != config['wrapper_sha256']:
        raise OutlineBuildError('installed wrapper hash differs from configuration; prepare again')
    if sha256(Path(config['outliner']).read_bytes()) != config['outliner_sha256']:
        raise OutlineBuildError('outliner hash differs from configuration; prepare again')
    return config


def split_windows_response(text):
    """LLVM/CRT response quoting: backslashes only escape a following quote."""
    words = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        word = []
        quoted = False
        while index < len(text) and (quoted or not text[index].isspace()):
            backslashes = 0
            while index < len(text) and text[index] == '\\':
                backslashes += 1
                index += 1
            if index < len(text) and text[index] == '"':
                word.append('\\' * (backslashes // 2))
                if backslashes % 2:
                    word.append('"')
                elif quoted and index + 1 < len(text) and text[index + 1] == '"':
                    word.append('"')
                    index += 1
                else:
                    quoted = not quoted
                index += 1
            else:
                word.append('\\' * backslashes)
                if index < len(text) and (quoted or not text[index].isspace()):
                    word.append(text[index])
                    index += 1
        if quoted:
            raise OutlineBuildError('unterminated quote in Windows response file')
        words.append(''.join(word))
    return words


def split_gnu_response(text):
    # LLVM TokenizeGNUCommandLine treats backslash as an escape even inside
    # single quotes; POSIX shlex.split does not. In particular, unescaped
    # Windows paths inside shlex.quote(...) would silently lose backslashes.
    words = []
    word = []
    quote = None
    started = False
    index = 0
    while index < len(text):
        value = text[index]
        if value == '\\' and index + 1 < len(text):
            word.append(text[index + 1])
            started = True
            index += 2
            continue
        if value in {'\"', "'"}:
            if quote is None:
                quote = value
                started = True
            elif quote == value:
                quote = None
            else:
                word.append(value)
        elif value.isspace() and quote is None:
            if started:
                words.append(''.join(word))
                word = []
                started = False
        else:
            word.append(value)
            started = True
        index += 1
    if quote is not None:
        raise OutlineBuildError('unterminated quote in GNU response file')
    if started:
        words.append(''.join(word))
    return words


def split_response(data, response_format):
    text = data.decode('utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
    return split_windows_response(text) if response_format == 'windows' else split_gnu_response(text)


def join_response(argv, response_format):
    if response_format == 'windows':
        return subprocess.list2cmdline(argv)
    return ' '.join('"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"' for value in argv)


@dataclass
class Argument:
    value: str
    index: int = -1
    path: Path | None = None
    children: list | None = None


class ResponseArguments:
    """Keep response boundaries/order, rewriting only owned shadow copies."""
    def __init__(self, argv, cwd, response_format):
        self.cwd = cwd
        self.response_format = response_format
        self.flat = []
        self.files = []
        self.shadows = []
        self.nodes = self._parse(argv, ())

    def _parse(self, argv, active):
        if len(active) > 32:
            raise OutlineBuildError('response-file nesting exceeds 32 levels')
        result = []
        for value in argv:
            node = Argument(value)
            if value.startswith('@') and len(value) > 1:
                path = absolute_path(value[1:], self.cwd).resolve()
                if path in active:
                    raise OutlineBuildError(f'response-file cycle: {path}')
                data = path.read_bytes()
                self.files.append({'path': str(path), 'sha256': sha256(data)})
                node.path = path
                node.children = self._parse(split_response(data, self.response_format), (*active, path))
            else:
                node.index = len(self.flat)
                self.flat.append(value)
                if len(self.flat) > 1000000:
                    raise OutlineBuildError('response-file argument count exceeds limit')
            result.append(node)
        return result

    def render(self, edits, appended, directory, stage):
        counter = 0

        def walk(nodes):
            nonlocal counter
            result = []
            changed = False
            for node in nodes:
                if node.children is None:
                    replacement = edits.get(node.index, [node.value])
                    result.extend(replacement)
                    changed |= replacement != [node.value]
                else:
                    children, child_changed = walk(node.children)
                    if child_changed:
                        path = directory / f'{stage}-{counter}.rsp'
                        counter += 1
                        data = (join_response(children, self.response_format) + '\n').encode('utf-8')
                        path.write_bytes(data)
                        self.shadows.append({'stage': stage, 'path': str(path),
                                             'original_path': str(node.path), 'sha256': sha256(data),
                                             'argv': children})
                        result.append('@' + str(path))
                        changed = True
                    else:
                        result.append(node.value)
            return result, changed

        command, _ = walk(self.nodes)
        return command + appended

    def expanded(self, edits, appended):
        result = []
        for index, value in enumerate(self.flat):
            result.extend(edits.get(index, [value]))
        return result + appended


@dataclass
class CompileInput:
    index: int
    source: Path
    output: Path
    language: str
    output_indices: list[int] = field(default_factory=list)
    language_indices: list[int] = field(default_factory=list)


def find_compile_input(argv, cwd, language):
    if '-c' not in argv or any(flag in argv for flag in ('-E', '-S', '-M', '-MM', '-fsyntax-only', '-emit-pch')):
        return None
    sources = []
    output = None
    output_indices = []
    language_indices = []
    index = 1
    explicit_language = None
    while index < len(argv):
        value = argv[index]
        if value in _VALUE_OPTIONS:
            if index + 1 >= len(argv):
                raise OutlineBuildError(f'missing value for {value}')
            if value == '-o':
                output = argv[index + 1]
                output_indices += [index, index + 1]
            elif value == '-x':
                explicit_language = argv[index + 1]
                language_indices += [index, index + 1]
            index += 2
            continue
        if value.startswith('-o') and len(value) > 2:
            output = value[2:]
            output_indices.append(index)
        elif value.startswith('-x') and len(value) > 2:
            explicit_language = value[2:]
            language_indices.append(index)
        elif not value.startswith('-') and Path(value).suffix in _SOURCE_LANGUAGES:
            sources.append((index, value))
        index += 1
    if len(sources) != 1:
        return None
    source_index, raw_source = sources[0]
    effective_language = _SOURCE_LANGUAGES[Path(raw_source).suffix]
    if explicit_language is not None:
        effective_language = {'c': 'c', 'c++': 'cpp', 'cpp-output': 'c',
                              'c++-cpp-output': 'cpp'}.get(explicit_language)
        if effective_language is None:
            return None
    if language != effective_language:
        raise OutlineBuildError(f'compiler language {language} does not match source language {effective_language}')
    source = absolute_path(raw_source, cwd)
    output = absolute_path(output or Path(raw_source).stem + '.o', cwd)
    return CompileInput(source_index, source, output, language, output_indices, language_indices)


def component_for(path, source_root):
    """Do not mistake a dependency under core/subprojects for core itself."""
    resolved = path.resolve()
    for name in ('frida-core', 'frida-gum'):
        root = (source_root / 'subprojects' / name).resolve()
        if resolved.is_relative_to(root):
            relative = resolved.relative_to(root)
            if relative.parts and relative.parts[0] == 'subprojects':
                continue
            return name
    return None


def should_outline(unit, config, build_root):
    source_root = Path(config['source_root'])
    if any(part in {'meson-private', 'meson-logs', 'meson-info'} for part in unit.source.parts):
        return False
    if component_for(unit.source, source_root):
        return True
    generated_roots = [source_root / 'build'] + ([build_root] if build_root is not None else [])
    if not any(is_within(unit.source, root) for root in generated_roots):
        return False
    # These exact resource-compiler outputs contain already verified embedded
    # ELF payloads, not gumjs runtime resources. Keep the compiler's original
    # command and avoid building millions of AST nodes for opaque ELF bytes.
    if unit.language == 'c' and unit.source.name in {
            'frida-data-agent.c', 'frida-data-helper-process.c', 'frida-data-helper-backend.c'}:
        return False
    # Meson-generated and Vala-generated C lives in the build tree, not in the
    # original checkout. Identify its owning project by the object directory.
    for path in (unit.source, unit.output):
        for root in (source_root / 'build', build_root):
            if root is None or not is_within(path, root):
                continue
            parts = path.resolve().relative_to(root.resolve()).parts
            for index, part in enumerate(parts):
                if part in {'frida-core', 'frida-gum'}:
                    rest = parts[index + 1:]
                    if rest and rest[0] == 'subprojects' and len(rest) > 1 and rest[1] not in {'frida-core', 'frida-gum'}:
                        return False
                    return True
    # A standalone compat Meson project uses short src/... and gum/... object
    # paths. Its public JSON metadata supplies the source directory; no pickle
    # or Python from the source archive is imported or executed here.
    if build_root is not None and is_within(unit.source, build_root):
        info = build_root / 'meson-info' / 'meson-info.json'
        if info.is_file():
            source = json.loads(info.read_text(encoding='utf-8'))['directories']['source']
            if component_for(absolute_path(source), source_root):
                parts = unit.output.resolve().relative_to(build_root.resolve()).parts if is_within(unit.output, build_root) else ()
                return bool(parts) and parts[0] not in {'subprojects', 'meson-private'}
    return False


@dataclass
class Dependencies:
    mode: str = '-MD'
    file: str | None = None
    targets: list = field(default_factory=list)
    switches: list = field(default_factory=list)
    requested: bool = False


def dependency_edits(argv):
    """Remove dependency emitters; reconstruct original dependencies in -E only."""
    edits = {}
    dependencies = Dependencies()

    def consume(values, indices, wp=False):
        kept = []
        index = 0
        while index < len(values):
            value = values[index]
            option = value
            joined = None
            for candidate in ('-MF', '-MT', '-MQ'):
                if value.startswith(candidate) and len(value) > len(candidate):
                    option, joined = candidate, value[len(candidate):]
                    break
            if option in _DEP_MODES:
                dependencies.mode = option
                dependencies.requested = True
                edits[indices[index]] = []
                # -Wp,-MD,FILE is a preprocessor spelling, unlike driver -MD.
                if wp and index + 1 < len(values) and not values[index + 1].startswith('-'):
                    dependencies.file = values[index + 1]
                    edits[indices[index + 1]] = []
                    index += 1
            elif option in _DEP_VALUES:
                dependencies.requested = True
                edits[indices[index]] = []
                if joined is None:
                    if index + 1 >= len(values):
                        raise OutlineBuildError(f'missing dependency value for {option}')
                    joined = values[index + 1]
                    edits[indices[index + 1]] = []
                    index += 1
                if option in {'-MF', '-dependency-file'}:
                    dependencies.file = joined
                else:
                    dependencies.targets.append((option, joined))
            elif option in _DEP_SWITCHES:
                dependencies.requested = True
                edits[indices[index]] = []
                if option in {'-M', '-MM'}:
                    raise OutlineBuildError('dependency-only compilation cannot be outlined')
                if option not in dependencies.switches:
                    dependencies.switches.append(option)
            else:
                kept.append(value)
            index += 1
        return kept

    index = 1
    while index < len(argv):
        value = argv[index]
        if value.startswith('-Wp,'):
            parts = value[4:].split(',')
            # Synthetic indices let the same parser handle comma-delimited deps.
            synthetic = [-(index * 10000 + item + 1) for item in range(len(parts))]
            kept = consume(parts, synthetic, wp=True)
            for key in synthetic:
                edits.pop(key, None)
            if kept != parts:
                edits[index] = ['-Wp,' + ','.join(kept)] if kept else []
        elif value in {'-Xclang', '-Xpreprocessor'} and index + 1 < len(argv):
            wrapped = argv[index + 1]
            if wrapped in _DEP_VALUES | _DEP_SWITCHES:
                indices = [index + 1]
                values = [wrapped]
                removals = [index]
                if wrapped in _DEP_VALUES:
                    value_index = index + 2
                    if value_index < len(argv) and argv[value_index] == value:
                        removals.append(value_index)
                        value_index += 1
                    if value_index >= len(argv):
                        raise OutlineBuildError(f'missing wrapped dependency value for {wrapped}')
                    values.append(argv[value_index])
                    indices.append(value_index)
                consume(values, indices)
                for removal in removals:
                    edits[removal] = []
                index = indices[-1]
        elif value in _VALUE_OPTIONS and value not in _DEP_VALUES:
            index += 1
        elif value in _DEP_VALUES or value in _DEP_SWITCHES or any(value.startswith(p) and len(value) > len(p) for p in ('-MF', '-MT', '-MQ')):
            count = 2 if value in _DEP_VALUES else 1
            consume(argv[index:index + count], list(range(index, index + count)))
            index += count - 1
        index += 1
    return edits, dependencies


def prefix_map_flags(config, cwd, unit=None):
    roots = [Path(config['source_root'])]
    if unit is not None:
        # Windows may spell the same directory using an 8.3 alias and '\\'
        # separators. Match the exact input spelling as well as resolved root.
        parts = unit.source.parts
        for index, part in enumerate(parts):
            if part == 'subprojects' and index + 1 < len(parts) and parts[index + 1] in {'frida-core', 'frida-gum'}:
                roots.append(Path(*parts[:index]))
                break
    mappings = []
    for root in roots:
        mappings += [(root.as_posix(), '../nianchu-source'), (str(root), '../nianchu-source'),
                     ((root / 'releng').as_posix(), '../nianchu-source/build-support'),
                     (str(root / 'releng'), '../nianchu-source/build-support')]
    for root in roots:
        for name, replacement in (('frida-core', 'nianchu-core'), ('frida-gum', 'nianchu-gum')):
            component = root / 'subprojects' / name
            mappings += [(f'../subprojects/{name}', f'../subprojects/{replacement}'),
                         (component.as_posix(), f'../subprojects/{replacement}'),
                         (str(component), f'../subprojects/{replacement}')]
            try:
                relative = os.path.relpath(component, cwd).replace('\\', '/')
                mappings.append((relative, relative.rsplit('/', 1)[0] + '/' + replacement))
            except ValueError:
                pass  # Windows paths on different drives cannot be relative.
    unique = dict(mappings)
    return [f'-ffile-prefix-map={before}={after}' for before, after in unique.items()]


def escape_depfile(value):
    # Make/Ninja's GCC depfile grammar, including drive letters and literal $.
    return value.replace('\\', '\\\\').replace('$', '$$').replace(' ', '\\ ').replace('\t', '\\\t').replace('#', '\\#').replace(':', '\\:')


def augment_depfile(path, inputs):
    data = path.read_bytes()
    if not data.strip():
        raise OutlineBuildError(f'compiler did not produce a usable dependency file: {path}')
    end = len(data)
    for index, byte in enumerate(data):
        if byte != 10:
            continue
        preceding = index - 1
        if preceding >= 0 and data[preceding] == 13:
            preceding -= 1
        backslashes = 0
        while preceding >= 0 and data[preceding] == 92:
            backslashes += 1
            preceding -= 1
        if not backslashes % 2:
            end = index - 1 if index > 0 and data[index - 1] == 13 else index
            break
    if b':' not in data[:end]:
        raise OutlineBuildError(f'invalid GCC dependency file: {path}')
    additions = (' ' + ' '.join(escape_depfile(str(path)) for path in inputs)).encode('utf-8')
    result = data[:end] + additions + data[end:]
    write_atomic(path, result)
    return sha256(result)


def compiler_identity(command, cwd, config, language):
    executable = absolute_path(command[0], cwd)
    if not executable.exists():
        import shutil
        found = shutil.which(command[0])
        executable = absolute_path(found, cwd) if found else executable
    info = executable.stat()
    key = sha256(json.dumps([str(executable), info.st_size, info.st_mtime_ns, language]).encode())
    path = Path(config['identity_cache']) / (key + '.json')
    if path.is_file():
        return json.loads(path.read_text(encoding='utf-8'))
    # Clang exits at --version even when a compile argv precedes it. This also
    # preserves a compiler-array launcher/base flags without guessing its size.
    probe = subprocess.run(command + ['--version'], cwd=cwd, capture_output=True,
                           text=True, errors='replace', timeout=30)
    result = {'executable': str(executable), 'size': info.st_size,
              'mtime_ns': info.st_mtime_ns, 'returncode': probe.returncode,
              'version': (probe.stdout + probe.stderr)[:65536]}
    if probe.returncode != 0:
        raise OutlineBuildError('real compiler --version probe failed')
    write_atomic(path, (json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
    return result


def cpp_header_origin_roots(argv, unit, config, cwd):
    """Select concrete libc++/V8/Highway roots; keep core/gum and C headers parsed."""
    if unit.language != 'cpp':
        return []
    candidates = []
    executable = absolute_path(argv[0], cwd)
    if not executable.is_file():
        found = shutil.which(argv[0])
        if found:
            executable = Path(found).resolve()
    if executable.is_file():
        candidates.append(executable.parent.parent / 'sysroot' / 'usr' / 'include' / 'c++' / 'v1')
    index = 1
    while index < len(argv):
        value = argv[index]
        include = None
        sysroot = None
        if value in {'-I', '-isystem', '-iquote', '-idirafter', '-isysroot', '--sysroot'}:
            if index + 1 >= len(argv):
                raise OutlineBuildError('missing header path for ' + value)
            if value in {'-isysroot', '--sysroot'}:
                sysroot = argv[index + 1]
            else:
                include = argv[index + 1]
            index += 2
        elif value.startswith('--sysroot='):
            sysroot = value[len('--sysroot='):]
            index += 1
        elif value.startswith('-I') and len(value) > 2:
            include = value[2:]
            index += 1
        elif value.startswith('-isystem') and len(value) > len('-isystem'):
            include = value[len('-isystem'):]
            index += 1
        elif value in _VALUE_OPTIONS:
            index += 2
        else:
            index += 1
        if sysroot:
            candidates.append(absolute_path(sysroot, cwd) / 'usr' / 'include' / 'c++' / 'v1')
        if include:
            directory = absolute_path(include, cwd)
            if directory.name == 'v1' and directory.parent.name == 'c++':
                candidates.append(directory)
            elif re.fullmatch(r'v8-\d+\.\d+', directory.name):
                candidates.append(directory)
            elif directory.name in {'hwy', 'highway'}:
                candidates.append(directory if directory.name == 'hwy' else directory / 'hwy')
            if (directory / 'hwy').is_dir():
                candidates.append(directory / 'hwy')
    roots = []
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        root = candidate.resolve()
        owned_roots = [(Path(config['source_root']) / 'subprojects' / name).resolve()
                       for name in ('frida-core', 'frida-gum')]
        if any(is_within(root, owned) or is_within(owned, root) for owned in owned_roots):
            raise OutlineBuildError('C++ opaque header root overlaps owned core/gum source: ' + str(root))
        if is_within(unit.source, root):
            raise OutlineBuildError('C++ opaque header root contains the compilation source: ' + str(root))
        if str(root) not in roots:
            roots.append(str(root))
    return roots


def regular_output(path, directory):
    if path.is_symlink() or not path.is_file() or not is_within(path, directory):
        raise OutlineBuildError(f'compiler/outliner output is missing or not an isolated regular file: {path}')


def compile_outlined(command, arguments, unit, config, cwd, build_root):
    report_dir = Path(config['report_dir']) / config['version']
    key = sha256(json.dumps([str(cwd), str(unit.source), str(unit.output), unit.language]).encode())[:24]
    report_path = report_dir / (key + '.json')
    original = unit.source.read_bytes()
    source_mode = stat.S_IMODE(unit.source.stat().st_mode)
    report = {'schema': 1, 'wrapper_version': WRAPPER_VERSION, 'frida_version': config['version'],
              'status': 'started', 'source': str(unit.source), 'output': str(unit.output),
              'language': unit.language, 'cwd': str(cwd), 'build_root': str(build_root) if build_root else None,
              'source_sha256': sha256(original), 'source_readonly': True,
              'source_mode_before': source_mode, 'original_argv': command,
              'original_expanded_argv': arguments.flat,
              'command_format': {'kind': 'argv', 'shell': False,
                                 'response_format': config['response_format']},
              'response_files': arguments.files, 'shadow_response_files': arguments.shadows,
              'config': config['config_path'], 'outliner': config['outliner'],
              'dependencies': config.get('dependencies', {})}
    returncode = 1
    try:
        report['compiler'] = compiler_identity(command, cwd, config, unit.language)
        work_root = Path(config['work_root'])
        work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=key + '-', dir=work_root) as temporary:
            directory = Path(temporary)
            suffix = '.c' if unit.language == 'c' else '.cpp'
            preprocessed = directory / ('preprocessed' + suffix)
            transformed = directory / ('outlined' + suffix)
            outline_report = directory / 'outline.json'
            edits, dependencies = dependency_edits(arguments.flat)
            preprocessing_edits = {**edits, **{index: [] for index in unit.output_indices}}
            for index, value in enumerate(arguments.flat):
                if value == '-c' or (unit.language == 'cpp' and value == '-P'):
                    preprocessing_edits[index] = []
                if unit.language == 'cpp' and (
                        (value.startswith('-Wp,') and '-P' in value[4:].split(',')) or
                        (value in {'-Xpreprocessor', '-Xclang'} and index + 1 < len(arguments.flat)
                         and arguments.flat[index + 1] == '-P') or
                        value in {'-Xpreprocessor=-P', '-Xclang=-P'}):
                    raise OutlineBuildError('C++ outlining requires compiler line origins; wrapped -P is unsupported')
            depfile = absolute_path(dependencies.file or str(unit.output.with_suffix('.d')), cwd)
            if depfile.resolve() == unit.source.resolve() or depfile.resolve() == unit.output.resolve():
                raise OutlineBuildError('dependency file aliases original source or object')
            targets = [token for pair in dependencies.targets for token in pair]
            if not targets:
                targets = ['-MQ', str(unit.output)]
            maps = prefix_map_flags(config, cwd, unit)
            dependency_args = [dependencies.mode, '-MF', str(depfile), *targets, *dependencies.switches]
            cpp_roots = cpp_header_origin_roots(arguments.flat, unit, config, cwd)
            preprocess_extra = [*maps, '-E', *(['-P'] if unit.language == 'c' else []),
                                '-o', str(preprocessed), *dependency_args]
            report['cpp_header_policy'] = CPP_HEADER_POLICY if unit.language == 'cpp' else None
            report['cpp_opaque_roots'] = cpp_roots
            report['compiler_line_origins_preserved'] = unit.language == 'cpp'
            preprocess_command = arguments.render(preprocessing_edits, preprocess_extra, directory, 'preprocess')
            report['preprocess_command'] = preprocess_command
            report['preprocess_expanded_argv'] = arguments.expanded(preprocessing_edits, preprocess_extra)
            report['prefix_map_flags'] = maps
            result = subprocess.run(preprocess_command, cwd=cwd)
            returncode = result.returncode
            if returncode:
                raise OutlineBuildError(f'preprocessing failed with exit code {returncode}')
            regular_output(preprocessed, directory)
            report['preprocessed_sha256'] = sha256(preprocessed.read_bytes())
            report['depfile'] = str(depfile)
            report['depfile_sha256'] = augment_depfile(depfile, [unit.source, Path(config['wrapper']),
                                                              Path(config['config_path']), Path(config['outliner'])])
            outline_command = [config['python'], '-I', config['outliner'],
                               '--input', str(preprocessed), '--output', str(transformed),
                               '--report', str(outline_report), '--language', unit.language,
                               *[value for root in cpp_roots for value in ('--cpp-opaque-root', root)]]
            report['outline_command'] = outline_command
            result = subprocess.run(outline_command, cwd=directory)
            returncode = result.returncode
            if outline_report.is_file() and not outline_report.is_symlink():
                regular_output(outline_report, directory)
                report['outliner_report'] = json.loads(outline_report.read_text(encoding='utf-8'))
            if returncode:
                raise OutlineBuildError(f'outlining failed with exit code {returncode}')
            regular_output(transformed, directory)
            regular_output(outline_report, directory)
            report['transformed_sha256'] = sha256(transformed.read_bytes())
            compilation_edits = {**edits, unit.index: ['-x', 'cpp-output' if unit.language == 'c' else 'c++-cpp-output',
                                                       str(transformed)],
                                 **{index: [] for index in unit.language_indices}}
            # The original -D/-U/-include/-I flags remain in their original
            # order. A preprocessed input language BEFORE the input prevents
            # re-expansion and duplicate forced-header declarations in the TU.
            compile_extra = maps
            compile_command = arguments.render(compilation_edits, compile_extra, directory, 'compile')
            report['compile_command'] = compile_command
            report['compile_expanded_argv'] = arguments.expanded(compilation_edits, compile_extra)
            result = subprocess.run(compile_command, cwd=cwd)
            returncode = result.returncode
            if returncode:
                raise OutlineBuildError(f'object compilation failed with exit code {returncode}')
            if sha256(depfile.read_bytes()) != report['depfile_sha256']:
                raise OutlineBuildError('flattened compilation overwrote original dependencies')
            report['status'] = 'compiled'
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, OutlineBuildError) as error:
        report['status'] = 'failed'
        report['error'] = str(error)
        if returncode == 0:
            returncode = 1
        print(f'string outline: {error}; report: {report_path}', file=sys.stderr)
    finally:
        try:
            report['source_sha256_after'] = sha256(unit.source.read_bytes())
            report['source_mode_after'] = stat.S_IMODE(unit.source.stat().st_mode)
            report['source_unchanged'] = (report['source_sha256_after'] == report['source_sha256'] and
                                          report['source_mode_after'] == source_mode)
        except OSError:
            report['source_unchanged'] = False
        if not report['source_unchanged']:
            report['status'] = 'failed'
            report['error'] = 'original source changed during compilation'
            returncode = 1
        report['returncode'] = returncode
        report['temporary_files_retained'] = False
        write_atomic(report_path, (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    return returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--language', choices=('c', 'cpp'), required=True)
    parser.add_argument('--build-root', type=Path)
    parser.add_argument('compiler', nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    command = options.compiler
    if command and command[0] == '--':
        command = command[1:]
    if not command:
        parser.error('a real compiler command is required after --')
    try:
        config = load_config(options.config)
        cwd = Path.cwd().resolve()
        build_root = absolute_path(options.build_root, cwd) if options.build_root else None
        arguments = ResponseArguments(command, cwd, config['response_format'])
        unit = find_compile_input(arguments.flat, cwd, options.language)
        if unit is None or not should_outline(unit, config, build_root):
            return subprocess.run(command, cwd=cwd).returncode
        return compile_outlined(command, arguments, unit, config, cwd, build_root)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, OutlineBuildError) as error:
        print(f'string outline: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    code = main()
    raise SystemExit(128 - code if code < 0 else code)
