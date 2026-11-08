#!/usr/bin/env python3
"""Prepare a trusted external compiler prefix before Frida configure.

The pinned releng/env_android.py hook prepends the emitted Python/wrapper/config
argv to c/cpp binaries; Meson preserves it in compiler coredata and regeneration.
No compiler executable or generated Ninja file is patched by this installer.

Prepare::
    python -I install_string_outline.py --source FRIDA --version VERSION \
        --state-dir EXTERNAL --python VENV_PYTHON --outliner TRUSTED_SCRIPT \
        --env-output ENV_FILE --report INSTALL_JSON

Validate after configure (and each configured compat workdir)::
    python -I install_string_outline.py --state-dir EXTERNAL --build BUILD \
        --report VALIDATION_JSON

The trusted outliner CLI is --input FILE --output FILE --report JSON
--language c|cpp. It runs as VENV_PYTHON -I, outside the downloaded checkout.
"""
import sys

if __name__ == '__main__' and not sys.flags.isolated:
    raise SystemExit('string outline installer must be launched with Python -I')

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

SCHEMA = 1
WRAPPER_VERSION = '1.1'
CPP_HEADER_POLICY = 'explicit-cpp-header-origins-v1'
PARSER_PINS = {'tree-sitter': '0.25.2', 'tree-sitter-c': '0.24.2', 'tree-sitter-cpp': '0.23.4'}
PINNED_RELENG = {
    '16.7.19': {'commit': 'ddd0f5875c08edc005e9f89f7fdb7b0928fac4dc',
                'env_android_sha256': 'fddf203f9234a5604c275eeec32ac2795f2f0b9459312d8f2915ea66a6acc9c5'},
    '17.25.2': {'commit': '564352a3eac2ca0f5db776b6929955dbb20cf731',
                'env_android_sha256': '33efcf33095441ce6b54f4074740acc66dec149e13abb8cedc2dc3cfeb1b37b4'},
}
RELENG_OLD = '''        raw_val = strv_to_meson(argv)
        if identifier in {"c", "cpp"}:
            raw_val += " + common_flags"
'''
RELENG_NEW = '''        # NIANCHU: keep an argv prefix in Meson compiler arrays across regeneration.
        if identifier in {"c", "cpp"} and environ.get("NIANCHU_STRING_OUTLINER"):
            argv = [environ["NIANCHU_STRING_OUTLINE_PYTHON"], "-I",
                    environ["NIANCHU_STRING_OUTLINE_COMPILER"],
                    "--config", environ["NIANCHU_STRING_OUTLINE_CONFIG"],
                    "--language", identifier, "--build-root", str(outdir), "--", *argv]

        raw_val = strv_to_meson(argv)
        if identifier in {"c", "cpp"}:
            raw_val += " + common_flags"
'''


class InstallationError(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def absolute_path(value):
    # Do not resolve the Python executable: venv/bin/python is often a symlink
    # to system Python, and resolving that symlink silently loses the venv.
    return Path(os.path.abspath(value))


def outside(path, source_root, label):
    if path.resolve().is_relative_to(source_root.resolve()):
        raise InstallationError(f'{label} must be outside the complete source tree: {path}')


def owned_write(path, data):
    path = Path(path)
    if path.is_symlink():
        raise InstallationError(f'refusing to overwrite symlink: {path}')
    if path.is_file() and path.read_bytes() == data:
        return False
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix='.' + path.name + '-', dir=path.parent,
                                     delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')


def dependency_preflight(python, directory, allow_stub=False):
    code = '''import importlib, importlib.metadata as m, json, sys
pins = json.loads(sys.argv[1])
modules = {'tree-sitter':'tree_sitter', 'tree-sitter-c':'tree_sitter_c',
           'tree-sitter-cpp':'tree_sitter_cpp'}
versions = {name: m.version(name) for name in pins}
if versions != pins:
    raise SystemExit('parser versions differ from exact pins: ' + repr(versions))
loaded = {name: importlib.import_module(module) for name, module in modules.items()}
ts = loaded['tree-sitter']
for grammar in ('tree-sitter-c', 'tree-sitter-cpp'):
    parser = ts.Parser(ts.Language(loaded[grammar].language()))
    if parser.parse(b'int nianchu_probe(void) { return 0; }').root_node.has_error:
        raise SystemExit('parser ABI preflight failed: ' + grammar)
print(json.dumps({'versions':versions, 'executable':sys.executable,
                  'prefix':sys.prefix, 'base_prefix':sys.base_prefix,
                  'is_venv':sys.prefix != sys.base_prefix, 'isolated':bool(sys.flags.isolated)}))
'''
    if allow_stub:
        code = '''import json, sys
print(json.dumps({'versions':{}, 'executable':sys.executable, 'prefix':sys.prefix,
                  'base_prefix':sys.base_prefix, 'is_venv':sys.prefix != sys.base_prefix,
                  'isolated':bool(sys.flags.isolated), 'stub_only':True}))
'''
    result = subprocess.run([str(python), '-I', '-c', code, json.dumps(PARSER_PINS)],
                            cwd=directory, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise InstallationError('isolated parser preflight failed: ' + result.stderr.strip())
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise InstallationError('invalid Python preflight JSON') from error


def merge_environment_file(path, environment):
    """Preserve unrelated KEY=value and GitHub multiline entries verbatim."""
    path = Path(path)
    previous = path.read_text(encoding='utf-8') if path.is_file() else ''
    lines = previous.splitlines(keepends=True)
    retained = []
    seen = set()
    delimiter = None
    for line in lines:
        raw = line.rstrip('\r\n')
        if delimiter is not None:
            retained.append(line)
            if raw == delimiter:
                delimiter = None
            continue
        if '<<' in raw and ('=' not in raw or raw.index('<<') < raw.index('=')):
            name, token = raw.split('<<', 1)
            if name in environment:
                raise InstallationError(f'cannot merge multiline value for owned environment key: {name}')
            delimiter = token
            retained.append(line)
            continue
        name = raw.split('=', 1)[0]
        if '=' in raw and name in environment:
            if name not in seen:
                retained.append(f'{name}={environment[name]}\n')
                seen.add(name)
        else:
            retained.append(line)
    if delimiter is not None:
        raise InstallationError('cannot append to an unterminated multiline environment value')
    text = ''.join(retained)
    if text and not text.endswith(('\n', '\r')):
        text += '\n'
    text += ''.join(f'{name}={value}\n' for name, value in environment.items() if name not in seen)
    return owned_write(path, text.encode('utf-8'))


def prepare(source, version, state_dir, python, outliner, env_output=None,
            response_format=None, allow_stub=False):
    source = absolute_path(source).resolve()
    if not source.is_dir():
        raise InstallationError(f'source directory does not exist: {source}')
    if version not in PINNED_RELENG:
        raise InstallationError(f'unsupported pinned Frida version: {version}')
    state_dir = absolute_path(state_dir)
    python = absolute_path(python)
    outliner = absolute_path(outliner)
    wrapper_source = Path(__file__).absolute().with_name('string_outline_compiler.py')
    outside(Path(__file__).absolute(), source, 'installer')
    for path, label in ((state_dir, 'state directory'), (python, 'Python'),
                        (outliner, 'outliner'), (wrapper_source, 'wrapper source')):
        outside(path, source, label)
    if not python.is_file() or not outliner.is_file() or not wrapper_source.is_file():
        raise InstallationError('Python, outliner, and wrapper must be existing external files')
    if env_output is not None:
        env_output = absolute_path(env_output)
        outside(env_output, source, 'environment output')
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    dependencies = dependency_preflight(python, state_dir, allow_stub)
    wrapper = state_dir / 'string_outline_compiler.py'
    wrapper_data = wrapper_source.read_bytes()
    changed = owned_write(wrapper, wrapper_data)
    config_path = state_dir / 'config.json'
    # Android Clang is a GCC-syntax driver on every host, including Windows.
    # A clang-cl/CRT response format is supported only by explicit opt-in.
    response_format = response_format or 'gnu'
    if response_format not in {'gnu', 'windows'}:
        raise InstallationError('response format must be gnu or windows')
    config = {'schema': SCHEMA, 'wrapper_version': WRAPPER_VERSION, 'version': version,
              'source_root': str(source), 'python': str(python), 'wrapper': str(wrapper),
              'outliner': str(outliner), 'work_root': str(state_dir / 'work'),
              'report_dir': str(state_dir / 'reports'), 'identity_cache': str(state_dir / 'compiler-identities'),
              'response_format': response_format, 'dependencies': dependencies,
              'cpp_header_policy': CPP_HEADER_POLICY,
              'parser_pins': PARSER_PINS, 'wrapper_sha256': digest(wrapper_data),
              'outliner_sha256': digest(outliner.read_bytes()),
              'installer_sha256': digest(Path(__file__).read_bytes())}
    changed |= owned_write(config_path, json_bytes(config))
    environment = {'NIANCHU_STRING_OUTLINER': str(outliner),
                   'NIANCHU_STRING_OUTLINE_PYTHON': str(python),
                   'NIANCHU_STRING_OUTLINE_COMPILER': str(wrapper),
                   'NIANCHU_STRING_OUTLINE_CONFIG': str(config_path)}
    if env_output is not None:
        for name, value in environment.items():
            if '\n' in value or '\r' in value:
                raise InstallationError(f'newline in environment value: {name}')
        changed |= merge_environment_file(env_output, environment)
    return {'schema': SCHEMA, 'action': 'prepare', 'status': 'prepared',
            'wrapper_version': WRAPPER_VERSION, 'installer_sha256': config['installer_sha256'],
            'version': version, 'source_root': str(source), 'source_readonly': True,
            'changed': bool(changed), 'state_dir': str(state_dir), 'config': str(config_path),
            'environment': environment, 'dependencies': dependencies,
            'wrapper_sha256': config['wrapper_sha256'], 'outliner_sha256': config['outliner_sha256'],
            'report_dir': config['report_dir'], 'work_root': config['work_root'],
            'compiler_prefix': [str(python), '-I', str(wrapper), '--config', str(config_path)],
            'installation_point': 'pinned releng/env_android.py compiler arrays before configure',
            'regeneration': 'Meson compiler coredata preserves prefix; compat regenerates the same gated arrays',
            'pinned_releng': {**PINNED_RELENG[version], 'path': 'releng/env_android.py',
                              'old': RELENG_OLD, 'new': RELENG_NEW}}


def ninja_rules(text):
    # Fold Ninja continuations before parsing rule blocks. Do not eval commands
    # or unpickle Meson coredata from a downloaded/source tree.
    text = re.sub(r'\$\r?\n[ \t]*', '', text)
    current = None
    rules = {}
    for line in text.splitlines():
        if line.startswith('rule '):
            current = line[5:].strip()
            rules[current] = {}
        elif line and not line[0].isspace() and not line.startswith('#'):
            current = None
        elif current and '=' in line:
            name, value = line.split('=', 1)
            rules[current][name.strip()] = value.strip()
    return rules


def validate_build(state_dir, build):
    state_dir = absolute_path(state_dir)
    config_path = state_dir / 'config.json'
    config = json.loads(config_path.read_text(encoding='utf-8'))
    if config.get('schema') != SCHEMA or config.get('wrapper_version') != WRAPPER_VERSION:
        raise InstallationError('unsupported installed configuration')
    if config.get('cpp_header_policy') != CPP_HEADER_POLICY:
        raise InstallationError('unsupported installed C++ header origin policy')
    if config.get('installer_sha256') != digest(Path(__file__).read_bytes()):
        raise InstallationError('installer changed after prepare; prepare again before building')
    wrapper = Path(config['wrapper'])
    if digest(wrapper.read_bytes()) != config['wrapper_sha256']:
        raise InstallationError('installed wrapper hash differs from configuration')
    if digest(Path(config['outliner']).read_bytes()) != config['outliner_sha256']:
        raise InstallationError('outliner changed after prepare; prepare again before building')
    build = absolute_path(build)
    ninja = build / 'build.ninja'
    rules = ninja_rules(ninja.read_text(encoding='utf-8'))
    checked = []
    for language in ('c', 'cpp'):
        candidates = [(name, properties) for name, properties in rules.items()
                      if re.fullmatch(language + r'_COMPILER(?:_\d+)?', name)]
        if not candidates:
            raise InstallationError(f'no Meson host {language} compiler rule in {ninja}')
        for name, properties in candidates:
            command = properties.get('command', '').replace('$$', '$').replace('$ ', ' ').replace('$:', ':')
            for expected in (str(wrapper), str(config_path), '-I', '--config', '--language ' + language, '--build-root'):
                if expected not in command and expected.replace('\\', '/') not in command:
                    raise InstallationError(f'{name} is not using the isolated installed prefix: missing {expected}')
            checked.append({'rule': name, 'command': properties['command'],
                            'depfile': properties.get('depfile'),
                            'rspfile': properties.get('rspfile'),
                            'rspfile_content': properties.get('rspfile_content')})
    return {'schema': SCHEMA, 'action': 'validate-build', 'status': 'validated',
            'wrapper_version': WRAPPER_VERSION, 'installer_sha256': config['installer_sha256'],
            'wrapper_sha256': config['wrapper_sha256'], 'outliner_sha256': config['outliner_sha256'],
            'version': config['version'], 'source_root': config['source_root'],
            'source_readonly': True, 'build_root': str(build), 'ninja_sha256': digest(ninja.read_bytes()),
            'config': str(config_path), 'compiler_rules': checked,
            'regeneration': 'compiler-array prefix persists in Meson compiler coredata',
            'report_dir': config['report_dir'], 'dependencies': config['dependencies']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--version', choices=tuple(PINNED_RELENG))
    parser.add_argument('--state-dir', required=True, type=Path)
    parser.add_argument('--python', type=Path)
    parser.add_argument('--outliner', type=Path)
    parser.add_argument('--env-output', type=Path, help='KEY=value lines, also suitable for GITHUB_ENV')
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--build', type=Path, help='validate an already configured Meson build, without patching Ninja')
    parser.add_argument('--response-format', choices=('gnu', 'windows'))
    parser.add_argument('--skip-dependency-check', action='store_true', help='stub-outliner tests only')
    options = parser.parse_args(argv)
    try:
        if options.build is not None:
            if options.source is not None or options.version is not None or options.python is not None or options.outliner is not None:
                parser.error('--build validation only needs --state-dir and --report')
            result = validate_build(options.state_dir, options.build)
        else:
            if any(value is None for value in (options.source, options.version, options.python, options.outliner)):
                parser.error('prepare requires --source, --version, --python, and --outliner')
            result = prepare(options.source, options.version, options.state_dir,
                             options.python, options.outliner, options.env_output,
                             options.response_format, options.skip_dependency_check)
        outside(absolute_path(options.report), Path(result['source_root']), 'installation report')
        owned_write(absolute_path(options.report), json_bytes(result))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, InstallationError) as error:
        print(f'string outline install: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
