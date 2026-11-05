#!/usr/bin/env python3
"""Build an independent nianchu Java bridge bundle for Frida 17.

Run with python -I. A new output directory holds four release artifacts:
.js, .patch-report.json, .package-lock.json and .manifest.json. Build inputs live
in an isolated private npm project with separate fixed official archives and a
locked dependency graph. The work directory defaults to out/_build, or a safe
system temporary path if out contains URL-escaped characters; --work-dir can
select a new ASCII path without spaces. Build inputs are retained for auditing.
This never edits system frida.exe, Python packages, the project's generator, or
a user's npm installation. npm lifecycle scripts are disabled. Compilation is
a host build, not an Android runtime test. Load Java-dependent code in the same
Frida Script; Java globals are not shared between separate Scripts.
"""

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import unquote, urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('nianchu_reference_bridge', ROOT / 'scripts/patch_reference_bridge.py')
bridge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bridge)

VERSION = '7.0.13'
COMPILER_VERSION = '16.4.1'
COMPILER_PIN = {
    'url': 'https://registry.npmjs.org/frida-compile/-/frida-compile-16.4.1.tgz',
    'integrity': 'sha512-xI9HNtUFpHxuKBGXaL6XJAYH1zWTvNJDrHRnz1hp0oS24iPHt6c01Jmm3qljZek3oQWn8HhvfNvrzfgbsKzoBQ==',
    'shasum': '5a1d7cf946a28d375aa2c2eb4d507f6c8520e765',
    'sha256': 'df71ddd84115301b5d0e12f3100e12cb90dea142406c4b72ed3f4d69aac3231a',
}
ENTRYPOINT = b"import Java from 'frida-java-bridge';\nglobalThis.Java = Java;\n"
TSCONFIG = {
    'files': ['entrypoint.js'],
    'compilerOptions': {'allowJs': True, 'checkJs': False, 'skipLibCheck': True, 'types': []},
}
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def verify_archive(data, pin):
    integrity = 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode('ascii')
    if (bridge.digest(data) != pin['sha256']
            or hashlib.sha1(data).hexdigest() != pin['shasum']
            or integrity != pin['integrity']):
        raise ValueError('official npm archive hash/integrity mismatch: ' + pin['url'])


def archive_files(data):
    """Read verified tar data without extracting or executing any package file."""
    files = {}
    size = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            name = member.name
            path = PurePosixPath(name)
            if ('\\' in name or path.is_absolute() or '..' in path.parts
                    or any(':' in part or part.endswith((' ', '.')) for part in path.parts)
                    or not path.parts or path.parts[0] != 'package'
                    or name.rstrip('/') != path.as_posix()):
                raise ValueError('unsafe npm archive member: ' + name)
            if member.isdir():
                continue
            if not member.isfile() or len(path.parts) < 2:
                raise ValueError('npm archives must contain only regular package files')
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if relative in files:
                raise ValueError('duplicate npm archive member: ' + relative)
            size += member.size
            if size > MAX_ARCHIVE_BYTES:
                raise ValueError('npm archive exceeds unpacked size limit')
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError('unreadable npm archive member: ' + name)
            with stream:
                files[relative] = stream.read()
    if not files:
        raise ValueError('empty npm package archive')
    return files


def download_archive(pin, directory):
    # Each downloaded archive has its own new empty directory; the compiler is
    # invoked from the trusted project, never from these download directories.
    directory.mkdir(parents=True, exist_ok=False)
    with urlopen(pin['url'], timeout=90) as response:
        final_url = urlparse(response.geturl())
        if final_url.scheme != 'https' or final_url.hostname != 'registry.npmjs.org':
            raise ValueError('unexpected npm registry redirect')
        data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError('npm archive exceeds download size limit')
    verify_archive(data, pin)
    archive = directory / 'package.tgz'
    with archive.open('xb') as output:
        output.write(data)
    return archive, archive_files(data)


def resolve_tool(value, label):
    located = shutil.which(str(value))
    path = Path(located if located is not None else value).absolute()
    if not path.is_file():
        raise ValueError(label + ' executable not found: ' + str(value))
    return path.resolve()


def npm_command(npm, node):
    npm = resolve_tool(npm, 'npm')
    if npm.suffix.lower() == '.js':
        return [str(node), str(npm)]
    # Avoid a Windows .cmd shell and quoting of paths containing spaces. This
    # also supports npm symlinks on Unix by resolving to bin/npm-cli.js above.
    cli = npm.parent / 'node_modules/npm/bin/npm-cli.js'
    if cli.is_file():
        return [str(node), str(cli.resolve())]
    if npm.suffix.lower() in ('.cmd', '.bat'):
        raise ValueError('npm wrapper lacks npm-cli.js; pass --npm <absolute npm-cli.js>')
    return [str(npm)]


def controlled_environment(work):
    env = dict(os.environ)
    for name in list(env):
        if name.upper().startswith('NPM_CONFIG_') or name.upper() in ('NODE_OPTIONS', 'NODE_PATH'):
            del env[name]
    config = work / 'config'
    config.mkdir()
    for name in ('user.npmrc', 'global.npmrc'):
        (config / name).write_bytes(b'')
    env.update({
        'npm_config_userconfig': str(config / 'user.npmrc'),
        'npm_config_globalconfig': str(config / 'global.npmrc'),
        'npm_config_cache': str(work / 'npm-cache'),
        'npm_config_registry': 'https://registry.npmjs.org/',
        'npm_config_ignore_scripts': 'true',
        'npm_config_audit': 'false',
        'npm_config_fund': 'false',
        'npm_config_update_notifier': 'false',
    })
    return env


def run_checked(command, project, env):
    return subprocess.run(command, cwd=project, env=env, check=True,
                          capture_output=True, text=True, encoding='utf-8',
                          errors='replace', timeout=600)


def verify_lock(lock, pins):
    if not isinstance(lock, dict):
        raise ValueError('npm lock must be a JSON object')
    packages = lock.get('packages')
    if lock.get('lockfileVersion') not in (2, 3) or not isinstance(packages, dict):
        raise ValueError('npm must produce a v2 or v3 package lock')
    if not all(isinstance(relative, str) and isinstance(entry, dict)
               for relative, entry in packages.items()):
        raise ValueError('npm lock package entries must be objects')
    for name, (version, pin) in pins.items():
        entry = packages.get('node_modules/' + name, {})
        if (entry.get('version') != version or entry.get('integrity') != pin['integrity']
                or entry.get('link') is True):
            raise ValueError('npm lock fixed package identity mismatch: ' + name)
    dependencies = {}
    for relative, entry in sorted(packages.items()):
        if relative == '':
            continue
        path = PurePosixPath(relative)
        if ('\\' in relative or path.is_absolute() or '..' in path.parts
                or path.as_posix() != relative or not relative.startswith('node_modules/')
                or entry.get('link') is True or not entry.get('version')):
            raise ValueError('unsupported npm lock dependency path: ' + relative)
        resolved = entry.get('resolved', '')
        integrity = entry.get('integrity', '')
        if not isinstance(resolved, str) or not isinstance(integrity, str):
            raise ValueError('npm lock resolved/integrity must be strings: ' + relative)
        if relative in {'node_modules/' + name for name in pins}:
            if not resolved.startswith('file:'):
                raise ValueError('fixed package must resolve to its verified local archive')
        else:
            url = urlparse(resolved)
            if url.scheme != 'https' or url.hostname != 'registry.npmjs.org':
                raise ValueError('dependency must resolve to the official npm registry: ' + relative)
        if not integrity.startswith(('sha512-', 'sha1-')):
            raise ValueError('missing npm dependency integrity: ' + relative)
        dependencies[relative] = {
            'version': entry['version'], 'resolved': resolved, 'integrity': integrity,
        }
    return dependencies


def verify_compiler(package, expected_files):
    package = bridge.checked_path(package, 'compiler package')
    if not package.is_dir():
        raise ValueError('installed compiler package missing')
    files = {}

    def walk_error(error):
        raise error

    for directory, dirs, names in os.walk(package, followlinks=False, onerror=walk_error):
        parent = Path(directory)
        for name in dirs + names:
            path = parent / name
            bridge.checked_path(path, 'compiler package member')
        if parent == package and 'node_modules' in dirs:
            # Validate the directory itself before excluding nested dependencies
            # from the official compiler tarball's own file inventory.
            dirs.remove('node_modules')
        for name in names:
            path = parent / name
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError('compiler package must contain only regular files')
            files[path.relative_to(package).as_posix()] = path.read_bytes()
    actual = bridge.package_hashes(files)
    if actual != bridge.package_hashes(expected_files):
        raise ValueError('installed official compiler file inventory/hash mismatch')
    metadata = json.loads(files['package.json'])
    bin_field = metadata.get('bin')
    cli_path = bin_field.get('frida-compile') if isinstance(bin_field, dict) else bin_field
    if (metadata.get('name') != 'frida-compile' or metadata.get('version') != COMPILER_VERSION
            or cli_path != 'dist/cli.js'):
        raise ValueError('official compiler package metadata mismatch')
    return actual


def compiler_path_safe(path):
    # Official 16.4.1 derives filesystem paths by slicing import.meta.url. Do
    # not patch the compiler: avoid percent-encoded work roots instead.
    uri = Path(path).absolute().as_uri()
    return uri == unquote(uri)


def create_work_directory(out, work_dir):
    if work_dir is not None:
        work = bridge.checked_path(work_dir, 'build work directory')
        if work.exists() or work.is_relative_to(out) or out.is_relative_to(work):
            raise ValueError('explicit work directory must be new and separate from output')
        if not compiler_path_safe(work):
            raise ValueError('work directory must not need URL escaping; use an ASCII path without spaces')
        work.mkdir(parents=True)
        return work
    default = out / '_build'
    if compiler_path_safe(default):
        default.mkdir()
        return default
    temporary_root = bridge.checked_path(tempfile.gettempdir(), 'system temporary directory')
    if not compiler_path_safe(temporary_root):
        raise ValueError('system temporary path needs URL escaping; pass --work-dir with a new ASCII path without spaces')
    return Path(tempfile.mkdtemp(prefix='nianchu-bridge-build-', dir=temporary_root)).resolve()


def build(out, version=VERSION, npm='npm', node='node', work_dir=None):
    if version != VERSION:
        raise ValueError('external reference bundle supports only bridge ' + VERSION)
    out = bridge.checked_path(out, 'build output')
    if out.exists():
        raise ValueError('build output must be a new independent directory')
    node = resolve_tool(node, 'node')
    npm = npm_command(npm, node)
    inventory = bridge.load_inventory(version)
    out.mkdir(parents=True)
    work = create_work_directory(out, work_dir)
    print('Build inputs retained in ' + str(work), flush=True)
    project = work / 'project'
    project.mkdir()
    env = controlled_environment(work)
    bridge_archive, bridge_files = download_archive(bridge.SOURCE_PINS[version], work / 'downloads/bridge')
    if bridge.package_hashes(bridge_files) != inventory:
        raise ValueError('official bridge archive file inventory/hash mismatch')
    compiler_archive, compiler_files = download_archive(COMPILER_PIN, work / 'downloads/compiler')
    (project / 'package.json').write_bytes(bridge.json_bytes({
        'name': 'nianchu-reference-java-bridge-build', 'version': '1.0.0',
        'private': True, 'type': 'module',
        'dependencies': {
            # npm's file spec is a filesystem path, not a percent-encoded URL.
            # Relative POSIX paths also work in Windows non-ASCII workspaces.
            'frida-java-bridge': 'file:' + Path(os.path.relpath(bridge_archive, project)).as_posix(),
            'frida-compile': 'file:' + Path(os.path.relpath(compiler_archive, project)).as_posix(),
        },
    }))
    # The only new executable source is in the trusted project directory, kept
    # separate from archives and installed package directories.
    entrypoint = project / 'entrypoint.js'
    entrypoint.write_bytes(ENTRYPOINT)
    tsconfig_data = bridge.json_bytes(TSCONFIG)
    (project / 'tsconfig.json').write_bytes(tsconfig_data)
    node_version = run_checked([str(node), '--version'], project, env).stdout.strip()
    npm_version = run_checked([*npm, '--version'], project, env).stdout.strip()
    flags = ['--ignore-scripts', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/']
    run_checked([*npm, 'install', '--package-lock-only', *flags], project, env)
    lock_path = project / 'package-lock.json'
    lock_data = lock_path.read_bytes()
    lock = json.loads(lock_data)
    dependencies = verify_lock(lock, {
        'frida-java-bridge': (version, bridge.SOURCE_PINS[version]),
        'frida-compile': (COMPILER_VERSION, COMPILER_PIN),
    })
    run_checked([*npm, 'ci', '--omit=dev', *flags], project, env)
    if lock_path.read_bytes() != lock_data:
        raise ValueError('npm ci changed the verified dependency lock')
    package = project / 'node_modules/frida-java-bridge'
    compiler = project / 'node_modules/frida-compile'
    compiler_hashes = verify_compiler(compiler, compiler_files)
    stem = 'nianchu-java-bridge-' + version
    report_path = out / (stem + '.patch-report.json')
    report = bridge.patch(package, version, report_path)
    bundled = project / (stem + '.js')
    command = [str(node), str(compiler / 'dist/cli.js'), str(entrypoint),
               '-o', str(bundled), '-S']
    run_checked(command, project, env)
    bundle_data = bundled.read_bytes()
    if not bundle_data:
        raise ValueError('compiler produced an empty bridge bundle')
    if b'Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod)' in bundle_data:
        raise ValueError('reference hook unexpectedly present in the emitted bundle')
    _, _, current_hashes, state, _ = bridge.preflight(package, version)
    if state != 'patched' or current_hashes != report['after']:
        raise ValueError('compiled bridge input drifted after patching')
    if verify_compiler(compiler, compiler_files) != compiler_hashes:
        raise ValueError('compiler input changed during compilation')
    if (entrypoint.read_bytes() != ENTRYPOINT or lock_path.read_bytes() != lock_data
            or (project / 'tsconfig.json').read_bytes() != tsconfig_data):
        raise ValueError('build entrypoint, TypeScript config or lock changed during compilation')
    if json.loads(report_path.read_bytes()) != report:
        raise ValueError('patch report changed during compilation')
    artifacts = {
        stem + '.js': bundle_data,
        stem + '.patch-report.json': report_path.read_bytes(),
        stem + '.package-lock.json': lock_data,
    }
    manifest = {
        'schema': 1,
        'author': bridge.AUTHOR,
        'profile': bridge.PROFILE,
        'bridge_version': version,
        'frida_major': 17,
        'format': 'frida-compile-esm-bundle',
        'integration': 'external-client-bridge',
        'entrypoint': ENTRYPOINT.decode('utf-8'),
        'entrypoint_sha256': bridge.digest(ENTRYPOINT),
        'typescript_config': TSCONFIG,
        'typescript_config_sha256': bridge.digest(tsconfig_data),
        'build_work_directory': str(work),
        'bridge_archive': bridge.SOURCE_PINS[version],
        'compiler_version': COMPILER_VERSION,
        'compiler_archive': COMPILER_PIN,
        'compiler_files': compiler_hashes,
        'compiler_args': ['entrypoint.js', '-o', stem + '.js', '-S'],
        'node_version': node_version,
        'npm_version': npm_version,
        'npm_lifecycle_scripts_executed': False,
        'dependency_lock_sha256': bridge.digest(lock_data),
        'dependencies': dependencies,
        'bridge_before': report['before'],
        'bridge_after': current_hashes,
        'patch_files': report['patch_files'],
        'bundle_built': True,
        'runtime_tested': False,
        'system_frida_modified': False,
        'python_packages_modified': False,
        'loading_scope': 'Java-dependent code must run in the same Frida Script; no cross-Script globals',
        'artifacts': {name: {'sha256': bridge.digest(data), 'size': len(data)}
                      for name, data in sorted(artifacts.items())},
    }
    # Publish the independent manifest last, only after all host build guards.
    for name, data in artifacts.items():
        if name.endswith('.patch-report.json'):
            continue
        with (out / name).open('xb') as output:
            output.write(data)
    with (out / (stem + '.manifest.json')).open('xb') as output:
        output.write(bridge.json_bytes(manifest))
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', choices=(VERSION,), required=True)
    parser.add_argument('--out', type=Path, required=True, help='new independent build/artifact directory')
    parser.add_argument('--npm', default='npm', help='npm executable or absolute npm-cli.js; default: npm on PATH')
    parser.add_argument('--node', default='node', help='Node executable; default: node on PATH')
    parser.add_argument('--work-dir', type=Path,
                        help='optional new separate ASCII build directory without spaces; inputs retained')
    args = parser.parse_args(argv)
    try:
        build(args.out, args.version, args.npm, args.node, args.work_dir)
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print((error.stdout or '') + (error.stderr or ''), file=sys.stderr)
        return 1
    print('PASS: nianchu-java-bridge-' + args.version + '.js and independent manifest in '
          + str(args.out.resolve()) + '; runtime_tested=false')
    return 0


if __name__ == '__main__':
    sys.exit(main())
