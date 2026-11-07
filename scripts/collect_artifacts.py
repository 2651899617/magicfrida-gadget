#!/usr/bin/env python3
"""Collect only installed final targets named by Meson introspection."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('elf_audit', ROOT / 'patches/rename.py')
elf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf)
spec = importlib.util.spec_from_file_location('patch_recipes', ROOT / 'scripts/apply_patches.py')
recipes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipes)


def validate_source_report(source, expected):
    """Check verifier report completeness, not authenticity or runtime behavior."""
    if not isinstance(source, dict) or type(source.get('schema')) is not int or source['schema'] != 1:
        raise ValueError('invalid source report schema')
    if source.get('commit') != expected['commit'] or source.get('submodules') != expected['submodules']:
        raise ValueError('source provenance mismatch')
    if source.get('version') != expected['version'] or source.get('ndk_revision') != expected['ndk_revision']:
        raise ValueError('version/NDK provenance mismatch')
    if source.get('runtime_tested') is not False:
        raise ValueError('source report must not claim runtime validation')
    # These are the verifier's actual top-level fields, not a synthetic toolchain object.
    for name in ('python', 'node', 'npm', 'git'):
        value = source.get(name)
        if not isinstance(value, str) or not value.strip() or '\n' in value or '\r' in value:
            raise ValueError('missing or invalid source toolchain field: ' + name)
    lines = source.get('submodule_status')
    if not isinstance(lines, list) or not lines:
        raise ValueError('missing source submodule_status')
    status = {}
    for line in lines:
        # verify_source.run().strip() removes the first status line's leading space.
        match = re.fullmatch(r' ?([0-9a-f]{40}) ([^\r\n]+?)(?: \([^\r\n]*\))?', line) if isinstance(line, str) else None
        if not match or match[2] != match[2].strip() or match[2] in status:
            raise ValueError('invalid, drifting or duplicate source submodule_status')
        status[match[2]] = match[1]
    if any(status.get(path) != sha for path, sha in expected['submodules'].items()):
        raise ValueError('source submodule_status provenance mismatch')


def validate_patch_report(patches, expected):
    if not isinstance(patches, dict) or type(patches.get('schema')) is not int or patches['schema'] != 1:
        raise ValueError('invalid patch report schema')
    version = expected['version']
    recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
    if recipe['version'] != version or recipe['source'] != expected['submodules']:
        raise ValueError('patch spec provenance mismatch')
    if patches.get('version') != version or patches.get('profile') != 'nianchu-compatible' or patches.get('dry_run') is not False:
        raise ValueError('patch report is not an applied version/profile report')
    features = patches.get('features')
    if (not isinstance(features, list) or any(not isinstance(feature, str) for feature in features)
            or len(features) != len(set(features)) or not set(features).issubset(recipe['features'])):
        raise ValueError('invalid, duplicate or unsupported patch features')
    if (patches.get('java_bridge') != recipe['java_bridge']
            or patches.get('binary_rewriting') is not False or patches.get('runtime_tested') is not False):
        raise ValueError('patch report policy mismatch')
    files = patches.get('files')
    if not isinstance(files, list):
        raise ValueError('incomplete patch file report')
    records = {}
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str) or item['path'] in records:
            raise ValueError('invalid or duplicate patch file report')
        records[item['path']] = item
    paths = [entry['path'] for entry in recipe['files']]
    if not paths or len(paths) != len(set(paths)) or set(records) != set(paths):
        raise ValueError('patch file set mismatch (missing, extra or duplicate files)')
    for entry in recipe['files']:
        path = entry['path']
        base = (ROOT / 'tests' / 'fixtures' / version / path).read_bytes()
        upstream = hashlib.sha256(base).hexdigest()
        if upstream != entry['upstream_sha256']:
            raise ValueError('corrupt pinned source fixture: ' + path)
        after = recipes.transform(base, entry['edits'])
        for feature in features:
            after = recipes.transform(after, entry.get('optional', {}).get(feature, []))
        record = records[path]
        if record.get('upstream_sha256') != upstream or record.get('result_sha256') != hashlib.sha256(after).hexdigest():
            raise ValueError('patch hash mismatch: ' + path)
        statuses = ('verified-unchanged',) if after == base else ('applied', 'already-applied')
        if record.get('status') not in statuses:
            raise ValueError('failed or inconsistent patch status: ' + path)


def final_outputs(build, targets):
    if (not isinstance(targets, dict) or set(targets) != {'server', 'gadget'}
            or any(not isinstance(name, str) or not name for name in targets.values())
            or len(set(targets.values())) != 2):
        raise ValueError('both distinct final server and gadget targets are required')
    if not isinstance(build, list) or any(not isinstance(item, dict) for item in build):
        raise ValueError('invalid Meson target introspection')
    result = {}
    for kind, name in targets.items():
        matches = [item for item in build if item.get('name') == name]
        if len(matches) != 1:
            raise ValueError('expected one final target: ' + name)
        item = matches[0]
        filenames = item.get('filename')
        if (item.get('type') != 'custom' or item.get('installed') is not True
                or not isinstance(filenames, list) or len(filenames) != 1
                or not isinstance(filenames[0], str) or not filenames[0]):
            raise ValueError('not a unique installed post-processed target: ' + name)
        result[kind] = Path(filenames[0])
    return result


def artifact_variant(kind, features, rewritten=False):
    variant = '-entry-renamed' if 'agent-entrypoint-rename' in features else ''
    if rewritten:
        variant += '-elf-rewritten'
    if kind == 'gadget' and 'gadget-json-config' in features:
        variant += '-json-config'
    return variant


def gadget_config_lookup(kind, features):
    if kind != 'gadget':
        return 'not-applicable'
    sidecars = ['.config', '.config.so']
    if 'gadget-json-config' in features:
        sidecars.insert(1, '.json')
    return {'android_sidecars': sidecars, 'inline_config': 'takes-precedence',
            'source_contract': 'verified', 'runtime_lookup': 'not-tested'}


def collect(build_dir, version, out, source_report, patch_report, rewrite_elf=False):
    manifest = json.loads((ROOT / 'versions.json').read_text(encoding='utf-8'))
    versions = [item for item in manifest['versions'] if item['version'] == version]
    if len(versions) != 1:
        raise ValueError('unsupported version')
    expected = versions[0]
    source = json.loads(source_report.read_text(encoding='utf-8'))
    patches = json.loads(patch_report.read_text(encoding='utf-8'))
    validate_source_report(source, expected)
    validate_patch_report(patches, expected)
    targets = json.loads((build_dir / 'meson-info/intro-targets.json').read_text(encoding='utf-8'))
    outputs = final_outputs(targets, expected['targets'])
    checked, final_paths = {}, set()
    for kind, path in outputs.items():
        if kind == 'gadget' and path.name != 'nianchu-gadget.so':
            raise ValueError('unexpected final Gadget filename: ' + path.name)
        if not path.is_absolute():
            path = build_dir / path
        if path.is_symlink():
            raise ValueError('final output must not be a symlink: ' + str(path))
        path = path.resolve()
        if kind == 'gadget' and path.name != 'nianchu-gadget.so':
            raise ValueError('unexpected resolved final Gadget filename: ' + path.name)
        if not path.is_relative_to(build_dir.resolve()) or not path.is_file():
            raise ValueError('missing final output in build directory: ' + str(path))
        if path in final_paths:
            raise ValueError('final server and gadget outputs must be distinct files')
        final_paths.add(path)
        data = path.read_bytes()
        original = data
        rewrite_report = None
        if rewrite_elf:
            data, rewrite_report = elf.rewrite(data, kind)
            elf.validate_rewrite_report(data, rewrite_report, kind)
        info = elf.audit(data)
        renamed_entry = 'agent-entrypoint-rename' in patches['features']
        embedded_agents = None
        if kind == 'server' and rewrite_elf:
            embedded_agents = elf.verify_embedded_agents(data, elf.AGENT_ENTRY)
            info['embedded_agents'] = embedded_agents
        info['agent_entrypoint'] = {
            'symbol': ('nianchu_agent_main' if renamed_entry else 'frida_agent_main') if kind == 'server' else None,
            'scope': 'embedded-agent' if kind == 'server' else 'not-applicable-gadget',
            'source_contract': 'verified' if kind == 'server' else 'not-applicable',
            'final_symbol_lookup': ('verified' if embedded_agents is not None else 'not-tested') if kind == 'server' else 'not-applicable',
        }
        if rewrite_report is not None:
            info['elf_rewrite'] = rewrite_report
            info['binary_modified'] = True
        if version.encode() not in data:
            raise ValueError('version string missing from final ' + kind)
        checked[kind] = (path, original, data, info, rewrite_report)
    if out.exists():
        raise ValueError('output directory must not exist')
    out.mkdir(parents=True)
    artifacts = {}
    for kind, (path, original, data, info, rewrite_report) in checked.items():
        label = 'gadget-zygisk' if kind == 'gadget' and 'zygisk-loader' in patches['features'] else kind
        variant = artifact_variant(kind, patches['features'], rewrite_elf)
        name = 'nianchu-' + label + variant + '-' + version + '-android-arm64' + ('.so' if kind == 'gadget' else '')
        destination = out / name
        if rewrite_report is None:
            shutil.copyfile(path, destination)
        else:
            destination.write_bytes(data)
            (out / (name + '.rewrite.json')).write_text(json.dumps(rewrite_report, indent=2) + '\n', encoding='utf-8')
        if kind == 'server':
            destination.chmod(0o755)
        if destination.read_bytes() != data or path.read_bytes() != original:
            raise ValueError('copy byte identity mismatch')
        artifacts[kind] = {'file': name, 'final_target': expected['targets'][kind],
                           'final_filename': path.name,
                           'gadget_config_lookup': gadget_config_lookup(kind, patches['features']), **info}
    report = {'schema': 1, 'version': version, 'source': source, 'patches': patches,
              'artifacts': artifacts, 'binary_modified': rewrite_elf,
              'validation': {'build_outputs': 'verified', 'protocol_handshake': 'not-tested',
                             'zygisk_load': 'not-tested', 'app_detection': 'not-tested'}}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--source-report', required=True, type=Path)
    parser.add_argument('--patch-report', required=True, type=Path)
    parser.add_argument('--rewrite-elf', action='store_true')
    args = parser.parse_args()
    try:
        result = collect(args.build.resolve(), args.version, args.out, args.source_report, args.patch_report, args.rewrite_elf)
        print(json.dumps(result['artifacts'], indent=2))
    except (OSError, ValueError, ImportError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
