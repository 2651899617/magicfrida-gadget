#!/usr/bin/env python3
"""Snapshot the actual ELF-backing object/link chain on the cloud build host."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
GUM = 'subprojects/frida-gum/gum/gumelfmodule.c'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def tokens(text):
    result, current, i = [], '', 0
    while i < len(text):
        char = text[i]
        if char == '$':
            require(i + 1 < len(text) and text[i + 1] in ' $:', 'unsupported Ninja variable in edge')
            current += text[i + 1]
            i += 2
        elif char.isspace():
            if current:
                result.append(current)
                current = ''
            i += 1
        else:
            current += char
            i += 1
    if current:
        result.append(current)
    return result


def split_edge(line):
    i = 6
    while i < len(line):
        if line[i] == '$':
            i += 2
        elif line[i] == ':':
            return line[6:i], line[i + 1:]
        else:
            i += 1
    raise ValueError('missing Ninja edge separator')


class Inputs:
    def __init__(self, workspace):
        self.workspace = workspace.resolve()
        self.records = {}
        self.saved = set()

    def path(self, value):
        path = Path(value).resolve()
        require(path.is_relative_to(self.workspace), 'input outside cloud workspace: ' + str(path))
        return path

    def add(self, value, save=True):
        path = self.path(value)
        require(path.is_file(), 'missing input: ' + str(path))
        record = {'size': path.stat().st_size, 'sha256': file_sha(path)}
        if path in self.records:
            require(self.records[path] == record, 'input changed during audit: ' + str(path))
        self.records[path] = record
        if save:
            self.saved.add(path)
        return path

    def read(self, value):
        path = self.add(value)
        data = path.read_bytes()
        require(sha(data) == self.records[path]['sha256'], 'input changed while reading')
        return data

    def json(self, value):
        return json.loads(self.read(value))


class Graph:
    def __init__(self, build, inputs):
        self.build, self.inputs = inputs.path(build), inputs
        self.edges, self.includes = {}, set()
        self.parse(self.build / 'build.ninja')
        log = inputs.read(self.build / '.ninja_log').decode('utf-8')
        require(log.startswith('# ninja log v'), 'missing Ninja execution log')
        self.logged = {self.node(row.split('\t')[3]) for row in log.splitlines()[1:]
                       if len(row.split('\t')) == 5}

    def node(self, value):
        path = Path(value)
        return (path if path.is_absolute() else self.build / path).resolve()

    def parse(self, path):
        path = self.inputs.path(path)
        require(path.is_relative_to(self.build) and path not in self.includes and len(self.includes) < 32,
                'unsafe or repeated Ninja include')
        self.includes.add(path)
        text = re.sub(r'\$\r?\n[ \t]*', '', self.inputs.read(path).decode('utf-8'))
        for line in text.splitlines():
            if line.startswith(('include ', 'subninja ')):
                names = tokens(line.split(' ', 1)[1])
                require(len(names) == 1, 'ambiguous Ninja include')
                self.parse(self.node(names[0]))
            elif line.startswith('build '):
                left, right = split_edge(line)
                outputs, arguments = tokens(left), tokens(right)
                require(outputs and arguments, 'empty Ninja edge')
                dependencies = []
                for token in arguments[1:]:
                    if token == '||':
                        break
                    if token != '|':
                        dependencies.append(self.node(token))
                for output in outputs:
                    if output == '|':
                        continue
                    node = self.node(output)
                    require(node not in self.edges, 'duplicate Ninja output')
                    self.edges[node] = (arguments[0], dependencies)

    def chain(self, target, source):
        target, source = self.inputs.path(target), self.inputs.path(source)
        queue, parents, index = [target], {target: None}, 0
        while index < len(queue):
            node = queue[index]
            index += 1
            if node == source:
                result = []
                while node is not None:
                    result.append(node)
                    node = parents[node]
                for node in result:
                    if node in self.edges and self.edges[node][0] != 'phony':
                        require(node in self.logged, 'link dependency absent from execution log: ' + str(node))
                        self.inputs.add(node)
                return result
            require(len(parents) <= 50000, 'Ninja traversal limit exceeded')
            for dependency in self.edges.get(node, ('', []))[1]:
                if dependency not in parents:
                    parents[dependency] = node
                    queue.append(dependency)
        raise ValueError('missing data dependency: ' + str(source) + ' -> ' + str(target))


def archive_members(archive, object_data):
    require(archive.startswith(b'!<arch>\n'), 'regular ar archive required')
    offset, names, matches = 8, b'', []
    while offset < len(archive):
        require(offset + 60 <= len(archive), 'truncated ar header')
        header = archive[offset:offset + 60]
        require(header[58:60] == b'`\n', 'invalid ar member header')
        size = int(header[48:58].decode('ascii').strip())
        require(size >= 0, 'negative ar member size')
        start, end = offset + 60, offset + 60 + size
        require(end <= len(archive), 'ar member exceeds archive')
        name, data = header[:16].decode('ascii').strip(), archive[start:end]
        if name == '//':
            names = data
        elif name.startswith('#1/'):
            length = int(name[3:])
            require(0 <= length <= len(data), 'invalid BSD ar member name')
            name, data = data[:length].decode().rstrip('\0'), data[length:]
        elif re.fullmatch(r'/\d+', name):
            position = int(name[1:])
            require(position < len(names), 'invalid GNU ar name offset')
            name = names[position:].split(b'/\n', 1)[0].decode()
        else:
            name = name.rstrip('/')
        if data == object_data:
            matches.append(name)
        offset = end + (size & 1)
    require(matches, 'compiled Gum object bytes absent from archive')
    return matches


def final_target(inputs, build, name):
    targets = inputs.json(build / 'meson-info/intro-targets.json')
    matches = [target for target in targets if target.get('name') == name]
    require(len(matches) == 1 and len(matches[0]['filename']) == 1, 'unique final target missing: ' + name)
    path = Path(matches[0]['filename'][0])
    path = inputs.path(path if path.is_absolute() else build / path)
    require(path.is_relative_to(build), 'final target outside build')
    return path


def bind_embedded_agent(linked, embedded, rewritten, rewrite, canonical):
    require(rewrite.get('before', {}).get('sha256') == linked['agent_sha256']
            and rewrite.get('before', {}).get('size') == linked['agent_size'],
            'embedded rewrite input differs from Agent linked with repaired Gum')
    require(sha(rewritten) == rewrite.get('after', {}).get('sha256')
            and len(rewritten) == rewrite.get('after', {}).get('size')
            and embedded['sha256'] == sha(rewritten) and embedded['extent'] == len(rewritten),
            'embedded Agent differs from rewritten resource')
    require(canonical.find(rewritten) >= 0, 'canonical server lacks rewritten Agent bytes')


def audit(source, build, version, profile, config_path, manifest_path, output):
    require(not output.exists(), 'audit output must not exist')
    inputs = Inputs(ROOT)
    source, build = inputs.path(source), inputs.path(build)
    config_path, manifest_path = inputs.path(config_path), inputs.path(manifest_path)
    config, manifest = inputs.json(config_path), inputs.json(manifest_path)
    spec = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
    entry = next(row for row in spec['files'] if row['path'] == GUM)
    fixture = inputs.read(ROOT / 'tests/fixtures' / version / GUM)
    require(sha(fixture) == entry['upstream_sha256'], 'pinned Gum fixture differs')
    loader = importlib.util.spec_from_file_location('trusted_collector', ROOT / 'scripts/collect_artifacts.py')
    collector = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(collector)
    selected = collector.recipes.selected_features(spec, ['zygisk-loader'] if profile == 'zygisk' else [])
    expected = collector.recipes.profile_bytes(fixture, entry, selected)
    gum = inputs.path(source / GUM)
    require(inputs.read(gum) == expected, 'actual canonical Gum differs from pinned repair')
    require(manifest['version'] == version and manifest['patches']['features'] == selected,
            'collector version/profile differs')
    rows = [row for row in manifest['patches']['files'] if row['path'] == GUM]
    require(len(rows) == 1 and rows[0]['result_sha256'] == sha(expected), 'collector Gum hash differs')
    require(config['version'] == version and Path(config['source_root']).resolve() == source,
            'compiler config source/version differs')
    for key in ('wrapper', 'outliner'):
        tool = inputs.add(config[key])
        require(file_sha(tool) == config[key + '_sha256'], 'configured compiler tool hash differs: ' + key)
    require(file_sha(ROOT / 'scripts/install_string_outline.py') == config['installer_sha256'],
            'configured installer hash differs')
    for path in (ROOT / 'scripts/audit_elf_backing_ci.py', ROOT / 'scripts/collect_artifacts.py',
                 ROOT / 'scripts/apply_patches.py', ROOT / 'patches/rename.py', ROOT / 'patches' / version / 'spec.json'):
        inputs.add(path)
    graphs, records = {}, []
    for path in sorted((inputs.path(config['report_dir']) / version).glob('*.json')):
        candidate = json.loads(path.read_text(encoding='utf-8'))
        if Path(candidate.get('source', '')).name != 'gumelfmodule.c':
            continue
        require(Path(candidate['source']).resolve() == gum, 'nested Gum consumer differs from canonical repair')
        record = inputs.json(path)
        policy = record.get('outline_runtime_policy')
        require(policy in ('android-arm64', 'android-arm') and record.get('status') == 'compiled'
                and record.get('returncode') == 0 and record.get('source_unchanged') is True
                and record.get('source_sha256') == sha(expected) and record.get('source_sha256_after') == sha(expected)
                and Path(record['config']).resolve() == config_path, 'invalid Gum compilation receipt')
        require(record.get('frida_version') == version and record.get('language') == 'c', 'Gum compiler version/language differs')
        outliner = record.get('outliner_report', {})
        require(outliner.get('ok') is True and outliner.get('runtime_policy') == policy
                and outliner.get('input_sha256') == record.get('preprocessed_sha256')
                and outliner.get('output_sha256') == record.get('transformed_sha256'), 'outlined translation unit differs')
        argv = record['original_expanded_argv']
        require('-c' in argv and any(Path(record['cwd'], value).resolve() == gum for value in argv
                                   if value.endswith('gumelfmodule.c')), 'actual compiler source argument missing')
        target = 'aarch64' if policy == 'android-arm64' else 'arm'
        require(any(target in value and 'android' in value for value in argv), 'Android target argument differs')
        compiler = record['compiler']
        require(compiler.get('returncode') == 0 and 'clang' in compiler.get('version', '').lower(), 'real Clang identity missing')
        # NDK is outside the repository workspace. Hash its executable without publishing a large tool binary.
        compiler_path = Path(compiler['executable']).resolve()
        require(compiler_path.is_file() and compiler_path.stat().st_size == compiler['size'], 'compiler executable size differs')
        compiler_hash = file_sha(compiler_path)
        object_path = inputs.path(record['output'])
        object_data = inputs.read(object_path)
        require(len(object_data) >= 20 and object_data[:6] == b'\x7fELF' + bytes([2 if policy == 'android-arm64' else 1, 1])
                and struct.unpack_from('<HH', object_data, 16) == (1, 183 if policy == 'android-arm64' else 40),
                'Gum object is not matching Android relocatable ELF')
        current_build = inputs.path(record['build_root'])
        require(current_build.is_relative_to(build) and object_path.is_relative_to(current_build), 'Gum output/build root differs')
        if current_build not in graphs:
            graphs[current_build] = Graph(current_build, inputs)
        graph = graphs[current_build]
        agent = final_target(inputs, current_build, 'frida-agent')
        agent_data = inputs.read(agent)
        layout = collector.elf.Layout(agent_data)
        require(layout.extent == len(agent_data), 'Agent has bytes outside ELF extent')
        layout.exported(collector.elf.AGENT_ENTRY)
        chain = graph.chain(agent, object_path)
        archives = [node for node in chain if node.suffix == '.a' and 'frida-gum' in str(node)]
        require(len(archives) == 1, 'unique linked Gum archive missing')
        members = archive_members(inputs.read(archives[0]), object_data)
        source_chain = graph.chain(object_path, gum)
        row = {'policy': policy, 'receipt': str(path.relative_to(ROOT)), 'object': str(object_path.relative_to(ROOT)),
               'object_sha256': sha(object_data), 'archive_members': members, 'source_sha256': sha(expected),
               'agent': str(agent.relative_to(ROOT)), 'agent_sha256': sha(agent_data), 'agent_size': len(agent_data),
               'compiler': compiler, 'compiler_sha256_now': compiler_hash,
               'object_to_agent': [str(node.relative_to(ROOT)) for node in chain],
               'source_to_object': [str(node.relative_to(ROOT)) for node in source_chain]}
        if policy == 'android-arm64':
            gadget = final_target(inputs, current_build, 'frida-gadget')
            server = final_target(inputs, current_build, 'frida-server')
            row['object_to_gadget'] = [str(node.relative_to(ROOT)) for node in graph.chain(gadget, object_path)]
            row['agent_to_server'] = [str(node.relative_to(ROOT)) for node in graph.chain(server, agent)]
        records.append(row)
    require(len(records) == 2 and {row['policy'] for row in records} == {'android-arm64', 'android-arm'},
            'exactly one actual ARM64 and ARM32 Gum compilation required')
    deliveries = {}
    for kind in ('server', 'gadget'):
        record = manifest['artifacts'][kind]
        final = final_target(inputs, build, record['final_target'])
        canonical = inputs.read(final)
        product_path = manifest_path.parent / record['file']
        product = inputs.read(product_path)
        require(sha(canonical) == record['elf_rewrite']['before']['sha256'] and sha(product) == record['sha256']
                and len(product) == record['size'], 'canonical/delivered product hash differs')
        collector.elf.validate_rewrite_report(product, record['elf_rewrite'], kind)
        row = {'file': str(product_path.relative_to(ROOT)), 'sha256': sha(product), 'size': len(product),
               'canonical_sha256': sha(canonical)}
        if kind == 'server':
            agents = collector.elf.verify_embedded_agents(product, collector.elf.AGENT_ENTRY)
            require(agents == record['embedded_agents'], 'embedded Agent manifest differs')
            require(len(agents) == 2, 'server must embed both Agent architectures')
            bindings = []
            for embedded in agents:
                policy = {'aarch64': 'android-arm64', 'arm': 'android-arm'}[embedded['architecture']]
                linked = next(item for item in records if item['policy'] == policy)
                candidates = list((build / 'subprojects/frida-core/src').rglob(
                    'frida-agent-' + ('64' if policy == 'android-arm64' else '32') + '.so.rewrite.json'))
                require(len(candidates) == 1, 'unique embedded Agent rewrite sidecar missing')
                sidecar = inputs.path(candidates[0])
                rewrite = inputs.json(sidecar)
                asset = sidecar.with_name(sidecar.name.removesuffix('.rewrite.json'))
                rewritten = inputs.read(asset)
                collector.elf.validate_rewrite_report(rewritten, rewrite, 'agent')
                bind_embedded_agent(linked, embedded, rewritten, rewrite, canonical)
                begin, extent = embedded['offset'], embedded['extent']
                require(product[begin:begin + extent] == rewritten, 'delivered server Agent bytes differ from resource')
                bindings.append({'policy': policy, 'linked_sha256': linked['agent_sha256'],
                                 'rewrite_sidecar': str(sidecar.relative_to(ROOT)),
                                 'resource': str(asset.relative_to(ROOT)), 'embedded_sha256': sha(rewritten)})
            row['embedded_agents'] = agents
            row['rewrite_bindings'] = bindings
        deliveries[kind] = row
    output.mkdir(parents=True)
    archive = output / 'evidence.tar.gz'
    with tarfile.open(archive, 'w:gz', compresslevel=1) as stream:
        for path in sorted(inputs.saved):
            inputs.add(path)
            stream.add(path, arcname=path.relative_to(ROOT).as_posix(), recursive=False)
    for path in inputs.records:
        inputs.add(path, save=False)
    report = {'schema': 1, 'status': 'verified-source-object-archive-agent-server-chain',
              'version': version, 'profile': profile, 'github_commit': __import__('os').environ.get('GITHUB_SHA'),
              'github_run_id': __import__('os').environ.get('GITHUB_RUN_ID'), 'gum_sha256': sha(expected),
              'compilations': records, 'products': deliveries,
              'inputs': {path.relative_to(ROOT).as_posix(): value for path, value in sorted(inputs.records.items())},
              'evidence': {'file': archive.name, 'sha256': file_sha(archive), 'size': archive.stat().st_size},
              'android_runtime_tested': False,
              'limitations': ['Compiler executable is hashed on the build host, not included in evidence.',
                              'Temporary preprocessed/transformed bytes are recorded by receipts, not retained.',
                              'This is build provenance, not a signed reproducible-build attestation.']}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--version', choices=('16.7.19', '17.25.2'), required=True)
    parser.add_argument('--profile', choices=('compatible', 'zygisk'), required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.source, args.build, args.version, args.profile, args.config, args.manifest, args.out)
        print(json.dumps({'status': report['status'], 'gum_sha256': report['gum_sha256'], 'evidence': report['evidence']}))
    except (OSError, ValueError, KeyError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
