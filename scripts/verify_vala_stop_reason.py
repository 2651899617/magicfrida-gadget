#!/usr/bin/env python3
"""Compile and run the pinned StopReason declarations. Host GLib only, not Android."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ('16.7.19', '17.25.2')
AGENT_PATH = 'subprojects/frida-core/lib/agent/agent.vala'
SCOPE = 'Host GLib only'
EXPECTED_OUTPUT = '''scope=Host GLib only
gtype=NianchuAgentStopReason
values=0,1
value[0]=FRIDA_AGENT_STOP_REASON_UNLOAD|unload
value[1]=FRIDA_AGENT_STOP_REASON_PROCESS_TRANSITION|process-transition
lookup-by-name=0,1
lookup-by-nick=0,1
property-default=0
property-direct-read-write=1,0
property-set-get=1,0
PASS
'''


class MissingTool(ValueError):
    """An executable is absent; a present but failing compiler is not missing."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def extract_stop_reason(text):
    """Return the actual private enum and its immediately preceding CCode verbatim."""
    # Preserve offsets while ignoring braces/declarations inside comments and strings.
    masked = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\r\n]*|/\*[\s\S]*?\*/',
                    lambda match: re.sub(r'[^\r\n]', ' ', match[0]), text)
    matches = list(re.finditer(r'\b(?:(private|public|internal)\s+)?enum\s+StopReason\s*\{', masked))
    if len(matches) != 1 or matches[0][1] != 'private':
        raise ValueError('expected exactly one private enum StopReason declaration')
    enum = matches[0]
    line_start = text.rfind('\n', 0, enum.start()) + 1
    if text[line_start:enum.start()].strip():
        raise ValueError('StopReason declaration must start on its own line')
    namespaces = list(re.finditer(r'\bnamespace\s+Frida\s*\.\s*Agent\s*\{', masked[:line_start]))
    if not namespaces:
        raise ValueError('StopReason must be in namespace Frida.Agent')
    scope = masked[namespaces[-1].end() - 1:line_start]
    if scope.count('{') - scope.count('}') != 1:
        raise ValueError('StopReason must be directly inside namespace Frida.Agent')

    end, depth = None, 0
    for brace in re.finditer(r'[{}]', masked[enum.end() - 1:]):
        depth += 1 if brace[0] == '{' else -1
        if depth == 0:
            end = enum.end() + brace.start()
            break
    if end is None:
        raise ValueError('unterminated StopReason declaration')
    if text[end:end + 2] == '\r\n':
        end += 2
    elif text[end:end + 1] == '\n':
        end += 1

    prefix = masked[:line_start].rstrip()
    if not prefix.endswith(']'):
        raise ValueError('StopReason is missing its immediately preceding CCode in the actual spec profile')
    depth, opening = 0, None
    for position in range(len(prefix) - 1, -1, -1):
        if prefix[position] == ']':
            depth += 1
        elif prefix[position] == '[':
            depth -= 1
            if depth == 0:
                opening = position
                break
    if opening is None or not re.fullmatch(r'\[CCode\s*\([\s\S]*\)\]', text[opening:len(prefix)]):
        raise ValueError('StopReason is missing its immediately preceding CCode in the actual spec profile')
    start = text.rfind('\n', 0, opening) + 1
    if text[start:opening].strip():
        raise ValueError('StopReason CCode must start on its own line')
    return text[start:end]


def apply_edits(text, edits):
    for edit in edits:
        old, new, count = edit['old'], edit['new'], edit['count']
        if (not isinstance(old, str) or not old or not isinstance(new, str)
                or type(count) is not int or count < 0):
            raise ValueError('invalid pinned edit')
        if text.count(old) != count:
            raise ValueError('expected exactly ' + str(count) + ' occurrences of ' + repr(old))
        text = text.replace(old, new)
    return text


def load_stop_reason(version, root=ROOT):
    """Read only the actual spec/fixture, verify SHA, then replay its default profile."""
    if version not in VERSIONS:
        raise ValueError('unsupported version: ' + version)
    root = Path(root).resolve()
    spec_path = root / 'patches' / version / 'spec.json'
    fixture_path = root / 'tests' / 'fixtures' / version / AGENT_PATH
    for path in (spec_path, fixture_path):
        if path.is_symlink() or not path.is_file():
            raise ValueError('required regular pinned input missing: ' + str(path))
    spec_bytes, base = spec_path.read_bytes(), fixture_path.read_bytes()
    spec = json.loads(spec_bytes.decode('utf-8'))
    if spec['version'] != version:
        raise ValueError('pinned spec version mismatch')
    entries = [entry for entry in spec['files'] if entry['path'] == AGENT_PATH]
    if len(entries) != 1:
        raise ValueError('expected exactly one agent.vala spec entry')
    entry = entries[0]
    if digest(base) != entry['upstream_sha256']:
        raise ValueError('corrupt pinned source fixture: ' + str(fixture_path))
    features = spec.get('default_features', [])
    available = spec['features']
    if (len(features) != len(set(features)) or len(available) != len(set(available))
            or not set(features).issubset(available)):
        raise ValueError('invalid default features')
    text = apply_edits(base.decode('utf-8'), entry['edits'])
    for feature in features:
        text = apply_edits(text, entry.get('optional', {}).get(feature, []))
    declaration = extract_stop_reason(text)
    provenance = {'version': version, 'namespace': 'Frida.Agent',
                  'spec': {'path': str(spec_path), 'sha256': digest(spec_bytes)},
                  'fixture': {'path': str(fixture_path), 'sha256': digest(base)},
                  'upstream_sha256': entry['upstream_sha256'],
                  'pinned_source': spec['source'], 'features': features,
                  'patched_agent_sha256': digest(text.encode('utf-8')),
                  'declaration': declaration, 'declaration_sha256': digest(declaration.encode('utf-8'))}
    return declaration, provenance


PROGRAM = r'''// Host GLib only. The enum below is extracted verbatim from the pinned profile.
namespace Frida.Agent {
__STOP_REASON__
	private class Probe : GLib.Object {
		public StopReason stop_reason { get; set; default = StopReason.UNLOAD; }

		private static bool check (bool condition, string description) {
			if (!condition)
				stderr.printf ("FAIL: %s\n", description);
			return condition;
		}

		private static int main (string[] args) {
			var enum_type = typeof (StopReason);
			if (!check (enum_type.is_enum () && enum_type.name () == "NianchuAgentStopReason", "registered GType name"))
				return 1;
			if (!check (GLib.Type.from_name ("NianchuAgentStopReason") == enum_type &&
					GLib.Type.from_name ("FridaAgentStopReason") == GLib.Type.INVALID, "GType lookup"))
				return 1;
			if (!check ((int) StopReason.UNLOAD == 0 && (int) StopReason.PROCESS_TRANSITION == 1, "enum integers"))
				return 1;
			GLib.EnumClass klass = (GLib.EnumClass) enum_type.class_ref ();
			if (!check (klass.n_values == 2 && klass.minimum == 0 && klass.maximum == 1, "enum class range"))
				return 1;
			unowned GLib.EnumValue? unload = klass.get_value (0);
			unowned GLib.EnumValue? transition = klass.get_value (1);
			if (!check (unload != null && transition != null && klass.get_value (2) == null, "enum value lookup"))
				return 1;
			if (!check (unload.value == 0 && unload.value_name == "FRIDA_AGENT_STOP_REASON_UNLOAD" &&
					unload.value_nick == "unload", "unload value_name/nick"))
				return 1;
			if (!check (transition.value == 1 && transition.value_name == "FRIDA_AGENT_STOP_REASON_PROCESS_TRANSITION" &&
					transition.value_nick == "process-transition", "transition value_name/nick"))
				return 1;
			unowned GLib.EnumValue? name0 = klass.get_value_by_name ("FRIDA_AGENT_STOP_REASON_UNLOAD");
			unowned GLib.EnumValue? name1 = klass.get_value_by_name ("FRIDA_AGENT_STOP_REASON_PROCESS_TRANSITION");
			unowned GLib.EnumValue? nick0 = klass.get_value_by_nick ("unload");
			unowned GLib.EnumValue? nick1 = klass.get_value_by_nick ("process-transition");
			if (!check (name0 != null && name1 != null && nick0 != null && nick1 != null, "name/nick lookups exist"))
				return 1;
			if (!check (name0.value == 0 && name1.value == 1 && nick0.value == 0 && nick1.value == 1 &&
					klass.get_value_by_name ("UNKNOWN") == null && klass.get_value_by_nick ("unknown") == null,
					"name/nick lookup results"))
				return 1;
			stdout.printf ("scope=Host GLib only\ngtype=%s\nvalues=%d,%d\n", enum_type.name (),
					(int) StopReason.UNLOAD, (int) StopReason.PROCESS_TRANSITION);
			stdout.printf ("value[0]=%s|%s\nvalue[1]=%s|%s\n", unload.value_name, unload.value_nick,
					transition.value_name, transition.value_nick);
			stdout.printf ("lookup-by-name=%d,%d\nlookup-by-nick=%d,%d\n", name0.value, name1.value, nick0.value, nick1.value);

			var probe = new Probe ();
			unowned GLib.ParamSpec? pspec = probe.get_class ().find_property ("stop-reason");
			if (!check (pspec != null && pspec is GLib.ParamSpecEnum, "enum Object property"))
				return 1;
			unowned GLib.ParamSpecEnum enum_spec = (GLib.ParamSpecEnum) pspec;
			var read_write = GLib.ParamFlags.READABLE | GLib.ParamFlags.WRITABLE;
			if (!check (enum_spec.value_type == enum_type && (enum_spec.flags & read_write) == read_write &&
					enum_spec.default_value == 0 && probe.stop_reason == StopReason.UNLOAD, "property type/default/flags"))
				return 1;
			var readback = GLib.Value (enum_type);
			probe.get_property ("stop-reason", ref readback);
			if (!check (readback.get_enum () == 0, "get_property default"))
				return 1;
			stdout.printf ("property-default=%d\n", enum_spec.default_value);

			probe.stop_reason = StopReason.PROCESS_TRANSITION;
			probe.get_property ("stop-reason", ref readback);
			int direct_transition = readback.get_enum ();
			if (!check (probe.stop_reason == StopReason.PROCESS_TRANSITION && direct_transition == 1, "direct property write/read transition"))
				return 1;
			probe.stop_reason = StopReason.UNLOAD;
			probe.get_property ("stop-reason", ref readback);
			int direct_unload = readback.get_enum ();
			if (!check (probe.stop_reason == StopReason.UNLOAD && direct_unload == 0, "direct property write/read unload"))
				return 1;
			stdout.printf ("property-direct-read-write=%d,%d\n", direct_transition, direct_unload);

			var writeback = GLib.Value (enum_type);
			writeback.set_enum ((int) StopReason.PROCESS_TRANSITION);
			probe.set_property ("stop-reason", writeback);
			probe.get_property ("stop-reason", ref readback);
			int generic_transition = readback.get_enum ();
			if (!check (probe.stop_reason == StopReason.PROCESS_TRANSITION && generic_transition == 1, "set_property/get_property transition"))
				return 1;
			writeback.set_enum ((int) StopReason.UNLOAD);
			probe.set_property ("stop-reason", writeback);
			probe.get_property ("stop-reason", ref readback);
			int generic_unload = readback.get_enum ();
			if (!check (probe.stop_reason == StopReason.UNLOAD && generic_unload == 0, "set_property/get_property unload"))
				return 1;
			stdout.printf ("property-set-get=%d,%d\nPASS\n", generic_transition, generic_unload);
			return 0;
		}
	}
}
'''


def build_program(declaration):
    # Do not recreate the enum, alter its visibility, or borrow annotations from a generator.
    return PROGRAM.replace('__STOP_REASON__', declaration)


def resolve_tools(valac=None, cc=None, pkg_config=None):
    tools = {}
    for name, candidates in (('valac', (valac,) if valac is not None else ('valac',)),
                             ('cc', (cc,) if cc is not None else ('cc', 'gcc')),
                             ('pkg-config', (pkg_config,) if pkg_config is not None else ('pkg-config',))):
        found = next((shutil.which(str(candidate)) for candidate in candidates
                      if shutil.which(str(candidate))), None)
        if found is None:
            raise MissingTool('required ' + SCOPE + ' tool missing: ' + name + ' (' + ', '.join(map(str, candidates)) + ')')
        tools[name] = str(Path(found).resolve())
    return tools


def run_command(argv, cwd, log_stem=None, env=None):
    try:
        process = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, capture_output=True,
                                 text=True, encoding='utf-8', errors='replace', timeout=120)
    except subprocess.TimeoutExpired as error:
        raise ValueError('command timed out: ' + shlex.join(list(map(str, argv)))) from error
    record = {'argv': list(map(str, argv)), 'returncode': process.returncode,
              'stdout': process.stdout, 'stderr': process.stderr}
    if log_stem is not None:
        for stream in ('stdout', 'stderr'):
            Path(str(log_stem) + '.' + stream + '.txt').write_bytes(record[stream].encode('utf-8'))
    if process.returncode != 0:
        raise ValueError('command failed (' + str(process.returncode) + '): ' + shlex.join(record['argv'])
                         + '\n' + record['stdout'] + record['stderr'])
    return record


def artifact(path):
    data = path.read_bytes()
    return {'path': str(path), 'sha256': digest(data), 'text': data.decode('utf-8')}


def verify(out, valac=None, cc=None, pkg_config=None, root=ROOT):
    out = Path(out).absolute()
    if os.path.lexists(out):
        raise ValueError('--out must be a new, nonexistent directory: ' + str(out))
    # Preflight both real inputs and all tools before creating the output directory.
    inputs = [load_stop_reason(version, root) for version in VERSIONS]
    tools = resolve_tools(valac, cc, pkg_config)
    tool_versions = {name: {'path': path, 'version': run_command([path, '--version'], Path(root).resolve())}
                     for name, path in tools.items()}
    packages = run_command([tools['pkg-config'], '--modversion', 'glib-2.0', 'gobject-2.0'], Path(root).resolve())
    flags = run_command([tools['pkg-config'], '--cflags', '--libs', 'glib-2.0', 'gobject-2.0'], Path(root).resolve())
    out.mkdir(parents=True, exist_ok=False)
    out = out.resolve()
    results = []
    for declaration, provenance in inputs:
        directory = out / provenance['version']
        directory.mkdir()
        source, generated = directory / 'probe.vala', directory / 'probe.c'
        executable = directory / ('probe.exe' if os.name == 'nt' else 'probe')
        source.write_bytes(build_program(declaration).encode('utf-8'))
        vala_compile = run_command([tools['valac'], '-C', '--pkg', 'glib-2.0', '--pkg', 'gobject-2.0',
                                    '--directory', directory, source], directory, directory / 'valac')
        if not generated.is_file() or generated.is_symlink():
            raise ValueError('valac did not produce the expected generated C: ' + str(generated))
        c_compile = run_command([tools['cc'], str(generated), '-o', str(executable), *shlex.split(flags['stdout'])],
                                directory, directory / 'cc')
        if not executable.is_file() or executable.is_symlink():
            raise ValueError('C compiler did not produce the host executable: ' + str(executable))
        environment = dict(os.environ, G_DEBUG='fatal-warnings')
        run = run_command([executable], directory, directory / 'run', environment)
        if run['stdout'].splitlines() != EXPECTED_OUTPUT.splitlines():
            raise ValueError('unexpected Host GLib probe output for ' + provenance['version'] + ':\n' + run['stdout'])
        results.append({'version': provenance['version'], 'input': provenance,
                        'source': artifact(source), 'generated_c': artifact(generated),
                        'executable': {'path': str(executable), 'sha256': digest(executable.read_bytes())},
                        'valac_compile': vala_compile, 'c_compile': c_compile, 'run': run,
                        'run_environment': {'G_DEBUG': 'fatal-warnings'}, 'host_runtime_tested': True})
    report = {'schema': 1, 'scope': SCOPE,
              'claim': 'Host GLib only; not a Frida Agent/Gadget, Android ABI, device or end-to-end test.',
              'host_runtime_tested': True, 'android_runtime_tested': False,
              'tools': tool_versions, 'glib_package_versions': packages, 'pkg_config_flags': flags,
              'versions': results}
    # Never publish a success report after only extraction, compilation, or one version.
    with (out / 'report.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='new, nonexistent output directory')
    parser.add_argument('--valac', help='host valac executable (no implicit fallback when specified)')
    parser.add_argument('--cc', help='host C compiler executable; defaults to cc, then gcc')
    parser.add_argument('--pkg-config', help='host pkg-config executable')
    args = parser.parse_args(argv)
    try:
        report = verify(args.out, args.valac, args.cc, args.pkg_config)
        print(json.dumps({'scope': report['scope'], 'versions': [item['version'] for item in report['versions']],
                          'report': str(args.out.resolve() / 'report.json')}, ensure_ascii=False))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('FATAL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
