#!/usr/bin/env python3
"""Regenerate reviewable recipes from checked-in, SHA-pinned upstream fixtures."""
import argparse
import difflib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXTRA_FILES = {
    '16.7.19': {
        'src/linux/frida-helper-process.vala': 'f2d119388031073c930ed67d3e9db18abdf3c17b80f0feb82cbcbe6fb1c3d190',
        'src/linux/frida-helper-backend.vala': '252265fb5fb0a3254aa03c3ff65dbb6ae4c4df27a5448204e6859346a579d96e',
        'src/frida-glue.c': '07cb65c4dd1865a60481dd3ffbfe25da4610625b4b15bc6aea9c86eb38745cc2',
    },
    '17.25.2': {
        'src/linux/frida-helper-process.vala': '59e765d9d317e1865872d2f4d664eeafe7c8a6eb0cd2b52dfc9fec9203165441',
        'src/linux/frida-helper-backend.vala': '213c631cddc4abe6f8fda4ed94e785b512902dece7b370c953164452326d186b',
        'src/linux/helpers/zymbiote.c': '8df4004f21d1412fb44312e120bd4a91771ddf7969e0fbdec579389aaa849101',
        'src/linux/mapped-agent.vala': '874dae0cd900d76be2ca82ded03bfc0404cbf0590367ad22f33e2bca244bb41c',
        'src/frida-glue.c': '70f9ba86b23b99cc0557d034bdfe3bfe94d1e20dc027b608c8f315518064c181',
    },
}

EXTRA_GUM_FILES = {
    '16.7.19': {'gum/gum.c': '7cb75dacbe8fe3402a1675ac1828a472c84b4fc19f9ab83e0fec4a8ad674434c'},
    '17.25.2': {'gum/gum.c': '62d0a353bafb5edc87adf18460dcc7a0dcf0e1280c81f3c84cbb6e6988e3be4e'},
}


def edit(old, new, count=1):
    return {'old': old, 'new': new, 'count': count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new generation directory')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('generation output must not exist')
    module = importlib.util.spec_from_file_location('patches', ROOT / 'scripts/apply_patches.py')
    patches = importlib.util.module_from_spec(module)
    module.loader.exec_module(patches)
    manifest = json.loads((ROOT / 'versions.json').read_text(encoding='utf-8'))
    for info in manifest['versions']:
        version = info['version']
        previous = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
        files = []
        guards = list(previous['files'])
        extras = {'subprojects/frida-core/' + path: sha for path, sha in EXTRA_FILES[version].items()}
        extras.update({'subprojects/frida-gum/' + path: sha for path, sha in EXTRA_GUM_FILES[version].items()})
        entrypoint_files = json.loads((ROOT / 'patches/entrypoint-files.json').read_text(encoding='utf-8'))[version]
        extras.update({'subprojects/frida-core/' + path: sha for path, sha in entrypoint_files.items()})
        gadget_files = json.loads((ROOT / 'patches/gadget-files.json').read_text(encoding='utf-8'))[version]
        extras.update({'subprojects/frida-core/' + path: sha for path, sha in gadget_files.items()})
        fullpatch_files = json.loads((ROOT / 'patches/fullpatch-files.json').read_text(encoding='utf-8'))[version]
        extras.update({'subprojects/frida-core/' + path: sha for path, sha in fullpatch_files.items()})
        for path, sha in extras.items():
            matches = [guard for guard in guards if guard['path'] == path]
            if matches:
                if len(matches) != 1 or matches[0]['upstream_sha256'] != sha:
                    raise ValueError('extra fixture guard mismatch: ' + path)
            else:
                guards.append({'path': path, 'upstream_sha256': sha})
        for guard in guards:
            relative = guard['path']
            data = (ROOT / 'tests/fixtures' / version / relative).read_bytes()
            if patches.digest(data) != guard['upstream_sha256']:
                raise ValueError('fixture drift: ' + relative)
            text = data.decode('utf-8')
            changes, optional = [], {}
            if relative.endswith('server/server.vala'):
                changes = [edit('private const string DEFAULT_DIRECTORY = "re.frida.server";',
                                'private static string DEFAULT_DIRECTORY;'),
                           edit('\tprivate static int main (string[] args) {\n',
                                '\tprivate static int main (string[] args) {\n\t\tDEFAULT_DIRECTORY = GLib.Uuid.string_random ();\n')]
            elif relative.endswith('linux-host-session.vala'):
                changes = [edit('private AgentDescriptor? agent;',
                                'private AgentDescriptor? agent;\n\t\tprivate string agent_prefix;'),
                           edit('agent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),',
                                'agent_prefix = GLib.Uuid.string_random ();\n\t\t\tagent = new AgentDescriptor (PathTemplate (agent_prefix + "-<arch>.so"),'),
                           edit('new AgentResource ("frida-agent-arm.so",', 'new AgentResource (agent_prefix + "-arm.so",'),
                           edit('new AgentResource ("frida-agent-arm64.so",', 'new AgentResource (agent_prefix + "-arm64.so",'),
                           edit('unowned string name;\n\t\t\tswitch (cpu_type_from_pid (pid))',
                                'string name;\n\t\t\tswitch (cpu_type_from_pid (pid))'),
                           edit('name = "frida-agent-arm.so";', 'name = agent_prefix + "-arm.so";'),
                           edit('name = "frida-agent-arm64.so";', 'name = agent_prefix + "-arm64.so";')]
                if version.startswith('17.'):
                    changes.extend([
                        edit('"/data/local/tmp/frida-helper-"', '"/data/local/tmp/nianchu-helper-"'),
                        edit('string name = "/frida-zymbiote-" + Uuid.string_random ().replace ("-", "");',
                             'string name = "/nianchu-zymbiote-" + Uuid.string_random ().replace ("-", "");'),
                        edit('"/frida-zymbiote-00000000000000000000000000000000".data',
                             '"/nianchu-zymbiote-00000000000000000000000000000000".data'),
                    ])
            elif relative.endswith('src/linux/helpers/zymbiote.c'):
                changes = [edit('.socket_path = "/frida-zymbiote-00000000000000000000000000000000",',
                                '.socket_path = "/nianchu-zymbiote-00000000000000000000000000000000",')]
            elif relative.endswith('src/linux/mapped-agent.vala'):
                changes = [edit('Gum.Mapper.new_take_blob ("frida-agent.so",',
                                'Gum.Mapper.new_take_blob ("nianchu-agent.so",')]
            elif relative.endswith('src/frida-glue.c'):
                changes = [edit('g_thread_new ("frida-main-loop",', 'g_thread_new ("nianchu-main",'),
                           edit('\n    if (runtime == FRIDA_RUNTIME_OTHER)\n',
                                '\n    g_set_prgname ("nianchu");\n\n    if (runtime == FRIDA_RUNTIME_OTHER)\n')]
            elif relative.endswith('gum/gum.c'):
                changes = [edit('g_set_prgname ("frida");', 'g_set_prgname ("nianchu");')]
            elif relative.endswith('frida-helper-process.vala'):
                changes = [edit('make_temporary_helper ("frida-helper-32",', 'make_temporary_helper ("nianchu-helper-32",'),
                           edit('make_temporary_helper ("frida-helper-64",', 'make_temporary_helper ("nianchu-helper-64",'),
                           edit('string socket_path = "/frida-" + Uuid.string_random ();',
                                'string socket_path = "/nianchu-" + Uuid.string_random ();')]
            elif relative.endswith('frida-helper-backend.vala'):
                changes = [edit('return "/frida-" + Uuid.string_random ();',
                                'return "/nianchu-" + Uuid.string_random ();')]
                if version.startswith('16.'):
                    changes.append(edit('return Linux.syscall (SysCall.memfd_create, name, flags);',
                                        'return Linux.syscall (SysCall.memfd_create, "nianchu-cache", flags);'))
            elif relative.endswith('lib/base/linux.vala'):
                changes = [edit('return Linux.syscall (LinuxSyscall.MEMFD_CREATE, name, flags);',
                                'return Linux.syscall (LinuxSyscall.MEMFD_CREATE, "nianchu-cache", flags);')]
            elif relative.endswith('lib/base/rpc.vala'):
                helper = '''\t\tprivate string get_rpc_marker (bool quoted = false) {
\t\t\tstring marker = (string) GLib.Base64.decode ((string) GLib.Base64.decode ("Wm5KcFpHRTZjbkJq"));
\t\t\treturn quoted ? "\\\"" + marker + "\\\"" : marker;
\t\t}

'''
                changes = [edit('\t\tprivate Gee.HashMap<string, PendingResponse> pending_responses',
                                helper + '\t\tprivate Gee.HashMap<string, PendingResponse> pending_responses'),
                           edit('.add_string_value ("frida:rpc")', '.add_string_value (get_rpc_marker ())'),
                           edit('json.index_of ("\\\"frida:rpc\\\"")', 'json.index_of (get_rpc_marker (true))'),
                           edit('type != "frida:rpc"', 'type != get_rpc_marker ()')]
            elif relative.endswith(('src/droidy/droidy-client.vala', 'src/adb.vala')):
                changes = [edit('throw new Error.PROTOCOL ("Unexpected command");',
                                'break; /* Ignore unsolicited OPEN/CLSE/WRTE as in the reference patch. */')]
            elif relative.endswith('src/freebsd/binjector-glue.c'):
                changes = [edit('g_strdup_printf ("%s/binjector-%u", self->temp_path, self->id)',
                                'g_strdup_printf ("%s/%p%u", self->temp_path, self, self->id)')]
            elif relative.endswith(('src/droidy/droidy-host-session.vala', 'src/android-helper/client.vala')):
                if '"/data/local/tmp/frida-helper-"' in text:
                    changes = [edit('"/data/local/tmp/frida-helper-"', '"/data/local/tmp/nianchu-helper-"')]
            elif relative.endswith('src/linux/system-linux.c'):
                changes = [edit('return g_strdup ("/data/local/tmp");', 'return g_strdup ("/system/lib64");')]
            elif relative.endswith(('src/embed-agent.py', 'src/embed-helper.py')):
                # Apply before resource compilation, including every nonempty compat ELF.
                kind = 'agent' if relative.endswith('embed-agent.py') else 'helper'
                insertion = '''    if host_os in {"linux", "android"}:
        rewriter = __import__("os").environ["NIANCHU_ELF_REWRITER"]
        for asset in embedded_assets:
            if asset.stat().st_size == 0:
                continue
            subprocess.run([sys.executable, "-I", rewriter, str(asset),
                            "--rewrite", "--kind", "''' + kind + '''",
                            "--report", str(asset) + ".rewrite.json"], check=True)

'''
                changes = [edit('    subprocess.run([\n        resource_compiler,',
                                insertion + '    subprocess.run([\n        resource_compiler,')]
            elif relative.endswith('gadget-glue.c'):
                changes = [edit('g_thread_new ("frida-gadget",', 'g_thread_new ("nianchu-gadget",'),
                           edit('#include "frida-gadget.h"', '#include "nianchu-gadget.h"'),
                           edit('  gum_script_backend_get_type (); /* Warm up */',
                                '  g_set_prgname ("nianchu");\n\n  gum_script_backend_get_type (); /* Warm up */')]
                old = '''__attribute__ ((constructor)) static void
frida_on_load (void)
{
  frida_gadget_load (NULL, NULL, NULL);
}'''
                new = '''#ifdef HAVE_ANDROID
/* The module invokes this after android_dlopen_ext has released the linker lock. */
__attribute__ ((visibility ("default"))) void
nianchu_gadget_init (const gchar * config_data, int * result)
{
  frida_gadget_load (NULL, config_data, result);
}
#endif

__attribute__ ((constructor)) static void
frida_on_load (void)
{
#ifndef HAVE_ANDROID
  frida_gadget_load (NULL, NULL, NULL);
#else
  /* Keep the constructor visible to the upstream constructor-ordering tool. */
  __asm__ volatile ("" ::: "memory");
#endif
}'''
                optional['zygisk-loader'] = [edit(old, new)]
            elif relative.endswith('lib/gadget/gadget.vala'):
                changes = [edit('"frida-gadget-tcp-%u".printf (listen_port)', '"nianchu-t%u".printf (listen_port)'),
                           edit('"frida-gadget-unix"', '"nianchu-unix"')]
                old = '''\t\tif (!FileUtils.test (config_path, FileTest.EXISTS)) {
\t\t\tvar ext_index = config_path.last_index_of_char ('.');
\t\t\tif (ext_index != -1) {
\t\t\t\tconfig_path = config_path[0:ext_index] + ".config.so";
\t\t\t} else {
\t\t\t\tconfig_path = config_path + ".config.so";
\t\t\t}
\t\t}'''
                new = '''\t\tif (!FileUtils.test (config_path, FileTest.EXISTS)) {
\t\t\tvar ext_index = config_path.last_index_of_char ('.');
\t\t\tstring json_path;
\t\t\tif (ext_index != -1) {
\t\t\t\tjson_path = config_path[0:ext_index] + ".json";
\t\t\t} else {
\t\t\t\tjson_path = config_path + ".json";
\t\t\t}
\t\t\tif (FileUtils.test (json_path, FileTest.EXISTS)) {
\t\t\t\tconfig_path = json_path;
\t\t\t} else if (ext_index != -1) {
\t\t\t\tconfig_path = config_path[0:ext_index] + ".config.so";
\t\t\t} else {
\t\t\t\tconfig_path = config_path + ".config.so";
\t\t\t}
\t\t}'''
                optional['gadget-json-config'] = [edit(old, new)]
            elif relative.endswith('lib/gadget/meson.build'):
                changes = [edit("shared_library('frida-gadget-raw',", "shared_library('nianchu-gadget-raw',"),
                           edit("vala_header: 'frida-gadget.h'", "vala_header: 'nianchu-gadget.h'"),
                           edit("custom_target('frida-gadget-modulated',", "custom_target('nianchu-gadget-modulated',"),
                           edit("output: 'libfrida-gadget-modulated' + shlib_suffix",
                                "output: 'libnianchu-gadget-modulated' + shlib_suffix")]
            elif relative.endswith('lib/gadget/gadget-darwin.m'):
                changes = [edit('#include "frida-gadget.h"', '#include "nianchu-gadget.h"')]
            elif relative == 'subprojects/frida-core/meson.build':
                changes = [edit("gadget_name = 'frida-gadget' + shlib_suffix",
                                "gadget_name = ((host_os_family in ['windows', 'darwin']) ? 'frida-gadget' : 'nianchu-gadget') + shlib_suffix"),
                           edit("agent_name = 'frida-agent' + shlib_suffix",
                                "agent_name = ((host_os_family in ['windows', 'darwin']) ? 'frida-agent' : 'nianchu-agent') + shlib_suffix")]
            elif relative.endswith('compat/build.py'):
                changes = [edit('GADGET_FILE_ELF = Path("lib") / "gadget" / "frida-gadget.so"',
                                'GADGET_FILE_ELF = Path("lib") / "gadget" / "nianchu-gadget.so"'),
                           edit('AGENT_FILE_ELF = Path("lib") / "agent" / "frida-agent.so"',
                                'AGENT_FILE_ELF = Path("lib") / "agent" / "nianchu-agent.so"')]
            elif relative.endswith('src/droidy/injector.vala'):
                changes = [edit('"/data/local/tmp/frida-gadget-"', '"/data/local/tmp/nianchu-gadget-"', 2)]
            elif relative.endswith('src/fruity/injector.vala'):
                changes = [edit(r'/^frida-gadget-tcp-(\d+)$/.match', r'/^(?:frida-gadget-tcp-|nianchu-t)(\d+)$/.match')]
            elif relative.endswith('lib/payload/portal-client.vala'):
                changes = [edit('"Emulated realm is not supported by frida-gadget"',
                                '"Emulated realm is not supported by nianchu-gadget"')]
            elif relative.endswith('gumscriptscheduler.c'):
                changes = [edit('g_thread_new ("gum-js-loop",', 'g_thread_new ("nianchu-js",')]
            elif relative.endswith('bindings/gumjs/generate-runtime.py') and version.startswith('16.'):
                changes = [edit('    runtime_reldir = Path("runtime")\n',
                    '''    subprocess.run([sys.executable, "-I", os.environ["NIANCHU_BRIDGE_PATCHER"],
                    "--source", str(priv_dir / "node_modules" / "frida-java-bridge"),
                    "--version", "6.3.9", "--report", str(priv_dir / "nianchu-bridge-report.json")], check=True)

    runtime_reldir = Path("runtime")
''')]
            elif relative.endswith('frida-gadget.version'):
                optional['zygisk-loader'] = [edit('  local:\n', '  global:\n    nianchu_gadget_init;\n  local:\n')]
            elif relative.endswith('exit-monitor.vala'):
                start = text.index('\t\tconstruct {\n')
                end = text.index('\n\t\tpublic override void dispose', start)
                optional['exit-monitor-off'] = [edit(text[start:end], '\t\tconstruct {\n\t\t\t// Experimental: exit preparation interception is disabled.\n\t\t}\n')]
            elif relative.endswith('gumexceptor-posix.c'):
                suffix = 'self, NULL);' if version.startswith('16.') else 'NULL, &options);'
                indent = '      ' if version.startswith('16.') else '        '
                optional['signal-interposition-off'] = [
                    edit('    gum_exceptor_backend_detach (self);',
                         '    /* Reference profile: POSIX exception backend was not attached. */'),
                    edit('  gum_exceptor_backend_attach (backend);',
                         '  /* Reference profile: do not install POSIX exception/signal handlers. */'),
                    edit('gum_interceptor_replace (interceptor, gum_original_signal,\n' + indent +
                         'gum_exceptor_backend_replacement_signal, ' + suffix,
                         '/* Experimental: signal interposition disabled. */'),
                    edit('gum_interceptor_replace (interceptor, gum_original_sigaction,\n' + indent +
                         'gum_exceptor_backend_replacement_sigaction, ' + suffix,
                         '/* Experimental: sigaction interposition disabled. */'),
                    edit('gum_interceptor_revert (interceptor, gum_original_signal);', '/* signal interposition was not installed. */'),
                    edit('gum_interceptor_revert (interceptor, gum_original_sigaction);', '/* sigaction interposition was not installed. */'),
                ]
            core_relative = relative.removeprefix('subprojects/frida-core/')
            if core_relative in entrypoint_files:
                if core_relative == 'lib/agent/agent.vala':
                    # Private numeric state: rename only the generated GType name.
                    # Preserve the enum value names/nicks and C consumer prefix.
                    changes.append(edit('\tprivate enum StopReason {',
                        '\t[CCode (cname = "NianchuAgentStopReason", cprefix = "FRIDA_AGENT_STOP_REASON_", '
                        'lower_case_cprefix = "frida_agent_stop_reason_")]\n\tprivate enum StopReason {'))
                    optional['agent-entrypoint-rename'] = [edit('\tpublic void main (string agent_parameters,',
                        '\t[CCode (cname = "nianchu_agent_main")]\n\tpublic void main (string agent_parameters,')]
                else:
                    count = text.count('frida_agent_main')
                    if not count:
                        raise ValueError('entrypoint source has no expected symbol: ' + relative)
                    optional['agent-entrypoint-rename'] = [edit('frida_agent_main', 'nianchu_agent_main', count)]
            entry = {'path': relative, 'upstream_sha256': patches.digest(data), 'edits': changes, 'optional': optional}
            compatible = patches.transform(data, changes)
            for edits in optional.values():
                patches.transform(compatible, edits)
            files.append(entry)
            destination = args.output / 'tests/fixtures' / version / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        recipe = {'version': version, 'source': info['submodules'],
                  'features': ['exit-monitor-off', 'signal-interposition-off', 'zygisk-loader', 'agent-entrypoint-rename', 'gadget-json-config'],
                  'default_features': ['exit-monitor-off', 'signal-interposition-off', 'agent-entrypoint-rename', 'gadget-json-config'],
                  'java_bridge': {'mode': info['java_bridge'], 'modified': version.startswith('16.'),
                                  'profile': 'reference-prettymethod-off',
                                  'reason': '16 bundles the reference bridge patch; 17 publishes a separate patched client bundle'},
                  'files': files}
        destination = args.output / 'patches' / version / 'spec.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(recipe, indent=2) + '\n', encoding='utf-8', newline='\n')
        for feature in (None, *recipe['features']):
            diff = []
            for entry in files:
                base = (ROOT / 'tests/fixtures' / version / entry['path']).read_bytes()
                compatible = patches.transform(base, entry['edits'])
                before = compatible if feature else base
                after = patches.transform(compatible, entry.get('optional', {}).get(feature, [])) if feature else compatible
                diff.extend(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                                fromfile='a/' + entry['path'], tofile='b/' + entry['path']))
            (destination.parent / ((feature or 'compatible') + '.patch')).write_text(''.join(diff), encoding='utf-8', newline='\n')
        print(version, len(files), 'pinned files verified')


if __name__ == '__main__':
    main()
