#!/usr/bin/env python3
"""Regenerate reviewable recipes from checked-in, SHA-pinned upstream fixtures."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
        for guard in previous['files']:
            relative = guard['path']
            data = (ROOT / 'tests/fixtures' / version / relative).read_bytes()
            if patches.digest(data) != guard['upstream_sha256']:
                raise ValueError('fixture drift: ' + relative)
            text = data.decode('utf-8')
            changes, optional = [], {}
            if relative.endswith('server/server.vala'):
                changes = [edit('"re.frida.server"', '"nianchu.server"')]
            elif relative.endswith('linux-host-session.vala'):
                changes = [edit('"frida-agent-<arch>.so"', '"nianchu-agent-<arch>.so"'),
                           edit('"frida-agent-arm.so"', '"nianchu-agent-arm.so"', 2),
                           edit('"frida-agent-arm64.so"', '"nianchu-agent-arm64.so"', 2)]
            elif relative.endswith('gadget-glue.c'):
                changes = [edit('g_thread_new ("frida-gadget",', 'g_thread_new ("nianchu-gadget",')]
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
            elif relative.endswith('gumscriptscheduler.c'):
                changes = [edit('g_thread_new ("gum-js-loop",', 'g_thread_new ("nianchu-js",')]
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
                    edit('gum_interceptor_replace (interceptor, gum_original_signal,\n' + indent +
                         'gum_exceptor_backend_replacement_signal, ' + suffix,
                         '/* Experimental: signal interposition disabled. */'),
                    edit('gum_interceptor_replace (interceptor, gum_original_sigaction,\n' + indent +
                         'gum_exceptor_backend_replacement_sigaction, ' + suffix,
                         '/* Experimental: sigaction interposition disabled. */'),
                    edit('gum_interceptor_revert (interceptor, gum_original_signal);', '/* signal interposition was not installed. */'),
                    edit('gum_interceptor_revert (interceptor, gum_original_sigaction);', '/* sigaction interposition was not installed. */'),
                ]
            entry = {'path': relative, 'upstream_sha256': patches.digest(data), 'edits': changes, 'optional': optional}
            compatible = patches.transform(data, changes)
            for edits in optional.values():
                patches.transform(compatible, edits)
            files.append(entry)
            destination = args.output / 'tests/fixtures' / version / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        recipe = {'version': version, 'source': info['submodules'],
                  'features': ['exit-monitor-off', 'signal-interposition-off', 'zygisk-loader'],
                  'java_bridge': {'mode': info['java_bridge'], 'modified': False,
                                  'reason': 'ART/GC/JDWP removal needs functional replacement and runtime tests'},
                  'files': files}
        destination = args.output / 'patches' / version / 'spec.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(recipe, indent=2) + '\n', encoding='utf-8')
        print(version, len(files), 'pinned files verified')


if __name__ == '__main__':
    main()
