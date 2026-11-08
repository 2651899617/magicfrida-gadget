#!/usr/bin/env python3
"""Wrapper command contracts plus real outliner/native heap-restore integration.

Stub outlining keeps command/dep/security cases independent of the transformer.
Optional NIANCHU_STRING_OUTLINE_TEST_REPORT_DIR preserves JSON evidence outside
all test source trees. NIANCHU_TEST_CLANG / NIANCHU_TEST_CLANGXX opt in to real
Android C/C++ object-only checks (no product build, links, CI, or ADB).
"""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


installer = load_script('install_string_outline')
wrapper = load_script('string_outline_compiler')

STUB_OUTLINER = r'''import sys
if not sys.flags.isolated:
    raise SystemExit('outliner was not isolated')
import argparse, hashlib, json, os
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--input', required=True)
p.add_argument('--output', required=True)
p.add_argument('--report', required=True)
p.add_argument('--language', required=True, choices=('c','cpp'))
p.add_argument('--cpp-opaque-root', action='append', default=[])
p.add_argument('--runtime-policy', default='glib')
a = p.parse_args()
source = Path(a.input).read_bytes()
result = source.replace(b'"frida-outline-me"', b'"nianchu-outline-me"')
Path(a.output).write_bytes(result)
Path(a.report).write_text(json.dumps({'stub':True, 'language':a.language,
    'input_sha256':hashlib.sha256(source).hexdigest(),
    'output_sha256':hashlib.sha256(result).hexdigest(), 'isolated':True,
    'cwd':str(Path.cwd()), 'argv':sys.argv}), encoding='utf-8')
'''

FAKE_COMPILER = r'''import sys
if not sys.flags.isolated:
    raise SystemExit('fake compiler was not isolated')
import hashlib, json, os, re, shlex
from pathlib import Path

def expand(values):
    result=[]
    for value in values:
        if value.startswith('@'):
            result += expand(shlex.split(Path(value[1:]).read_text(encoding='utf-8')))
        else:
            result.append(value)
    return result

args=expand(sys.argv[1:])
log=Path(os.environ['NIANCHU_FAKE_COMPILER_LOG'])
with log.open('a', encoding='utf-8') as output:
    output.write(json.dumps({'argv':sys.argv[1:], 'expanded':args,
        'cwd':str(Path.cwd()), 'isolated':bool(sys.flags.isolated)})+'\n')
if '--version' in args:
    print('stub clang version 1.0')
    raise SystemExit(0)

def value(flag, default=None):
    return args[args.index(flag)+1] if flag in args else default

if '-c' not in args and '-E' not in args:
    raise SystemExit(0)
source=next(Path(item) for item in args if item.endswith(('.c','.cpp','.cc','.cxx')))
output=Path(value('-o',source.stem+'.o'))
output.parent.mkdir(parents=True,exist_ok=True)
if '-E' in args:
    if '--fail-preprocess' in args:
        raise SystemExit(27)
    text=source.read_text(encoding='utf-8')
    dependencies=[source]
    include_dirs=[source.parent]+[Path(args[i+1]) for i,x in enumerate(args) if x in ('-I','-iquote')]
    for header in re.findall(r'#include "([^"]+)"',text):
        path=next(directory/header for directory in include_dirs if (directory/header).exists())
        text=text.replace('#include "'+header+'"',path.read_text(encoding='utf-8'))
        dependencies.append(path)
    if '-include' in args:
        forced=Path(value('-include'))
        text=forced.read_text(encoding='utf-8')+'\n'+text
        dependencies.append(forced)
    output.write_text(text,encoding='utf-8')
    depfile=Path(value('-MF'))
    target=value('-MT',value('-MQ','wrong-preprocessed-target'))
    depfile.parent.mkdir(parents=True,exist_ok=True)
    def escape(x):
        return str(x).replace('\\','\\\\').replace(' ','\\ ').replace(':','\\:')
    depfile.write_text(escape(target)+': '+ ' '.join(escape(x) for x in dependencies)+'\n',encoding='utf-8')
else:
    if '--fail-compile' in args:
        raise SystemExit(29)
    if any(x in args for x in ('-MD','-MMD','-MF','-MT','-MQ')):
        raise SystemExit('flattened compile leaked dependency emitters')
    if '-x' not in args or value('-x') not in ('cpp-output','c++-cpp-output'):
        raise SystemExit('flattened compile was not preprocessed input')
    if args.index('-x') > args.index(str(source)):
        raise SystemExit('input language occurs after source')
    output.write_bytes(b'OBJECT\n'+source.read_bytes())
'''


class OutlineBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='nianchu-outline-test-')
        self.base = Path(self.temporary.name)
        self.source = self.base / 'downloaded source'
        self.core = self.source / 'subprojects' / 'frida-core' / 'src'
        self.gum = self.source / 'subprojects' / 'frida-gum' / 'gum'
        self.core.mkdir(parents=True)
        self.gum.mkdir(parents=True)
        self.build = self.source / 'build'
        self.build.mkdir()
        self.tools = self.base / 'trusted tools'
        self.tools.mkdir()
        self.state = self.base / 'outline state'
        self.outliner = self.tools / 'stub_outliner.py'
        self.outliner.write_text(STUB_OUTLINER, encoding='utf-8')
        self.compiler = self.tools / 'fake_compiler.py'
        self.compiler.write_text(FAKE_COMPILER, encoding='utf-8')
        self.input = self.core / 'original source.c'
        self.header = self.core / 'original header.h'
        self.forced = self.core / 'forced header.h'
        self.header.write_text('typedef unsigned int original_header_type;\n', encoding='utf-8')
        # No include guard: if flattened compilation preprocesses -include a
        # second time, the named struct produces a hard redefinition error.
        self.forced.write_text('struct forced_header_struct { unsigned long value; };\n'
                               'typedef struct forced_header_struct forced_header_type;\n', encoding='utf-8')
        self.input.write_text('#include "original header.h"\nconst char *message = "frida-outline-me";\n'
                              'int number = BASE;\n', encoding='utf-8')
        self.output = self.build / 'subprojects/frida-core/libfrida-core.p/original source.c.o'
        self.output.parent.mkdir(parents=True)
        self.depfile = self.output.with_suffix('.d')
        self.log = self.base / 'compiler.log'
        self.env_output = self.base / 'outline.env'
        self.prepare()

    def tearDown(self):
        destination = os.environ.get('NIANCHU_STRING_OUTLINE_TEST_REPORT_DIR')
        if destination:
            directory = Path(destination) / self.id().rsplit('.', 1)[-1]
            directory.mkdir(parents=True, exist_ok=True)
            for source in (self.state / 'reports').rglob('*.json'):
                shutil.copyfile(source, directory / source.name)
            if self.log.exists():
                shutil.copyfile(self.log, directory / 'compiler.jsonl')
        self.temporary.cleanup()

    def prepare(self, **kwargs):
        self.install = installer.prepare(self.source, kwargs.pop('version', '16.7.19'), self.state,
                                          sys.executable, self.outliner, self.env_output,
                                          kwargs.pop('response_format', 'gnu'), kwargs.pop('allow_stub', True))
        self.config = self.state / 'config.json'
        return self.install

    def command(self, args, language='c', compiler=None, build_root=None):
        return [sys.executable, '-I', str(self.state / 'string_outline_compiler.py'),
                '--config', str(self.config), '--language', language,
                '--build-root', str(build_root or self.build), '--',
                *(compiler or [sys.executable, '-I', str(self.compiler)]), *args]

    def run_wrapper(self, args, language='c', compiler=None, cwd=None, environment=None, build_root=None):
        env = {**os.environ, 'NIANCHU_FAKE_COMPILER_LOG': str(self.log), **(environment or {})}
        return subprocess.run(self.command(args, language, compiler, build_root), cwd=cwd or self.build,
                              env=env, capture_output=True, text=True)

    def compile_flags(self, extra=()):
        return ['--fixed-compiler-base', '-target', 'aarch64-none-linux-android21',
                '--sysroot', '/unchanged sysroot', '-D', 'BASE=7', '-U', 'OLD_BASE',
                '-I', str(self.core), '-include', str(self.forced), '-O2', '-fPIC',
                '-MD', '-MQ', str(self.output), '-MF', str(self.depfile),
                *extra, '-o', str(self.output), '-c', str(self.input)]

    def reports(self):
        paths = sorted((self.state / 'reports').rglob('*.json'), key=lambda path: path.stat().st_mtime_ns)
        return [json.loads(path.read_text(encoding='utf-8')) for path in paths]

    def calls(self):
        return [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()] if self.log.exists() else []

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = self.reports()[-1]
        self.assertEqual(report['status'], 'compiled', report)
        self.assertTrue(report['source_unchanged'])
        self.assertTrue(report['source_readonly'])
        self.assertNotEqual(report['preprocessed_sha256'], report['transformed_sha256'])
        return report

    def test_original_flags_order_source_hash_readonly_and_original_dependencies(self):
        self.input.chmod(stat.S_IREAD)
        before = self.input.read_bytes()
        args = self.compile_flags()
        report = self.assert_success(self.run_wrapper(args))
        self.assertEqual(self.input.read_bytes(), before)
        self.assertEqual(report['source_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(report['source_mode_before'], report['source_mode_after'])
        compiled = self.output.read_bytes()
        self.assertIn(b'nianchu-outline-me', compiled)
        self.assertNotIn(b'frida-outline-me', compiled)
        dependency = self.depfile.read_text(encoding='utf-8')
        for source in (self.input, self.header, self.forced):
            self.assertIn(str(source).replace('\\', '\\\\').replace(' ', '\\ ').replace(':', '\\:'), dependency)
        self.assertNotIn('outlined.c', dependency)
        self.assertNotIn('preprocessed.c', dependency)
        self.assertEqual(report['depfile_sha256'], hashlib.sha256(self.depfile.read_bytes()).hexdigest())
        pre = report['preprocess_expanded_argv']
        final = report['compile_expanded_argv']
        for preserved in ('--fixed-compiler-base', '-target', 'aarch64-none-linux-android21',
                          '--sysroot', '/unchanged sysroot', '-D', 'BASE=7', '-U', 'OLD_BASE',
                          '-I', str(self.core), '-include', str(self.forced), '-O2', '-fPIC'):
            self.assertIn(preserved, pre)
            self.assertIn(preserved, final)
        original_prefix = args[:args.index('-MD')]
        self.assertEqual(pre[3:3 + len(original_prefix)], original_prefix)
        self.assertEqual(final[3:3 + len(original_prefix)], original_prefix)
        self.assertIn('-E', pre)
        self.assertNotIn('-P', pre)
        self.assertTrue(report['compiler_line_origins_preserved'])
        self.assertIsNone(report['cpp_header_policy'])
        self.assertEqual(report['cpp_opaque_roots'], [])
        for removed in ('-MD', '-MMD', '-MF', '-MT', '-MQ'):
            self.assertNotIn(removed, final)
        self.assertIn('-ffile-prefix-map=../subprojects/frida-core=../subprojects/nianchu-core', pre)
        self.assertIn('-ffile-prefix-map=../subprojects/frida-gum=../subprojects/nianchu-gum', final)
        self.assertEqual(report['command_format']['kind'], 'argv')
        self.assertFalse(report['command_format']['shell'])
        self.assertEqual(report['compiler']['version'].strip(), 'stub clang version 1.0')
        self.assertFalse(list((self.state / 'work').iterdir()))

    def test_nested_response_files_are_immutable_preserved_and_shadowed(self):
        nested = self.build / 'nested args.rsp'
        root_rsp = self.build / 'compile args.rsp'
        nested.write_text(wrapper.join_response(self.compile_flags()[1:], 'gnu'), encoding='utf-8')
        root_rsp.write_text(wrapper.join_response(['--fixed-compiler-base', '@' + str(nested)], 'gnu'), encoding='utf-8')
        before = {path: path.read_bytes() for path in (nested, root_rsp)}
        report = self.assert_success(self.run_wrapper(['@' + str(root_rsp)]))
        for path, data in before.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(len(report['response_files']), 2)
        self.assertTrue(all('@' in ' '.join(report[name]) for name in ('preprocess_command', 'compile_command')))
        self.assertEqual({item['stage'] for item in report['shadow_response_files']}, {'preprocess', 'compile'})
        self.assertEqual(report['command_format']['response_format'], 'gnu')
        self.assertTrue(all(Path(item['path']).is_relative_to(self.state) for item in report['shadow_response_files']))
        self.assertFalse(list((self.state / 'work').iterdir()))

    def test_response_file_with_only_unmodified_base_flags_keeps_original_at_argument(self):
        rsp = self.build / 'base.rsp'
        rsp.write_text('-D BASE=7 -U OLD_BASE -fPIC', encoding='utf-8')
        args = ['@' + str(rsp), '-MD', '-MF', str(self.depfile), '-c', str(self.input), '-o', str(self.output)]
        report = self.assert_success(self.run_wrapper(args))
        self.assertIn('@' + str(rsp), report['preprocess_command'])
        self.assertIn('@' + str(rsp), report['compile_command'])
        self.assertEqual(report['shadow_response_files'], [])

    def test_attached_and_wp_dependency_outputs_only_run_during_original_preprocess(self):
        for args in ([f'-MF{self.depfile}', '-MMD', f'-MT{self.output}', '-MP'],
                     ['-Wp,-DKEEP=1,-MMD,' + str(self.depfile), '-MQ' + str(self.output)],
                     ['-Xclang', '-dependency-file', '-Xclang', str(self.depfile), '-MD']):
            with self.subTest(args=args):
                result = self.run_wrapper([*args, '-c', str(self.input), '-o', str(self.output)])
                report = self.assert_success(result)
                final = report['compile_expanded_argv']
                self.assertFalse(any(value.startswith(('-MF', '-MT', '-MQ')) for value in final))
                self.assertNotIn('-MD', final)
                self.assertNotIn('-MMD', final)
                self.assertNotIn('-dependency-file', final)
                if args[0].startswith('-Wp,'):
                    self.assertIn('-Wp,-DKEEP=1', final)

    def test_no_depflags_still_emits_deps_for_original_source_and_headers(self):
        report = self.assert_success(self.run_wrapper(['-c', str(self.input), '-o', str(self.output)]))
        self.assertTrue(self.depfile.exists())
        self.assertEqual(report['depfile'], str(self.depfile))
        self.assertIn('-MQ', report['preprocess_expanded_argv'])
        self.assertIn(str(self.output), report['preprocess_expanded_argv'])

    def test_generated_c_gum_cpp_and_standalone_compat_c_are_selected(self):
        generated = self.build / 'subprojects/frida-core/libfrida-core.p/generated.vala.c'
        generated.write_text('const char *s="frida-outline-me";\n', encoding='utf-8')
        self.assert_success(self.run_wrapper(['-MD', '-MF', str(self.depfile), '-c', str(generated), '-o', str(self.output)]))
        cpp = self.gum / 'runtime.cc'
        cpp.write_text('namespace gum { const char *s="frida-outline-me"; }\n', encoding='utf-8')
        report = self.assert_success(self.run_wrapper(['-x', 'c++', '-c', str(cpp), '-o', str(self.output)], language='cpp'))
        self.assertIn('c++-cpp-output', report['compile_expanded_argv'])
        compat = self.build / 'subprojects/frida-core/compat.p/arm'
        (compat / 'src').mkdir(parents=True)
        (compat / 'meson-info').mkdir()
        (compat / 'meson-info/meson-info.json').write_text(json.dumps({'directories':{'source':str(self.core.parent)}}), encoding='utf-8')
        compatible_source = compat / 'src/generated.c'
        compatible_source.write_text('const char *s="frida-outline-me";\n', encoding='utf-8')
        compatible_output = compat / 'src/libfrida-agent.p/generated.c.o'
        compatible_output.parent.mkdir(parents=True)
        self.assert_success(self.run_wrapper(['-c', str(compatible_source), '-o', str(compatible_output)],
                                             cwd=compat, build_root=compat))

    def test_only_exact_generated_embedded_elf_sources_are_passthrough(self):
        generated_dir = self.build / 'subprojects/frida-core/src'
        generated_dir.mkdir(parents=True)
        for name in ('frida-data-agent.c', 'frida-data-helper-process.c', 'frida-data-helper-backend.c'):
            source = generated_dir / name
            source.write_text('const char *s="frida-outline-me";\n', encoding='utf-8')
            args = ['-MD', '-MF', str(self.depfile), '-c', str(source), '-o', str(self.output)]
            previous = len(self.calls())
            self.run_wrapper(args)
            self.assertEqual(len(self.calls()), previous + 1)
            self.assertEqual(self.calls()[-1]['argv'], args)
        self.assertEqual(self.reports(), [])
        # Original project sources and unrelated generated resources still use
        # the transformer, even when a basename resembles embedded ELF output.
        original = self.core / 'frida-data-agent.c'
        original.write_text('const char *s="frida-outline-me";\n', encoding='utf-8')
        self.assert_success(self.run_wrapper(['-c', str(original), '-o', str(self.output)]))
        runtime = generated_dir / 'frida-data-runtime.c'
        runtime.write_text('const char *s="frida-outline-me";\n', encoding='utf-8')
        self.assert_success(self.run_wrapper(['-c', str(runtime), '-o', str(self.output)]))

    def test_links_assembly_native_tools_and_third_party_are_passthrough(self):
        dependency = self.source / 'subprojects/frida-core/subprojects/libfoo/foo.c'
        dependency.parent.mkdir(parents=True)
        dependency.write_text('int foo;\n', encoding='utf-8')
        native = self.build / 'meson-private/sanitycheckc.c'
        native.parent.mkdir()
        native.write_text('int main(void){return 0;}\n', encoding='utf-8')
        # Link/probe/assembly cases exit successfully with exactly one call.
        for args in (['-shared', '-o', 'product.so', 'foo.o'], ['--version'],
                     ['-E', str(self.input)], ['-S', str(self.input)], ['-c', 'assembler.S']):
            before = len(self.calls())
            result = self.run_wrapper(args)
            if args[0] in ('-S', '-c'):
                # This deliberately simple fake cannot compile assembly;
                # passthrough is identified by exactly unchanged argv.
                pass
            self.assertEqual(len(self.calls()), before + 1, result.stderr)
            self.assertEqual(self.calls()[-1]['argv'], args)
        for path in (dependency, native):
            args = ['-c', str(path), '-o', str(self.output)]
            before = len(self.calls())
            self.run_wrapper(args)
            self.assertEqual(len(self.calls()), before + 1)
            self.assertEqual(self.calls()[-1]['argv'], args)
        self.assertEqual(self.reports(), [])

    def test_planted_python_modules_and_pythonpath_never_execute(self):
        marker = self.base / 'PLANTED_EXECUTED'
        malicious = f"open({str(marker)!r}, 'w').write('executed')\nraise RuntimeError('planted module')\n"
        for directory in (self.source, self.core, self.tools, self.state):
            for name in ('json.py', 'argparse.py', 'subprocess.py', 'shlex.py', 'hashlib.py', 'sitecustomize.py', 'tree_sitter.py'):
                (directory / name).write_text(malicious, encoding='utf-8')
        report = self.assert_success(self.run_wrapper(self.compile_flags(), cwd=self.source,
                                                       environment={'PYTHONPATH':str(self.source), 'PYTHONSTARTUP':str(self.source / 'json.py')}))
        self.assertTrue(report['outliner_report']['isolated'])
        self.assertTrue(Path(report['outliner_report']['cwd']).is_relative_to(self.state / 'work'))
        self.assertFalse(marker.exists())

    def test_installer_rejects_in_tree_tools_state_and_report_outputs(self):
        for state, outliner, python in ((self.source / 'wrapper', self.outliner, Path(sys.executable)),
                                       (self.state, self.input, Path(sys.executable)),
                                       (self.state, self.outliner, self.input)):
            with self.assertRaises(installer.InstallationError):
                installer.prepare(self.source, '16.7.19', state, python, outliner, allow_stub=True)
        result = subprocess.run([sys.executable, '-I', str(ROOT / 'scripts/install_string_outline.py'),
                                 '--source', str(self.source), '--version', '16.7.19', '--state-dir', str(self.state),
                                 '--python', sys.executable, '--outliner', str(self.outliner),
                                 '--report', str(self.source / 'not-allowed.json'), '--skip-dependency-check'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.source / 'not-allowed.json').exists())

    def test_missing_isolation_refused_before_python_source_imports(self):
        for path, args in ((ROOT / 'scripts/install_string_outline.py', ['--help']),
                           (self.state / 'string_outline_compiler.py', ['--help'])):
            result = subprocess.run([sys.executable, str(path), *args], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Python -I', result.stderr)

    def test_failure_records_preserved_source_and_does_not_fall_back_to_original_compile(self):
        for switch, code in (('--fail-preprocess', 27), ('--fail-compile', 29)):
            with self.subTest(switch=switch):
                self.log.unlink(missing_ok=True)
                self.output.unlink(missing_ok=True)
                result = self.run_wrapper(self.compile_flags([switch]))
                self.assertEqual(result.returncode, code, result.stderr)
                report = self.reports()[-1]
                self.assertEqual(report['status'], 'failed')
                self.assertTrue(report['source_unchanged'])
                self.assertFalse(self.output.exists())
                compilations = [call for call in self.calls() if '-c' in call['expanded'] and '--version' not in call['expanded']]
                self.assertEqual(len(compilations), 0 if switch == '--fail-preprocess' else 1)

    def test_outliner_failure_json_preserves_details_without_compile_fallback_or_temp_source(self):
        failure = {'status': 'failed',
                   'failures': [{'reason': 'parse_error', 'details': {'line': 17, 'node': 'ERROR',
                                                                     'message': 'stub parse failure'}}],
                   'skipped': [{'reason': 'readonly_literal', 'line': 3}],
                   'stub': True}
        self.outliner.write_text(
            STUB_OUTLINER + '\nPath(a.report).write_text(' + repr(json.dumps(failure)) +
            ", encoding='utf-8')\nraise SystemExit(31)\n", encoding='utf-8')
        self.prepare()
        original = self.input.read_bytes()
        result = self.run_wrapper(self.compile_flags())
        self.assertEqual(result.returncode, 31, result.stdout + result.stderr)
        report = self.reports()[-1]
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['outliner_report'], failure)
        self.assertEqual(report['outliner_report']['failures'][0]['reason'], 'parse_error')
        self.assertEqual(report['outliner_report']['skipped'], failure['skipped'])
        self.assertTrue(report['source_unchanged'])
        self.assertEqual(self.input.read_bytes(), original)
        self.assertNotIn('compile_command', report)
        self.assertFalse(self.output.exists())
        self.assertEqual(len([call for call in self.calls() if '-E' in call['expanded']]), 1)
        self.assertEqual(len([call for call in self.calls() if '-c' in call['expanded'] and
                              '--version' not in call['expanded']]), 0)
        self.assertFalse(list((self.state / 'work').iterdir()))
        self.assertFalse(report['temporary_files_retained'])

    def test_response_cycle_rejected_without_running_compiler(self):
        rsp = self.build / 'cycle.rsp'
        rsp.write_text(wrapper.join_response(['@' + str(rsp)], 'gnu'), encoding='utf-8')
        result = self.run_wrapper(['@' + str(rsp)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('response-file cycle', result.stderr)
        self.assertEqual(self.calls(), [])

    def test_installed_wrapper_and_outliner_hash_drift_fails_before_compiler(self):
        before = self.input.read_bytes()
        for path in (self.outliner, self.state / 'string_outline_compiler.py'):
            with self.subTest(path=path):
                self.prepare()
                self.log.unlink(missing_ok=True)
                original = path.read_bytes()
                path.write_bytes(original + b'\n# drift after prepare\n')
                result = self.run_wrapper(self.compile_flags())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('hash differs from configuration', result.stderr)
                self.assertEqual(self.calls(), [])
                self.assertEqual(self.input.read_bytes(), before)
                path.write_bytes(original)

    def test_installed_cpp_header_policy_drift_fails_before_compiler(self):
        original = self.config.read_bytes()
        for policy in (None, 'legacy-opaque-every-header'):
            with self.subTest(policy=policy):
                config = json.loads(original)
                if policy is None:
                    config.pop('cpp_header_policy')
                else:
                    config['cpp_header_policy'] = policy
                self.config.write_text(json.dumps(config), encoding='utf-8')
                result = self.run_wrapper(self.compile_flags())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unsupported C++ header origin policy', result.stderr)
                self.assertEqual(self.calls(), [])
                with self.assertRaisesRegex(installer.InstallationError, r'unsupported installed C\+\+ header origin policy'):
                    installer.validate_build(self.state, self.build)
        self.config.write_bytes(original)

    def test_installer_idempotent_env_and_both_pinned_releng_source_contracts(self):
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in
                  (self.config, self.state / 'string_outline_compiler.py', self.env_output)}
        second = self.prepare()
        self.assertFalse(second['changed'])
        for path, (data, timestamp) in before.items():
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.stat().st_mtime_ns, timestamp)
        environment = dict(line.split('=', 1) for line in self.env_output.read_text(encoding='utf-8').splitlines())
        self.assertEqual(environment, second['environment'])
        self.assertEqual(environment['NIANCHU_STRING_OUTLINER'], str(self.outliner))
        for version in ('16.7.19', '17.25.2'):
            pin = installer.PINNED_RELENG[version]
            self.assertEqual(len(pin['commit']), 40)
            self.assertEqual(len(pin['env_android_sha256']), 64)
            source = 'def init(environ, argv, identifier, outdir, strv_to_meson):\n' + installer.RELENG_NEW
            ast.parse(source)
            self.assertIn('"--language", identifier', source)
            self.assertIn('"--build-root", str(outdir)', source)
            self.assertIn('"--", *argv', source)
            compat = (ROOT / 'tests/fixtures' / version / 'subprojects/frida-core/compat/build.py').read_text(encoding='utf-8')
            scrub = compat[compat.index('def scrub_environment('):compat.index('def scrub_windows_devenv_dirs_from_path(')]
            self.assertNotIn('NIANCHU', scrub)
            self.assertIn('clean_env[k] = v', scrub)
            self.assertIn('host_machine=host_machine', compat)

    def test_prepare_and_build_validation_record_tool_byte_identities(self):
        config = json.loads(self.config.read_text(encoding='utf-8'))
        expected = {
            'installer_sha256': hashlib.sha256((ROOT/'scripts/install_string_outline.py').read_bytes()).hexdigest(),
            'wrapper_sha256': hashlib.sha256((ROOT/'scripts/string_outline_compiler.py').read_bytes()).hexdigest(),
            'outliner_sha256': hashlib.sha256(self.outliner.read_bytes()).hexdigest(),
        }
        for name, digest in expected.items():
            self.assertEqual(config[name], digest)
            self.assertEqual(self.install[name], digest)
        self.assertEqual(self.install['wrapper_version'], installer.WRAPPER_VERSION)
        lines = []
        for language in ('c', 'cpp'):
            command = shlex.join(self.install['compiler_prefix'] +
                                 ['--language', language, '--build-root', str(self.build), '--', 'clang'])
            lines += ['rule ' + language + '_COMPILER', ' command = ' + command + ' -c $in -o $out']
        ninja = self.build/'build.ninja'
        ninja.write_text('\n'.join(lines), encoding='utf-8')
        before = {path: path.read_bytes() for path in (self.config, self.outliner, ninja)}
        result = installer.validate_build(self.state, self.build)
        self.assertEqual(result['wrapper_version'], installer.WRAPPER_VERSION)
        for name, digest in expected.items():
            self.assertEqual(result[name], digest)
        for path, data in before.items():
            self.assertEqual(path.read_bytes(), data)

    def test_build_validation_rejects_missing_or_drifted_installer_identity(self):
        original = self.config.read_bytes()
        for value in (None, '0'*64):
            with self.subTest(value=value):
                config = json.loads(original)
                if value is None:
                    config.pop('installer_sha256')
                else:
                    config['installer_sha256'] = value
                self.config.write_text(json.dumps(config), encoding='utf-8')
                before = self.config.read_bytes()
                with self.assertRaisesRegex(installer.InstallationError, 'installer changed after prepare'):
                    installer.validate_build(self.state, self.build)
                self.assertEqual(self.config.read_bytes(), before)
                self.assertEqual(self.calls(), [])
        self.config.write_bytes(original)

    def test_environment_merge_preserves_unrelated_single_and_multiline_values(self):
        original = ('UNRELATED=keep this value\nMULTILINE<<END_NIANCHU\n'
                    'NIANCHU_STRING_OUTLINER=not-an-assignment-in-a-multiline-value\nEND_NIANCHU\n'
                    'NIANCHU_STRING_OUTLINER=stale\nNIANCHU_STRING_OUTLINER=duplicate\nTAIL=keep')
        self.env_output.write_text(original, encoding='utf-8')
        result = self.prepare()
        merged = self.env_output.read_text(encoding='utf-8')
        self.assertIn('UNRELATED=keep this value\n', merged)
        self.assertIn('MULTILINE<<END_NIANCHU\nNIANCHU_STRING_OUTLINER=not-an-assignment-in-a-multiline-value\nEND_NIANCHU\n', merged)
        self.assertIn('TAIL=keep\n', merged)
        self.assertNotIn('=stale', merged)
        self.assertNotIn('=duplicate', merged)
        self.assertEqual(merged.count('NIANCHU_STRING_OUTLINER='), 2)
        self.assertTrue(result['changed'])
        self.assertFalse(self.prepare()['changed'])
        self.env_output.write_text('NIANCHU_STRING_OUTLINER<<END\nold\nEND\n', encoding='utf-8')
        with self.assertRaises(installer.InstallationError):
            self.prepare()

    def test_build_validation_is_readonly_and_refuses_missing_wrapper_or_cpp_rule(self):
        prefix = self.install['compiler_prefix']
        lines = []
        for language in ('c', 'cpp'):
            command = shlex.join(prefix + ['--language', language, '--build-root', str(self.build), '--', 'clang'])
            lines += ['rule ' + language + '_COMPILER', ' command = ' + command + ' $ARGS -MD -MF $DEPFILE -o $out -c $in',
                      ' depfile = $DEPFILE']
        ninja = self.build / 'build.ninja'
        ninja.write_text('\n'.join(lines), encoding='utf-8')
        before = ninja.read_bytes()
        result = installer.validate_build(self.state, self.build)
        self.assertEqual(result['status'], 'validated')
        self.assertEqual(ninja.read_bytes(), before)
        ninja.write_text(before.decode().replace(str(self.state / 'string_outline_compiler.py'), '/plain/compiler'), encoding='utf-8')
        with self.assertRaises(installer.InstallationError):
            installer.validate_build(self.state, self.build)
        ninja.write_text('rule c_COMPILER\n command = clang -c $in -o $out\n', encoding='utf-8')
        with self.assertRaises(installer.InstallationError):
            installer.validate_build(self.state, self.build)

    def test_response_quoting_roundtrip_gnu_and_windows(self):
        args = ['clang', 'a b.c', r'C:\with space\source.c', 'a"b', 'backslash\\', '',
                '-DNAME="quoted value"', '$literal', 'a#b']
        for response_format in ('gnu', 'windows'):
            encoded = wrapper.join_response(args, response_format).encode('utf-8')
            self.assertEqual(wrapper.split_response(encoded, response_format), args)

    def test_exact_parser_version_and_abi_preflight_when_available(self):
        try:
            import importlib.metadata as metadata
            versions = {name:metadata.version(name) for name in installer.PARSER_PINS}
        except metadata.PackageNotFoundError:
            self.skipTest('exact parser venv not installed in this interpreter')
        if versions != installer.PARSER_PINS:
            self.skipTest('interpreter is not the exact parser venv')
        result = installer.dependency_preflight(Path(sys.executable), self.tools)
        self.assertEqual(result['versions'], installer.PARSER_PINS)
        self.assertTrue(result['isolated'])
        self.assertEqual(result['executable'], sys.executable)

    def test_real_outliner_wrapper_native_heap_restore_and_original_dependencies(self):
        compilers = {'c': os.environ.get('STRING_OUTLINE_CC') or shutil.which('gcc') or shutil.which('cc'),
                     'cpp': os.environ.get('STRING_OUTLINE_CXX') or shutil.which('g++') or shutil.which('c++')}
        if not all(compilers.values()):
            if os.environ.get('STRING_OUTLINE_REQUIRE_HOST') == '1':
                self.fail('real C/C++ compilers required for outliner integration')
            self.skipTest('native C/C++ compilers unavailable for real outliner integration')
        self.outliner = ROOT / 'scripts' / 'outline_elf_strings.py'
        self.prepare(allow_stub=False)
        # These single-threaded stubs exercise wrapper integration and heap
        # lifetime; actual GLib and concurrency have their own runtime tests.
        support = self.tools / 'heap support.c'
        support.write_text(
            '#include <stdlib.h>\n#include <string.h>\n'
            'typedef unsigned long gsize;\n'
            'void *g_malloc(gsize n) { return malloc((size_t)n); }\n'
            'int g_once_init_enter(volatile gsize *location) { return *location == 0; }\n'
            'void g_once_init_leave(volatile gsize *location, gsize value) { *location = value; }\n'
            'int nianchu_wire_matches(const char *value) { return strcmp(value,"frida:rpc") == 0; }\n'
            'int nianchu_task_matches(const char *value) { return strcmp(value,"Frida.Agent.load") == 0; }\n',
            encoding='utf-8')
        support_object = self.tools / 'heap support.o'
        compiled = subprocess.run([compilers['c'], '-std=gnu99', '-O2', '-Wall', '-Wextra', '-Werror',
                                   '-c', str(support), '-o', str(support_object)],
                                  cwd=self.tools, capture_output=True, text=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        declarations = ('typedef unsigned long gsize;\n'
                        'void *g_malloc(gsize);\n'
                        'int g_once_init_enter(volatile gsize *);\n'
                        'void g_once_init_leave(volatile gsize *, gsize);\n'
                        'int nianchu_wire_matches(const char *);\n'
                        'int nianchu_task_matches(const char *);\n')
        body = ('const char *wire="frida:rpc";\n'
                'const char *task_name(void) { return "Frida.Agent.load"; }\n'
                'int main(void) {\n'
                '  forced_header_type forced={4}; original_header_type number=BASE;\n'
                '  return !nianchu_wire_matches(wire) || !nianchu_task_matches(task_name())\n'
                '      || forced.value != 4 || number != 3;\n'
                '}\n')
        for language, compiler in compilers.items():
            with self.subTest(language=language):
                suffix = '.c' if language == 'c' else '.cpp'
                source = self.core / ('actual outliner' + suffix)
                prototype = declarations if language == 'c' else 'extern "C" {\n' + declarations + '}\n'
                source.write_text('#include "original header.h"\n' + prototype + body, encoding='utf-8')
                source.chmod(stat.S_IREAD)
                original = source.read_bytes()
                output = self.output.with_name('actual outliner' + suffix + '.o')
                depfile = output.with_suffix('.d')
                flags = ['-std=' + ('gnu99' if language == 'c' else 'gnu++17'), '-O2', '-Wall', '-Wextra',
                         '-Werror', '-D', 'BASE=3', '-include', str(self.forced), '-I', str(self.core),
                         '-MMD', '-MQ', str(output), '-MF', str(depfile), '-c', str(source), '-o', str(output)]
                report = self.assert_success(self.run_wrapper(flags, language=language, compiler=[compiler]))
                self.assertTrue(report['outliner_report']['ok'])
                self.assertNotIn('stub', report['outliner_report'])
                self.assertGreaterEqual(report['outliner_report']['summary']['literal_occurrences_transformed'], 2)
                self.assertEqual(report['outliner'], str(self.outliner))
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(report['source_mode_before'], report['source_mode_after'])
                self.assertFalse(report['temporary_files_retained'])
                self.assertFalse(list((self.state / 'work').iterdir()))
                object_bytes = output.read_bytes()
                for plaintext in (b'frida:rpc', b'Frida.Agent.load'):
                    self.assertNotIn(plaintext, object_bytes)
                dependencies = depfile.read_bytes()
                for required in (b'original\\ header.h', b'forced\\ header.h'):
                    self.assertIn(required, dependencies)
                self.assertNotIn(b'preprocessed', dependencies)
                self.assertNotIn(b'outlined', dependencies)
                self.assertEqual(report['depfile_sha256'], hashlib.sha256(dependencies).hexdigest())
                executable = self.tools / ('actual-' + language + ('.exe' if os.name == 'nt' else ''))
                linked = subprocess.run([compiler, str(output), str(support_object), '-o', str(executable)],
                                        cwd=self.tools, capture_output=True, text=True, timeout=60)
                self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
                runtime_environment = {**os.environ,
                                       'PATH': str(Path(compiler).resolve().parent) + os.pathsep + os.environ.get('PATH', '')}
                restored = subprocess.run([str(executable)], cwd=self.tools, env=runtime_environment,
                                          capture_output=True, timeout=30)
                self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)

    def test_cpp_preserves_origins_and_forwards_only_explicit_header_roots(self):
        toolchain = self.base / 'installed ndk' / 'toolchains' / 'llvm' / 'prebuilt' / 'host'
        binary = toolchain / 'bin' / 'clang'
        binary.parent.mkdir(parents=True)
        binary.write_text('compiler identity fixture', encoding='utf-8')
        libcxx = toolchain / 'sysroot' / 'usr' / 'include' / 'c++' / 'v1'
        libcxx.mkdir(parents=True)
        sdk = self.base / 'sdk headers' / 'include'
        v8 = sdk / 'v8-10.0'
        hwy = sdk / 'hwy'
        glib = sdk / 'glib-2.0'
        for path in (v8, hwy, glib):
            path.mkdir(parents=True)
        source = self.core / 'origin source.cpp'
        source.write_text('const char *message="frida-outline-me";\n', encoding='utf-8')
        output = self.output.with_name('origin.cpp.o')
        unit = wrapper.CompileInput(0, source, output, 'cpp', [], [])
        config = json.loads(self.config.read_text(encoding='utf-8'))
        argv = [str(binary), '-I', str(v8), '-isystem', str(glib), '-I' + str(sdk),
                '-I', str(self.core), '-c', str(source), '-o', str(output)]
        roots = wrapper.cpp_header_origin_roots(argv, unit, config, self.build)
        self.assertEqual(set(roots), {str(path.resolve()) for path in (libcxx, v8, hwy)})
        self.assertNotIn(str(glib.resolve()), roots)
        self.assertNotIn(str(self.core.resolve()), roots)
        self.assertEqual(wrapper.cpp_header_origin_roots(argv,
            wrapper.CompileInput(0, self.input, self.output, 'c', [], []), config, self.build), [])
        result = self.run_wrapper(['-std=gnu++17', '-I', str(v8), '-isystem', str(glib),
            '-I' + str(sdk), '-c', str(source), '-o', str(output)], language='cpp')
        report = self.assert_success(result)
        self.assertEqual(report['cpp_header_policy'], wrapper.CPP_HEADER_POLICY)
        self.assertTrue(report['compiler_line_origins_preserved'])
        self.assertNotIn('-P', report['preprocess_expanded_argv'])
        self.assertEqual(set(report['cpp_opaque_roots']), {str(path.resolve()) for path in (v8, hwy)})
        outline = report['outline_command']
        forwarded = [outline[index + 1] for index, value in enumerate(outline) if value == '--cpp-opaque-root']
        self.assertEqual(forwarded, report['cpp_opaque_roots'])

    def test_cpp_header_root_cannot_hide_owned_source(self):
        source = self.core / 'origin.cpp'
        source.write_text('int value;\n', encoding='utf-8')
        unit = wrapper.CompileInput(0, source, self.output, 'cpp', [], [])
        config = json.loads(self.config.read_text(encoding='utf-8'))
        owned = self.core / 'v8-10.0'
        nested = self.source / 'subprojects/frida-gum/subprojects/dep/include/v8-15.0'
        for root in (owned, nested):
            with self.subTest(root=root):
                root.mkdir(parents=True)
                with self.assertRaisesRegex(wrapper.OutlineBuildError, 'overlaps owned'):
                    wrapper.cpp_header_origin_roots(['compiler', '-I', str(root)], unit, config, self.build)
        ancestor = self.base / 'ancestor roots' / 'v8-10.0'
        (ancestor / 'subprojects/frida-core').mkdir(parents=True)
        with self.assertRaisesRegex(wrapper.OutlineBuildError, 'overlaps owned'):
            wrapper.cpp_header_origin_roots(['compiler', '-I', str(ancestor)], unit,
                dict(config, source_root=str(ancestor)), self.build)

    def test_cpp_header_roots_resolve_path_compiler_and_explicit_sysroot(self):
        source = self.core / 'origin.cpp'
        source.write_text('int value;\n', encoding='utf-8')
        unit = wrapper.CompileInput(0, source, self.output, 'cpp', [], [])
        config = json.loads(self.config.read_text(encoding='utf-8'))
        toolchain = self.base / 'known ndk host'
        binary = toolchain / 'bin' / 'clang++'
        binary.parent.mkdir(parents=True)
        binary.write_text('compiler identity fixture', encoding='utf-8')
        libcxx = toolchain / 'sysroot/usr/include/c++/v1'
        libcxx.mkdir(parents=True)
        from unittest import mock
        with mock.patch.object(wrapper.shutil, 'which', return_value=str(binary)) as lookup:
            roots = wrapper.cpp_header_origin_roots(['clang++', '-c', str(source)], unit, config, self.build)
        lookup.assert_called_once_with('clang++')
        self.assertEqual(roots, [str(libcxx.resolve())])
        self.assertEqual(wrapper.cpp_header_origin_roots([
            str(binary), '--sysroot=' + str(toolchain / 'sysroot'), '-c', str(source)], unit, config, self.build), roots)

    def test_c_cpp_direct_line_marker_suppression_removed(self):
        for language in ('c', 'cpp'):
            with self.subTest(language=language):
                suffix = '.c' if language == 'c' else '.cpp'
                source = self.core / ('direct origins' + suffix)
                source.write_text('const char *message="frida-outline-me";\n', encoding='utf-8')
                output = self.output.with_name('direct origins' + suffix + '.o')
                report = self.assert_success(self.run_wrapper(
                    ['-P', '-c', str(source), '-o', str(output)], language=language))
                self.assertIn('-P', report['original_expanded_argv'])
                self.assertNotIn('-P', report['preprocess_expanded_argv'])
                self.assertTrue(report['compiler_line_origins_preserved'])

    def test_c_cpp_wrapped_line_marker_suppression_rejected(self):
        variants = (['-Wp,-P'], ['-Wp,-MD,ignored.d,-P'], ['-Xpreprocessor', '-P'],
                    ['-Xclang', '-P'], ['-Xpreprocessor=-P'], ['-Xclang=-P'])
        for language in ('c', 'cpp'):
            suffix = '.c' if language == 'c' else '.cpp'
            source = self.core / ('origin' + suffix)
            source.write_text('int value;\n', encoding='utf-8')
            for index, wrapped in enumerate(variants):
                with self.subTest(language=language, wrapped=wrapped):
                    output = self.output.with_name('origin-' + str(index) + suffix + '.o')
                    result = self.run_wrapper([*wrapped, '-c', str(source), '-o', str(output)], language=language)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('wrapped -P is unsupported', result.stderr)
        self.assertFalse(any('-E' in call['expanded'] for call in self.calls()))

    def test_real_c_system_header_diagnostics_preserved_and_owned_errors_rejected(self):
        compiler = os.environ.get('STRING_OUTLINE_CC') or shutil.which('gcc') or shutil.which('cc')
        if not compiler:
            if os.environ.get('STRING_OUTLINE_REQUIRE_HOST') == '1':
                self.fail('native C compiler required for system-header diagnostics')
            self.skipTest('native C compiler unavailable for system-header diagnostics')
        self.outliner = ROOT / 'scripts' / 'outline_elf_strings.py'
        self.prepare(allow_stub=False)
        system = self.tools / 'system diagnostic.h'
        system.write_text(
            '#pragma GCC system_header\n'
            'static inline int system_result(void) { return missing_system_declaration(); }\n',
            encoding='utf-8')
        declarations = ('typedef unsigned long gsize; void *g_malloc(gsize);\n'
                        'int g_once_init_enter(volatile gsize *);\n'
                        'void g_once_init_leave(volatile gsize *, gsize);\n')
        source = self.core / 'system diagnostic.c'
        source.write_text('#include "system diagnostic.h"\n' + declarations +
                          'const char *message(void) { return "FridaSystemDiagnostic"; }\n'
                          'int result(void) { return system_result(); }\n', encoding='utf-8')
        original = source.read_bytes()
        common = ['-std=gnu99', '-O2', '-Werror=implicit-function-declaration',
                  '-I', str(self.tools)]
        reference = self.tools / 'system-reference.o'
        plain = subprocess.run([compiler, *common, '-c', str(source), '-o', str(reference)],
                               cwd=self.tools, capture_output=True, text=True, timeout=60)
        self.assertEqual(plain.returncode, 0, plain.stdout + plain.stderr)
        output = self.output.with_name('system diagnostic.c.o')
        result = self.run_wrapper([*common, '-MD', '-MF', str(output.with_suffix('.d')),
                                   '-c', str(source), '-o', str(output)], compiler=[compiler])
        report = self.assert_success(result)
        self.assertTrue(report['compiler_line_origins_preserved'])
        self.assertTrue(report['outliner_report']['ok'])
        self.assertNotIn('-P', report['preprocess_expanded_argv'])
        self.assertNotIn(b'FridaSystemDiagnostic', output.read_bytes())
        self.assertEqual(source.read_bytes(), original)
        dependency = output.with_suffix('.d').read_text(encoding='utf-8')
        self.assertIn('system\\ diagnostic.h', dependency)
        self.assertNotIn('preprocessed.c', dependency)
        self.assertNotIn('outlined.c', dependency)
        source.write_text(original.decode('utf-8') +
                          'int owned_error(void) { return missing_owned_declaration(); }\n', encoding='utf-8')
        failed = self.run_wrapper([*common, '-c', str(source), '-o', str(output)], compiler=[compiler])
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('missing_owned_declaration', failed.stderr)
        self.assertEqual(self.reports()[-1]['status'], 'failed')
        self.assertTrue(self.reports()[-1]['source_unchanged'])

    def test_android_runtime_policy_follows_effective_target(self):
        for target, policy in [('aarch64-none-linux-android21', 'android-arm64'),
                               ('armv7a-none-linux-androideabi19', 'android-arm'),
                               ('x86_64-linux-gnu', 'glib')]:
            self.assertEqual(wrapper.outline_runtime_policy(['clang', '-target', target]), policy)
            self.assertEqual(wrapper.outline_runtime_policy(['clang', '--target=' + target]), policy)
        self.assertEqual(wrapper.outline_runtime_policy(['aarch64-linux-android21-clang.exe']), 'android-arm64')
        self.assertEqual(wrapper.outline_runtime_policy(['clang', '-target', 'aarch64-linux-android21',
                                                        '-target', 'armv7a-linux-androideabi19']), 'android-arm')
        with self.assertRaises(wrapper.OutlineBuildError):
            wrapper.outline_runtime_policy(['clang', '-target', 'x86_64-linux-android21'])
        with self.assertRaises(wrapper.OutlineBuildError):
            wrapper.outline_runtime_policy(['clang', '-target'])

    def test_real_android_arm64_and_compat_arm32_c_cpp_object_compilation(self):
        clang = os.environ.get('NIANCHU_TEST_CLANG') or shutil.which('clang')
        clangxx = os.environ.get('NIANCHU_TEST_CLANGXX') or shutil.which('clang++')
        if not clang or not clangxx:
            self.skipTest('Clang C/C++ is optional; stub command/dep/security tests always run')
        self.prepare(response_format='gnu')
        for target in ('aarch64-none-linux-android21', 'armv7a-none-linux-androideabi21'):
            for language, compiler in (('c', clang), ('cpp', clangxx)):
                with self.subTest(target=target, language=language):
                    suffix = '.c' if language == 'c' else '.cpp'
                    source = self.core / ('real object' + suffix)
                    source.write_text('#include "original header.h"\nconst char *message="frida-outline-me";\n'
                                      'const char *diagnostic_file=__FILE__;\nint number=BASE;\n'
                                      'original_header_type n=3; forced_header_type f={4};\n', encoding='utf-8')
                    output = self.output.with_name(target + suffix + '.o')
                    depfile = output.with_suffix('.d')
                    args = ['-target', target, '-D', 'BASE=23', '-O2', '-fPIC', '-include', str(self.forced),
                            '-I', str(self.core), '-MD', '-MQ', str(output), '-MF', str(depfile),
                            '-c', str(source), '-o', str(output)]
                    # Android Clang uses GCC/GNU response quoting on Windows
                    # too; verify spaces and backslashes with the real driver.
                    response = self.build / ('real ' + target + language + '.rsp')
                    response.write_text(wrapper.join_response(args, 'gnu'), encoding='utf-8')
                    before = source.read_bytes()
                    result = self.run_wrapper(['@' + str(response)], language=language, compiler=[compiler])
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    report = next(item for item in self.reports() if item['output'] == str(output))
                    self.assertEqual(report['status'], 'compiled')
                    self.assertTrue(report['source_unchanged'])
                    data = output.read_bytes()
                    self.assertEqual(data[:4], b'\x7fELF')
                    self.assertIn(b'nianchu-outline-me', data)
                    self.assertNotIn(b'frida-outline-me', data)
                    self.assertIn(b'nianchu-core', data)
                    self.assertNotIn(b'frida-core', data)
                    self.assertEqual(source.read_bytes(), before)
                    deps = depfile.read_bytes()
                    self.assertNotIn(b'preprocessed', deps)
                    self.assertNotIn(b'outlined', deps)
                    self.assertIn(b'original\\ header.h', deps)
                    self.assertIn(b'forced\\ header.h', deps)


if __name__ == '__main__':
    unittest.main()
