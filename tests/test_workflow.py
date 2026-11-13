#!/usr/bin/env python3
"""Offline generation and build-hook contracts, not CI/Android execution."""
import ast
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
module_spec = importlib.util.spec_from_file_location('patches', ROOT / 'scripts/apply_patches.py')
patches = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(patches)


def default_source(version, relative):
    recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
    entry = next(item for item in recipe['files'] if item['path'] == relative)
    base = (ROOT / 'tests/fixtures' / version / relative).read_bytes()
    return patches.profile_bytes(base, entry, patches.selected_features(recipe)).decode('utf-8')


class WorkflowTests(unittest.TestCase):
    def test_generation_reproduces_checked_in_specs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'generated'
            result = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/generate_pinned_specs.py'),
                                     '--output', str(output)], capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for version in ('16.7.19', '17.25.2'):
                actual = json.loads((output / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
                expected = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
                self.assertEqual(actual, expected)
                self.assertEqual(actual['default_features'], ['exit-monitor-off', 'signal-interposition-off',
                                                              'agent-entrypoint-rename', 'gadget-json-config'])
                self.assertEqual(len(actual['files']), 56 if version.startswith('16.') else 58)
                for feature in (None, *actual['features']):
                    name = (feature or 'compatible') + '.patch'
                    self.assertEqual((output / 'patches' / version / name).read_bytes(),
                                     (ROOT / 'patches' / version / name).read_bytes())
                for entry in actual['files']:
                    relative = Path('tests/fixtures') / version / entry['path']
                    self.assertEqual((output / relative).read_bytes(), (ROOT / relative).read_bytes())

    def test_outline_android_compiler_arrays_are_pinned_and_keep_target_flags(self):
        expected_sha = {
            '16.7.19': 'fddf203f9234a5604c275eeec32ac2795f2f0b9459312d8f2915ea66a6acc9c5',
            '17.25.2': '33efcf33095441ce6b54f4074740acc66dec149e13abb8cedc2dc3cfeb1b37b4',
        }
        for version in patches.VERSIONS:
            relative = 'releng/env_android.py'
            base = (ROOT / 'tests/fixtures' / version / relative).read_bytes()
            self.assertEqual(patches.digest(base), expected_sha[version])
            text = default_source(version, relative)
            ast.parse(text)
            self.assertIn('if identifier in {"c", "cpp"} and environ.get("NIANCHU_STRING_OUTLINER"):', text)
            self.assertIn('environ["NIANCHU_STRING_OUTLINE_PYTHON"], "-I"', text)
            self.assertIn('"--config", environ["NIANCHU_STRING_OUTLINE_CONFIG"]', text)
            self.assertIn('"--language", identifier, "--build-root", str(outdir), "--", *argv', text)
            self.assertIn('raw_val += " + common_flags"', text)
            self.assertIn('"-target",', text)
            self.assertEqual(text.count('NIANCHU_STRING_OUTLINER'), 1)
            self.assertIn('NDK_REQUIRED = ' + ('25' if version.startswith('16.') else '29'), text)

    def test_outline_prepare_and_compiler_gates_precede_make_and_collect(self):
        text = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        for pin in ('tree-sitter==0.25.2', 'tree-sitter-c==0.24.2', 'tree-sitter-cpp==0.23.4'):
            self.assertEqual(text.count(pin), 2)
        prepare = text.index('- name: Prepare isolated string outlining compiler')
        configure = text.index('- name: Configure Android arm64 server and Gadget')
        validate = text.index('- name: Check persistent Android compiler arrays')
        build = text.index('- name: Build nianchu server and modified auto-init Gadget')
        collect = text.index('- name: Verify compatible source and collect both final targets')
        self.assertLess(prepare, configure)
        self.assertLess(configure, validate)
        self.assertLess(validate, build)
        self.assertLess(build, collect)
        self.assertIn('--state-dir "$GITHUB_WORKSPACE/outline-state"', text)
        self.assertIn('outline-state/reports/', text)
        self.assertIn('NIANCHU_STRING_OUTLINER=$GITHUB_WORKSPACE/scripts/outline_elf_strings.py', text)
        gate = text[validate:build]
        self.assertIn('--build "$GITHUB_WORKSPACE/frida-src/build"', gate)
        for unwanted in ('--source', '--python', '--outliner'):
            self.assertNotIn(unwanted, gate)

    def test_git_preserves_entrypoint_patch_bytes(self):
        for version in ('16.7.19', '17.25.2'):
            path = ROOT / 'patches' / version / 'agent-entrypoint-rename.patch'
            data = path.read_bytes()
            self.assertIn(b' EXPORTS\r\n', data)
            raw = subprocess.run(['git', 'hash-object', '--stdin', '--no-filters'], input=data,
                                 cwd=ROOT, capture_output=True)
            filtered = subprocess.run(['git', 'hash-object', '--stdin', '--path=' + path.relative_to(ROOT).as_posix()],
                                      input=data, cwd=ROOT, capture_output=True)
            self.assertEqual(raw.returncode, 0, raw.stderr)
            self.assertEqual(filtered.returncode, 0, filtered.stderr)
            self.assertEqual(filtered.stdout, raw.stdout)

    def test_jdk_is_configured_before_android_sdk(self):
        source = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        self.assertIn("java-version: '17'", source)
        self.assertLess(source.index('uses: actions/setup-java@v4'),
                        source.index('uses: android-actions/setup-android@v3'))
        self.assertNotIn('SKIP_JDK_VERSION_CHECK', source)

    def test_android_setup_does_not_request_obsolete_tools(self):
        source = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        self.assertIn("packages: 'platform-tools'", source)
        self.assertNotIn('packages: tools', source)

    def test_default_embed_hooks_rewrite_nonempty_assets_before_resource_compilation(self):
        # These are pinned Python source contracts, not execution of the ELF rewriter.
        for version in patches.VERSIONS:
            for kind in ('agent', 'helper'):
                with self.subTest(version=version, kind=kind):
                    text = default_source(version, 'subprojects/frida-core/src/embed-' + kind + '.py')
                    ast.parse(text)
                    start = text.index('    if host_os in {"linux", "android"}:\n        rewriter')
                    end = text.index('    subprocess.run([\n        resource_compiler,', start)
                    hook = text[start:end]
                    self.assertIn('rewriter = __import__("os").environ["NIANCHU_ELF_REWRITER"]', hook)
                    self.assertIn('for asset in embedded_assets:', hook)
                    self.assertIn('if asset.stat().st_size == 0:\n                continue', hook)
                    self.assertIn('subprocess.run([sys.executable, "-I", rewriter, str(asset),', hook)
                    self.assertIn('"--rewrite", "--kind", "' + kind + '"', hook)
                    self.assertIn('"--report", str(asset) + ".rewrite.json"], check=True)', hook)
                    self.assertEqual(text.count('NIANCHU_ELF_REWRITER'), 1)
                    self.assertIn('] + embedded_assets, check=True)', text[end:])
                    self.assertIn('embedded_assets += [', text[:start])

    def test_default_frida_16_bridge_patch_runs_before_runtime_compilation(self):
        relative = 'subprojects/frida-gum/bindings/gumjs/generate-runtime.py'
        text = default_source('16.7.19', relative)
        ast.parse(text)
        self.assertIn('subprocess.run([sys.executable, "-I", os.environ["NIANCHU_BRIDGE_PATCHER"],', text)
        self.assertIn('"--source", str(priv_dir / "node_modules" / "frida-java-bridge"),', text)
        self.assertIn('"--version", "6.3.9", "--report", str(priv_dir / "nianchu-bridge-report.json")], check=True)', text)
        self.assertLess(text.index('NIANCHU_BRIDGE_PATCHER'), text.index('runtime_reldir = Path("runtime")'))
        self.assertLess(text.index('NIANCHU_BRIDGE_PATCHER'), text.index('call_compiler(runtime_reldir / "java.js"'))
        self.assertNotIn('NIANCHU_BRIDGE_PATCHER', default_source('17.25.2', relative))

    def test_workflow_syntax_and_build_contract(self):
        # YAML is an optional local check; the static build contract always runs.
        source = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        if importlib.util.find_spec('yaml'):
            import yaml
            document = yaml.load(source, Loader=yaml.BaseLoader)
            self.assertIn('on', document)
            self.assertEqual(document['jobs']['build']['needs'], 'checks')
            expression = document['jobs']['build']['strategy']['matrix']['include']
            self.assertIn('fromJSON(', expression)
            rows = [json.loads(value) for value in re.findall(r"'(\[\{[^']+\}\])'", expression)]
            expected16 = [{'version': '16.7.19', 'ndk_revision': '25.2.9519653'}]
            expected17 = [{'version': '17.25.2', 'ndk_revision': '29.0.14206865'}]
            self.assertEqual(rows, [expected17, expected16 + expected17, expected16])
            options = document['on']['workflow_dispatch']['inputs']['frida_version']
            self.assertEqual(options['default'], '16.7.19')
            self.assertEqual(options['options'], ['16.7.19', '17.25.2', 'both'])
        for token in ('scripts/verify_source.py', 'scripts/apply_patches.py', 'scripts/collect_artifacts.py',
                      'scripts/build_module.py', '-Dserver=enabled', '-Dgadget=enabled',
                      '-Dfrida-core:compiler_backend=enabled', "go-version: '1.26.x'", 'if: always()',
                      'set -euo pipefail', '--feature zygisk-loader'):
            self.assertIn(token, source)
        for token in ('set +e', '--fuzz=5', 'patches/frida-core', 'head -1', 'sh.rustup.rs', '17.6.2'):
            self.assertNotIn(token, source)

    def test_push_builds_only_16_and_dispatch_requires_explicit_17_selection(self):
        text = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        expression = next(line for line in text.splitlines() if 'include: ${{ fromJSON(' in line)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.frida_version == '17.25.2'", expression)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.frida_version == 'both'", expression)
        rows = [json.loads(value) for value in re.findall(r"'(\[\{[^']+\}\])'", expression)]
        expected16 = [{'version': '16.7.19', 'ndk_revision': '25.2.9519653'}]
        expected17 = [{'version': '17.25.2', 'ndk_revision': '29.0.14206865'}]
        self.assertEqual(rows, [expected17, expected16 + expected17, expected16])
        self.assertIn("default: '16.7.19'", text)

    def test_workflow_pins_lief_in_an_independent_venv_before_build(self):
        text = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        self.assertIn('python3-venv', text)
        self.assertRegex(text, r'\bpython3(?:\s+-I)?\s+-m\s+venv\b')
        self.assertIn('lief==0.17.6', text)
        self.assertLess(text.index('lief==0.17.6'), text.index('--host=android-arm64'))
        self.assertIn('GITHUB_PATH', text)
        for name in ('NIANCHU_ELF_REWRITER', 'NIANCHU_BRIDGE_PATCHER'):
            self.assertRegex(text, name + r'=[^\n]*(?:\$GITHUB_WORKSPACE|\$\{GITHUB_WORKSPACE\}|\$PWD|\$\{PWD\})/')
        self.assertIn('patches/rename.py', text)
        # Both real product collections must opt in; default and Zygisk are the only outputs.
        invocations = re.findall(r'scripts/collect_artifacts\.py[^\n]*', text.replace('\\\n', ' '))
        self.assertEqual(len(invocations), 2)
        for invocation, destination in zip(invocations, ('out/compatible', 'out/zygisk')):
            self.assertIn('--rewrite-elf', invocation)
            self.assertIn('--out ' + destination, invocation)
            self.assertIn('--patch-report ', invocation)
        self.assertIn('scripts/build_module.py', text)
        self.assertIn('--manifest out/zygisk/manifest.json', text)


if __name__ == '__main__':
    unittest.main()
