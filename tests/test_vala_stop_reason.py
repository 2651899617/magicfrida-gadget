#!/usr/bin/env python3
"""Pinned extraction tests and real compiler/runtime tests (Host GLib only)."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
module_spec = importlib.util.spec_from_file_location('vala_stop_reason', ROOT / 'scripts/verify_vala_stop_reason.py')
verifier = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(verifier)
patch_spec = importlib.util.spec_from_file_location('stop_reason_profiles', ROOT / 'scripts/apply_patches.py')
profiles = importlib.util.module_from_spec(patch_spec)
patch_spec.loader.exec_module(profiles)


class StopReasonExtractionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def pinned_copy(self, version='16.7.19'):
        root = self.directory / 'inputs'
        spec_path = root / 'patches' / version / 'spec.json'
        fixture = root / 'tests' / 'fixtures' / version / verifier.AGENT_PATH
        spec_path.parent.mkdir(parents=True, exist_ok=True)
        fixture.parent.mkdir(parents=True, exist_ok=True)
        spec_path.write_bytes((ROOT / 'patches' / version / 'spec.json').read_bytes())
        fixture.write_bytes((ROOT / 'tests' / 'fixtures' / version / verifier.AGENT_PATH).read_bytes())
        return root, spec_path, fixture

    def test_extracts_both_actual_specs_after_sha_and_default_profile(self):
        for version in verifier.VERSIONS:
            with self.subTest(version=version):
                declaration, provenance = verifier.load_stop_reason(version)
                spec_bytes = (ROOT / 'patches' / version / 'spec.json').read_bytes()
                recipe = json.loads(spec_bytes)
                entry = next(item for item in recipe['files'] if item['path'] == verifier.AGENT_PATH)
                base = (ROOT / 'tests' / 'fixtures' / version / verifier.AGENT_PATH).read_bytes()
                patched = profiles.profile_bytes(base, entry, profiles.selected_features(recipe)).decode('utf-8')
                self.assertEqual(provenance['fixture']['sha256'], entry['upstream_sha256'])
                self.assertEqual(provenance['spec']['sha256'], verifier.digest(spec_bytes))
                self.assertEqual(provenance['patched_agent_sha256'], verifier.digest(patched.encode('utf-8')))
                self.assertEqual(provenance['features'], profiles.selected_features(recipe))
                self.assertIn(declaration, patched)
                # This independent literal slice proves the adjacent annotation/body are not rebuilt.
                start = patched.rfind('\n', 0, patched.index('[CCode (cname = "NianchuAgentStopReason"')) + 1
                enum_end = patched.index('\n\t}', start) + len('\n\t}\n')
                self.assertEqual(declaration, patched[start:enum_end])
                self.assertIn('private enum StopReason {', declaration)
                for annotation in ('cname = "NianchuAgentStopReason"', 'cprefix = "FRIDA_AGENT_STOP_REASON_"',
                                   'lower_case_cprefix = "frida_agent_stop_reason_"'):
                    self.assertIn(annotation, declaration)
                self.assertIn('\t\tUNLOAD,\n\t\tPROCESS_TRANSITION\n', declaration)

    def test_program_preserves_enum_and_private_probe_scope(self):
        for version in verifier.VERSIONS:
            declaration, _ = verifier.load_stop_reason(version)
            program = verifier.build_program(declaration)
            self.assertEqual(program.count(declaration), 1)
            self.assertEqual(program.count('[CCode'), declaration.count('[CCode'))
            self.assertIn('namespace Frida.Agent {', program)
            self.assertIn('private class Probe : GLib.Object', program)
            self.assertIn('private static int main (string[] args)', program)
            self.assertNotIn('public enum', program)
            self.assertNotIn('public class Probe', program)
            self.assertIn('probe.set_property ("stop-reason", writeback)', program)
            self.assertIn('probe.get_property ("stop-reason", ref readback)', program)
            self.assertIn('Host GLib only', program)

    def test_corrupt_fixture_fails_before_extraction(self):
        root, _, fixture = self.pinned_copy()
        fixture.write_bytes(fixture.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'corrupt pinned source fixture'):
            verifier.load_stop_reason('16.7.19', root)

    def test_stale_spec_is_not_repaired_from_generator(self):
        root, spec_path, _ = self.pinned_copy()
        recipe = json.loads(spec_path.read_bytes())
        entry = next(item for item in recipe['files'] if item['path'] == verifier.AGENT_PATH)
        entry['edits'] = [item for item in entry['edits'] if 'private enum StopReason' not in item['old']]
        spec_path.write_text(json.dumps(recipe), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'missing its immediately preceding CCode'):
            verifier.load_stop_reason('16.7.19', root)

    def test_default_optional_edits_are_applied_in_order(self):
        root, spec_path, _ = self.pinned_copy()
        recipe = json.loads(spec_path.read_bytes())
        expected, _ = verifier.load_stop_reason('16.7.19')
        entry = next(item for item in recipe['files'] if item['path'] == verifier.AGENT_PATH)
        enum_edit = next(item for item in entry['edits'] if item['old'] == '\tprivate enum StopReason {')
        entry['edits'].remove(enum_edit)
        # The annotation exists only in the default feature, not in unconditional edits.
        feature = recipe['default_features'][0]
        entry['optional'][feature] = [copy.deepcopy(enum_edit),
                                      {'old': 'cname = "NianchuAgentStopReason"',
                                       'new': 'cname = "ProfileSpecificStopReason"', 'count': 1}]
        spec_path.write_text(json.dumps(recipe), encoding='utf-8')
        declaration, provenance = verifier.load_stop_reason('16.7.19', root)
        self.assertEqual(declaration, expected.replace('NianchuAgentStopReason', 'ProfileSpecificStopReason'))
        self.assertEqual(provenance['features'], recipe['default_features'])

    def test_bad_edit_count_and_bad_default_features_fail(self):
        root, spec_path, _ = self.pinned_copy()
        recipe = json.loads(spec_path.read_bytes())
        entry = next(item for item in recipe['files'] if item['path'] == verifier.AGENT_PATH)
        entry['edits'][0]['count'] += 1
        spec_path.write_text(json.dumps(recipe), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'expected exactly'):
            verifier.load_stop_reason('16.7.19', root)
        recipe['default_features'].append(recipe['default_features'][0])
        spec_path.write_text(json.dumps(recipe), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'invalid default features'):
            verifier.load_stop_reason('16.7.19', root)

    def test_multiline_annotation_and_comment_braces_preserved_verbatim(self):
        declaration = ('\t[CCode (\n\t\tcname = "LiteralStopReason", cprefix = "LITERAL_",\n'
                       '\t\tlower_case_cprefix = "literal_"\n\t)]\n'
                       '\tprivate enum StopReason {\n\t\tUNLOAD, // a fake closing }\n'
                       '\t\t/* enum StopReason { ignored } */ PROCESS_TRANSITION\n\t}\n')
        source = ('namespace Frida.Agent {\n\tvoid previous () {}\n\n' + declaration +
                  '\tprivate class Other : GLib.Object {}\n}\n')
        self.assertEqual(verifier.extract_stop_reason(source), declaration)

    def test_visibility_namespace_missing_adjacent_ccode_and_duplicates_fail(self):
        declaration, _ = verifier.load_stop_reason('16.7.19')
        valid = 'namespace Frida.Agent {\n' + declaration + '}\n'
        invalid = (valid.replace('private enum', 'public enum'),
                   valid.replace('namespace Frida.Agent', 'namespace Other.Agent'),
                   'namespace Frida.Agent {\n\tprivate class Inner {\n' + declaration + '\t}\n}\n',
                   'namespace Frida.Agent {\n' + declaration + declaration + '}\n',
                   valid.replace('private enum', 'void between () {}\n\tprivate enum'))
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(ValueError):
                verifier.extract_stop_reason(source)

    def test_existing_out_directory_or_file_is_rejected_and_untouched(self):
        for name, directory in (('existing-directory', True), ('existing-file', False)):
            out = self.directory / name
            if directory:
                out.mkdir()
                sentinel = out / 'sentinel'
            else:
                sentinel = out
            sentinel.write_bytes(b'preserve')
            with self.subTest(directory=directory), self.assertRaisesRegex(ValueError, 'new, nonexistent'):
                verifier.verify(out)
            self.assertEqual(sentinel.read_bytes(), b'preserve')

    def test_missing_explicit_tool_is_nonzero_without_creating_output(self):
        out = self.directory / 'missing-tool-output'
        result = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/verify_vala_stop_reason.py'),
                                 '--out', str(out), '--valac', str(self.directory / 'no-such-valac')],
                                cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('tool missing: valac', result.stderr)
        self.assertFalse(out.exists())


class RealHostStopReasonTests(unittest.TestCase):
    def test_both_pinned_versions_really_compile_and_run(self):
        # No mocked compiler or substituted generated C: only absent tools can skip.
        try:
            tools = verifier.resolve_tools()
        except verifier.MissingTool as error:
            self.skipTest(str(error))
        # A present compiler/pkg-config, missing dev package, compilation error, or runtime
        # assertion is a test failure, never converted to a skip.
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / 'vala-stop-reason'
            result = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/verify_vala_stop_reason.py'),
                                     '--out', str(out), '--valac', tools['valac'], '--cc', tools['cc'],
                                     '--pkg-config', tools['pkg-config']], cwd=ROOT, capture_output=True,
                                    text=True, encoding='utf-8', errors='replace', timeout=600)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((out / 'report.json').read_bytes())
            self.assertEqual(report['scope'], 'Host GLib only')
            self.assertTrue(report['host_runtime_tested'])
            self.assertFalse(report['android_runtime_tested'])
            self.assertEqual([item['version'] for item in report['versions']], list(verifier.VERSIONS))
            for name, tool in report['tools'].items():
                self.assertEqual(tool['path'], tools[name])
                self.assertEqual(tool['version']['returncode'], 0)
                self.assertTrue(tool['version']['stdout'] or tool['version']['stderr'])
            self.assertEqual(report['glib_package_versions']['returncode'], 0)
            self.assertEqual(len(report['glib_package_versions']['stdout'].splitlines()), 2)
            self.assertEqual(report['pkg_config_flags']['returncode'], 0)
            for item in report['versions']:
                with self.subTest(version=item['version']):
                    declaration, _ = verifier.load_stop_reason(item['version'])
                    source = Path(item['source']['path']).read_bytes()
                    generated = Path(item['generated_c']['path']).read_bytes()
                    executable = Path(item['executable']['path']).read_bytes()
                    self.assertEqual(source.decode('utf-8'), verifier.build_program(declaration))
                    self.assertEqual(item['source']['sha256'], verifier.digest(source))
                    self.assertEqual(item['source']['text'], source.decode('utf-8'))
                    self.assertEqual(item['generated_c']['sha256'], verifier.digest(generated))
                    self.assertEqual(item['generated_c']['text'], generated.decode('utf-8'))
                    self.assertEqual(item['executable']['sha256'], verifier.digest(executable))
                    self.assertIn(b'NianchuAgentStopReason', generated)
                    self.assertIn(b'frida_agent_stop_reason_get_type', generated)
                    for value_name in (b'FRIDA_AGENT_STOP_REASON_UNLOAD', b'FRIDA_AGENT_STOP_REASON_PROCESS_TRANSITION'):
                        self.assertIn(value_name, generated)
                    for stage, stem in (('valac_compile', 'valac'), ('c_compile', 'cc'), ('run', 'run')):
                        self.assertEqual(item[stage]['returncode'], 0)
                        for stream in ('stdout', 'stderr'):
                            log = out / item['version'] / (stem + '.' + stream + '.txt')
                            self.assertEqual(log.read_bytes().decode('utf-8'), item[stage][stream])
                    self.assertIn('-C', item['valac_compile']['argv'])
                    self.assertEqual(item['c_compile']['argv'][0], tools['cc'])
                    self.assertEqual(item['run']['stdout'].splitlines(), verifier.EXPECTED_OUTPUT.splitlines())
                    self.assertTrue(item['host_runtime_tested'])
                    self.assertEqual(item['run_environment'], {'G_DEBUG': 'fatal-warnings'})


if __name__ == '__main__':
    unittest.main()
