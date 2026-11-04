#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def test_generation_reproduces_checked_in_specs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'generated'
            result = subprocess.run(['python', '-I', str(ROOT / 'scripts/generate_pinned_specs.py'),
                                     '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            import json
            for version in ('16.7.19', '17.25.2'):
                actual = json.loads((output / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
                expected = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
                self.assertEqual(actual, expected)

    def test_jdk_is_configured_before_android_sdk(self):
        source = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        self.assertIn("java-version: '17'", source)
        self.assertLess(source.index('uses: actions/setup-java@v4'),
                        source.index('uses: android-actions/setup-android@v3'))
        self.assertNotIn('SKIP_JDK_VERSION_CHECK', source)

    def test_workflow_syntax_and_build_contract(self):
        # YAML is an optional local check; the static build contract always runs.
        source = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        if importlib.util.find_spec('yaml'):
            import yaml
            document = yaml.load(source, Loader=yaml.BaseLoader)
            self.assertIn('on', document)
            self.assertEqual(document['jobs']['build']['needs'], 'checks')
            rows = document['jobs']['build']['strategy']['matrix']['include']
            self.assertEqual([(r['version'], r['ndk_revision']) for r in rows],
                             [('16.7.19', '25.2.9519653'), ('17.25.2', '29.0.14206865')])
        for token in ('scripts/verify_source.py', 'scripts/apply_patches.py', 'scripts/collect_artifacts.py',
                      'scripts/build_module.py', '-Dserver=enabled', '-Dgadget=enabled',
                      '-Dfrida-core:compiler_backend=enabled', "go-version: '1.26.x'", 'if: always()',
                      'set -euo pipefail', '--feature zygisk-loader'):
            self.assertIn(token, source)
        for token in ('set +e', '--fuzz=5', 'patches/frida-core', 'head -1', 'sh.rustup.rs', '17.6.2'):
            self.assertNotIn(token, source)


if __name__ == '__main__':
    unittest.main()
