#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('module_builder', ROOT / 'scripts/build_module.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ModuleTests(unittest.TestCase):
    def test_default_has_no_active_targets(self):
        lines = (ROOT / 'module/targets.conf').read_text(encoding='utf-8').splitlines()
        self.assertFalse([line for line in lines if line.strip() and not line.lstrip().startswith('#')])

    def test_public_header_is_unmodified(self):
        import hashlib
        data = (ROOT / 'module/include/zygisk.hpp').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         'f8d55e8b4f89d418c5941afe62ce6a09ddec1f4afd9a1b0a01eb40a93310dd28')
        self.assertIn(b'Permission to use, copy, modify', data)

    def test_loader_source_safety_contract(self):
        # Static contract only; native/device FD and thread behavior are not proven here.
        text = (ROOT / 'module/src/module.cpp').read_text(encoding='utf-8')
        worker = text[text.index('static void *load_gadget'):text.index('class NianchuModule')]
        self.assertNotIn('api->', worker)
        self.assertNotIn('env->', worker)
        self.assertLess(worker.index('android_dlopen_ext('), worker.index('init(config,'))
        self.assertIn('if (!verify_payload(fd))', worker)
        self.assertIn('api->exemptFd(fd)', text)
        self.assertNotIn('dlclose(', text)
        self.assertNotIn('connectCompanion(', text)
        self.assertNotIn('load_gadget(context)', text)
        self.assertIn('PTHREAD_CREATE_DETACHED', text)
        self.assertIn('preServerSpecialize(zygisk::ServerSpecializeArgs *) override { decline(); }', text)

    def test_no_device_scripts_or_operations(self):
        self.assertFalse((ROOT / 'module/service.sh').exists())
        self.assertFalse((ROOT / 'module/post-fs-data.sh').exists())
        text = (ROOT / 'module/customize.sh').read_text(encoding='utf-8')
        for token in ('resetprop ', 'setenforce ', 'pm install', 'adb '):
            self.assertNotIn(token, text)
        import re
        self.assertNotRegex(text, r'(?m)^\s*reboot(?:\s|$)')

    def test_missing_manifest_cannot_package(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                builder.payload_from_manifest(Path(directory) / 'missing.json')

    def test_existing_build_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            with self.assertRaisesRegex(ValueError, 'must not exist'):
                builder.build(out / 'absent-ndk', out)

    def test_native_real_policy_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            executable = out / ('policy.exe' if os.name == 'nt' else 'policy')
            compiler = shutil.which('g++') or shutil.which('clang++')
            if compiler:
                command = [compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror',
                           '-I' + str(ROOT / 'module/src'), str(ROOT / 'module/tests/test_policy.cpp'),
                           '-o', str(executable)]
            else:
                vswhere = Path('C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe')
                self.assertTrue(vswhere.is_file(), 'native compiler unavailable')
                result = subprocess.run([str(vswhere), '-all', '-products', '*', '-find',
                                         'VC/Auxiliary/Build/vcvars64.bat'], capture_output=True,
                                        text=True, encoding='utf-8')
                self.assertEqual(result.returncode, 0, result.stderr)
                candidates = [Path(x) for x in result.stdout.splitlines() if Path(x).is_file()]
                self.assertTrue(candidates, 'native C++ compiler unavailable')
                script = out / 'build.cmd'
                script.write_text('@call "' + str(candidates[0]) + '" >nul\n'
                                  '@if errorlevel 1 exit /b 1\n'
                                  '@cl /nologo /std:c++17 /EHsc /W4 /WX /I"' + str(ROOT / 'module/src') +
                                  '" /Fo"' + str(out / 'policy.obj') + '" /Fe"' + str(executable) +
                                  '" "' + str(ROOT / 'module/tests/test_policy.cpp') + '"\n'
                                  '@exit /b %errorlevel%\n', encoding='mbcs')
                command = ['cmd.exe', '/d', '/c', str(script)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS module native policy/hash:', result.stdout)
            print(result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
