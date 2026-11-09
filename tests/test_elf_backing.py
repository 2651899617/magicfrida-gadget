#!/usr/bin/env python3
"""Pinned ELF parser backing and compiled ownership/error-path regression (no device)."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = 'subprojects/frida-gum/gum/gumelfmodule.c'
PINS = {
    '16.7.19': ('12b93b344b68b9f641f69252c1415d15543a9bdcdc557d094912dcb269b3983a',
                '007feadf0edb0152d9897ecca2028f6779ae38ced4ab70c976a920cfedc0ff01'),
    '17.25.2': ('5d49e38fa7831c62b6a7863f8aed429ec4483793da8f8f3ad374606bd4294a7c',
                '51bbaa3c900fb521cec2f6ba740f1af90e92dbdfbe8d4a1687e1caba059b6d03'),
}
module = importlib.util.spec_from_file_location('elf_backing_patches', ROOT / 'scripts/apply_patches.py')
patches = importlib.util.module_from_spec(module)
module.loader.exec_module(patches)


def profile(version):
    recipe = json.loads((ROOT / 'patches' / version / 'spec.json').read_text(encoding='utf-8'))
    entries = [entry for entry in recipe['files'] if entry['path'] == RELATIVE]
    if len(entries) != 1:
        raise AssertionError('expected exactly one guarded ELF backing entry')
    entry = entries[0]
    base = (ROOT / 'tests/fixtures' / version / RELATIVE).read_bytes()
    return recipe, entry, base, patches.transform(base, entry['edits']).decode('utf-8')


def function_body(text, signature):
    start = text.index(signature)
    start = text.index('\n{\n', start) + len('\n{\n')
    return text[start:text.index('\n}\n', start)]


# These are ownership-tracking GLib test doubles, not a full GLib/Android build.
# The disk IO is real; the code under test is extracted from each patched fixture.
HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef int gboolean;
typedef char gchar;
typedef size_t gsize;
typedef const void * gconstpointer;
typedef struct { char * message; } GError;
typedef struct { uintptr_t base_address; size_t size; } GumMemoryRange;
typedef struct { void * data; size_t size; unsigned refs; int owned; } GBytes;
typedef struct { GBytes * bytes; } GMappedFile;
typedef struct {
  GBytes * file_bytes;
  GBytes * source_blob;
  const char * source_path;
  int source_mode;
  uintptr_t base_address;
  GumMemoryRange file_mapped_range;
  const void * file_data;
  size_t file_size;
} GumElfModule;
#define TRUE 1
#define FALSE 0
#define GUM_ELF_SOURCE_MODE_ONLINE 1
#define GUM_ELF_SOURCE_MODE_OFFLINE 2
#define GUM_ERROR 1
#define GUM_ERROR_INVALID_ARGUMENT 2
#define GUM_ADDRESS(p) ((uintptr_t) (p))
#define GSIZE_TO_POINTER(n) ((void *) (uintptr_t) (n))
#define G_MAXSIZE SIZE_MAX
#define GUM_ALIGN_SIZE(n, a) (((n) + (a) - 1) & ~((a) - 1))
static int reads, maps, mapped_unref, cloak_adds, cloak_removes;
static int allocations, releases, byte_objects, live_errors, error_clears;
static int apk_result, parser_failure;
static unsigned char live_image[4096];
static const unsigned char payload[] = { 0x7f, 'E', 'L', 'F', 0, 0xff, 0x12, 0x80 };

GBytes * g_bytes_new_take (void * data, size_t size) {
  GBytes * result = malloc (sizeof (GBytes));
  assert (result != NULL);
  *result = (GBytes) { data, size, 1, 1 };
  byte_objects++;
  return result;
}
GBytes * g_bytes_new_static (const void * data, size_t size) {
  GBytes * result = g_bytes_new_take ((void *) data, size);
  result->owned = 0;
  return result;
}
GBytes * g_bytes_ref (GBytes * bytes) {
  assert (bytes != NULL);
  bytes->refs++;
  return bytes;
}
void g_bytes_unref (GBytes * bytes) {
  if (bytes == NULL) return;
  assert (bytes->refs != 0);
  if (--bytes->refs != 0) return;
  if (bytes->owned) { free (bytes->data); releases++; }
  free (bytes);
  byte_objects--;
}
const void * g_bytes_get_data (GBytes * bytes, size_t * size) {
  assert (bytes != NULL);
  *size = bytes->size;
  return bytes->data;
}
void g_set_error (GError ** error, int domain, int code, const char * format, ...) {
  va_list args;
  const char * message;
  (void) domain; (void) code;
  assert (strcmp (format, "%s") == 0 && *error == NULL);
  va_start (args, format); message = va_arg (args, const char *); va_end (args);
  *error = malloc (sizeof (GError));
  assert (*error != NULL);
  (*error)->message = malloc (strlen (message) + 1);
  assert ((*error)->message != NULL);
  strcpy ((*error)->message, message);
  live_errors++;
}
void g_clear_error (GError ** error) {
  if (*error == NULL) return;
  free ((*error)->message); free (*error); *error = NULL;
  live_errors--; error_clears++;
}
int read_file (const char * path, char ** contents, size_t * size, GError ** error) {
  FILE * file = fopen (path, "rb");
  long length;
  if (file == NULL) { g_set_error (error, 0, 0, "%s", "backing unavailable"); return FALSE; }
  assert (fseek (file, 0, SEEK_END) == 0);
  length = ftell (file); assert (length >= 0);
  rewind (file);
  *size = (size_t) length;
  *contents = malloc (*size + 1); assert (*contents != NULL);
  assert (fread (*contents, 1, *size, file) == *size);
  (*contents)[*size] = 0;
  assert (fclose (file) == 0);
  allocations++;
  return TRUE;
}
#ifdef HAVE_ANDROID
int g_file_get_contents (const char * path, char ** contents, size_t * size, GError ** error) {
  reads++;
  return read_file (path, contents, size, error);
}
#else
GMappedFile * g_mapped_file_new (const char * path, int writable, GError ** error) {
  char * data = NULL;
  size_t size;
  GMappedFile * file;
  maps++; assert (!writable);
  if (!read_file (path, &data, &size, error)) return NULL;
  file = malloc (sizeof (GMappedFile)); assert (file != NULL);
  file->bytes = g_bytes_new_take (data, size);
  return file;
}
GBytes * g_mapped_file_get_bytes (GMappedFile * file) { return g_bytes_ref (file->bytes); }
void g_mapped_file_unref (GMappedFile * file) {
  mapped_unref++; g_bytes_unref (file->bytes); free (file);
}
void gum_cloak_add_range (const GumMemoryRange * range) {
  assert (range->base_address != 0 && range->size % 4096 == 0); cloak_adds++;
}
#endif
size_t gum_query_page_size (void) { return 4096; }
void gum_cloak_remove_range (const GumMemoryRange * range) {
  assert (range->base_address != 0); cloak_removes++;
}
int gum_maybe_extract_from_apk (const char * path, GBytes ** bytes) {
  char * data;
  (void) path;
  if (!apk_result) return FALSE;
  data = malloc (sizeof (payload)); assert (data != NULL);
  memcpy (data, payload, sizeof (payload)); allocations++;
  *bytes = g_bytes_new_take (data, sizeof (payload));
  return TRUE;
}
void gum_elf_module_unload (GumElfModule * self) {
@UNLOAD@
}
int load_backing (GumElfModule * self, GError ** error) {
@LOAD@
  if (parser_failure) {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT, "%s", "parser failure");
    goto propagate_error;
  }
  assert (local_error == NULL);
  return TRUE;
@ERRORS@
}
void assert_balanced (void) {
  assert (allocations == releases && byte_objects == 0 && live_errors == 0);
  assert (cloak_adds == cloak_removes);
}
void test_success (const char * path, int mode, size_t size) {
  GumElfModule self = { 0 };
  GError * error = NULL;
  int old_releases = releases, old_reads = reads, old_maps = maps;
  int old_unrefs = mapped_unref, old_cloaks = cloak_adds;
  const void * data;
  self.source_path = path; self.source_mode = mode;
  self.base_address = GUM_ADDRESS (live_image);
  assert (load_backing (&self, &error) && error == NULL);
  data = self.file_data;
  assert (data != live_image && self.file_size == size);
  assert (size == 0 || memcmp (data, payload, size) == 0);
  assert (releases == old_releases);
#ifdef HAVE_ANDROID
  assert (reads == old_reads + 1 && maps == old_maps);
  assert (mapped_unref == old_unrefs && cloak_adds == old_cloaks);
  assert (self.file_mapped_range.base_address == 0 && self.file_mapped_range.size == 0);
#else
  assert (reads == old_reads && maps == old_maps + 1);
  assert (mapped_unref == old_unrefs + 1 && cloak_adds == old_cloaks + 1);
  assert (self.file_mapped_range.base_address == GUM_ADDRESS (data));
  assert (self.file_mapped_range.size == GUM_ALIGN_SIZE (size, 4096));
#endif
  assert (load_backing (&self, &error) && self.file_data == data);
  assert (releases == old_releases);
  gum_elf_module_unload (&self);
  assert (releases == old_releases + 1 && self.file_bytes == NULL && self.file_data == NULL);
  assert (self.file_size == 0 && self.file_mapped_range.base_address == 0);
  assert_balanced ();
}
void test_missing (const char * path, int mode) {
  GumElfModule self = { 0 };
  GError * error = NULL;
  int old_releases = releases, old_clears = error_clears;
  self.source_path = path; self.source_mode = mode;
  self.base_address = GUM_ADDRESS (live_image);
  if (mode == GUM_ELF_SOURCE_MODE_OFFLINE) {
    assert (!load_backing (&self, &error));
    assert (error != NULL && strcmp (error->message, "backing unavailable") == 0);
    assert (self.file_bytes == NULL && self.file_data == NULL);
    assert (live_errors == 1 && error_clears == old_clears + 1);
    g_clear_error (&error);
  } else {
    assert (load_backing (&self, &error) && error == NULL);
    assert (live_errors == 0 && error_clears == old_clears + 1);
    assert (self.file_data == live_image && self.file_size == SIZE_MAX - self.base_address);
    gum_elf_module_unload (&self);
  }
  assert (releases == old_releases);
  assert_balanced ();
}
void test_bypass (const char * path, int kind) {
  GumElfModule self = { 0 };
  GError * error = NULL;
  GBytes * blob = NULL;
  int old_reads = reads, old_maps = maps;
  self.source_path = path; self.source_mode = GUM_ELF_SOURCE_MODE_ONLINE;
  self.base_address = GUM_ADDRESS (live_image);
  if (kind == 0) {
    char * data = malloc (sizeof (payload)); assert (data != NULL);
    memcpy (data, payload, sizeof (payload)); allocations++;
    blob = g_bytes_new_take (data, sizeof (payload)); self.source_blob = blob;
  } else if (kind == 1) {
    self.source_path = "linux-vdso.so.1";
  } else {
    apk_result = TRUE;
  }
  assert (load_backing (&self, &error) && error == NULL);
  assert (reads == old_reads && maps == old_maps);
  if (kind == 0) assert (self.file_bytes == blob && blob->refs == 2);
  if (kind == 1) assert (self.file_data == live_image && self.file_size == 4096);
  gum_elf_module_unload (&self);
  if (blob != NULL) { assert (blob->refs == 1); g_bytes_unref (blob); }
  apk_result = FALSE;
  assert_balanced ();
}
int main (int argc, char ** argv) {
  int mode;
  assert (argc == 4);
  for (mode = GUM_ELF_SOURCE_MODE_ONLINE; mode <= GUM_ELF_SOURCE_MODE_OFFLINE; mode++) {
    GumElfModule a = { 0 }, b = { 0 };
    GError * error = NULL;
    int old_releases;
    test_success (argv[1], mode, sizeof (payload));
    test_success (argv[2], mode, 0);
    test_missing (argv[3], mode);
    /* Two cached parser backings own independent persistent copies. */
    a.source_path = b.source_path = argv[1]; a.source_mode = b.source_mode = mode;
    a.base_address = b.base_address = GUM_ADDRESS (live_image);
    assert (load_backing (&a, &error) && load_backing (&b, &error));
    assert (a.file_data != b.file_data);
    old_releases = releases;
    gum_elf_module_unload (&a);
    assert (releases == old_releases + 1 && memcmp (b.file_data, payload, sizeof (payload)) == 0);
    gum_elf_module_unload (&b); assert_balanced ();
    parser_failure = TRUE;
    a.source_path = argv[1]; a.source_mode = mode;
    assert (!load_backing (&a, &error) && error != NULL);
    assert (strcmp (error->message, "parser failure") == 0 && a.file_bytes == NULL);
    g_clear_error (&error); parser_failure = FALSE; assert_balanced ();
  }
  for (mode = 0; mode < 3; mode++) test_bypass (argv[3], mode);
  puts ("PASS backing success/errors/cache/lifetime/blob/vdso/APK; GLib ownership doubles");
  return 0;
}
'''


class ElfBackingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='elf-backing-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def test_pinned_profile_sha_and_exact_scope(self):
        generator_spec = importlib.util.spec_from_file_location(
            'elf_backing_generator', ROOT / 'scripts/generate_pinned_specs.py')
        generator = importlib.util.module_from_spec(generator_spec)
        generator_spec.loader.exec_module(generator)
        for version, (upstream_sha, candidate_sha) in PINS.items():
            with self.subTest(version=version):
                recipe, entry, base, actual = profile(version)
                self.assertEqual(hashlib.sha256(base).hexdigest(), upstream_sha)
                self.assertEqual(entry['upstream_sha256'], upstream_sha)
                self.assertEqual(generator.EXTRA_GUM_FILES[version]['gum/gumelfmodule.c'], upstream_sha)
                self.assertEqual(hashlib.sha256(actual.encode()).hexdigest(), candidate_sha)
                self.assertEqual(entry['optional'], {})
                self.assertEqual(len(entry['edits']), 1)
                edit = entry['edits'][0]
                self.assertEqual(edit['count'], 1)
                self.assertEqual(actual.replace(edit['new'], edit['old']), base.decode())
                self.assertEqual(patches.profile_bytes(base, entry, recipe['features']), actual.encode())
                self.assertEqual(function_body(actual, 'gum_elf_module_unload (GumElfModule * self)\n{'),
                                 function_body(base.decode(), 'gum_elf_module_unload (GumElfModule * self)\n{'))

    def test_android_all_disk_backing_and_nonandroid_mapping(self):
        for version in PINS:
            with self.subTest(version=version):
                _, entry, _, actual = profile(version)
                new = entry['edits'][0]['new']
                android, rest = new.split('#else\n')
                nonandroid, fallback = rest.split('#endif\n')
                self.assertTrue(android.startswith('#ifdef HAVE_ANDROID\n'))
                self.assertIn('g_file_get_contents (self->source_path, &contents, &size, &local_error)', android)
                self.assertIn('self->file_bytes = g_bytes_new_take (contents, size);', android)
                for forbidden in ('g_mapped_file_', 'gum_cloak_', 'file_mapped_range',
                                  'GUM_ELF_SOURCE_MODE_', 'g_free (contents)'):
                    self.assertNotIn(forbidden, android)
                old_mapping = entry['edits'][0]['old'].split('      else\n')[0]
                self.assertEqual(nonandroid, old_mapping)
                self.assertIn('if (self->file_bytes == NULL)', fallback)
                self.assertLess(fallback.index('goto unable_to_open;'), fallback.index('g_clear_error (&local_error);'))
                self.assertLess(fallback.index('g_clear_error (&local_error);'), fallback.index('g_bytes_new_static'))
                load = function_body(actual, 'gum_elf_module_load (GumElfModule * self,')
                self.assertLess(load.index('self->source_blob != NULL'), load.index('#ifdef HAVE_ANDROID'))
                self.assertLess(load.index('"linux-vdso.so.1"'), load.index('#ifdef HAVE_ANDROID'))
                self.assertLess(load.index('gum_maybe_extract_from_apk'), load.index('#ifdef HAVE_ANDROID'))
                self.assertIn('self->file_data = g_bytes_get_data (self->file_bytes, &self->file_size);', load)

    def test_generation_preserves_all_outputs_and_order(self):
        output = self.directory / 'generated'
        result = subprocess.run([sys.executable, '-X', 'utf8', '-I', '-B', str(ROOT / 'scripts/generate_pinned_specs.py'),
                                 '--output', str(output)], cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for version in PINS:
            recipe, _, _, _ = profile(version)
            expected = {'spec.json', 'compatible.patch', *(feature + '.patch' for feature in recipe['features'])}
            directory = output / 'patches' / version
            self.assertEqual({path.name for path in directory.iterdir()}, expected)
            for name in expected:
                self.assertEqual((directory / name).read_bytes(), (ROOT / 'patches' / version / name).read_bytes())
            generated = json.loads((directory / 'spec.json').read_text())
            self.assertEqual([entry['path'] for entry in generated['files']], [entry['path'] for entry in recipe['files']])
            for entry in recipe['files']:
                self.assertEqual((output / 'tests/fixtures' / version / entry['path']).read_bytes(),
                                 (ROOT / 'tests/fixtures' / version / entry['path']).read_bytes())
        again = subprocess.run([sys.executable, '-X', 'utf8', '-I', '-B', str(ROOT / 'scripts/generate_pinned_specs.py'),
                                '--output', str(output)], cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn('generation output must not exist', again.stderr)

    def test_missing_or_drifted_elf_backing_fails_before_any_write(self):
        for version in PINS:
            for failure in ('missing', 'drift'):
                with self.subTest(version=version, failure=failure):
                    source = self.directory / (version + '-' + failure)
                    shutil.copytree(ROOT / 'tests/fixtures' / version, source)
                    target = source / RELATIVE
                    if failure == 'missing':
                        target.unlink()
                    else:
                        target.write_bytes(target.read_bytes() + b'\n/* drift */\n')
                    before = {path.relative_to(source): path.read_bytes() for path in source.rglob('*') if path.is_file()}
                    with self.assertRaisesRegex(ValueError, 'required regular source file missing|source drift'):
                        patches.apply(source, version, self.directory / 'report.json')
                    self.assertEqual(before, {path.relative_to(source): path.read_bytes() for path in source.rglob('*') if path.is_file()})
                    self.assertFalse((self.directory / 'report.json').exists())

    def test_compiled_actual_backing_and_cleanup_both_platform_branches(self):
        compiler = os.environ.get('ELF_BACKING_CC') or os.environ.get('STRING_OUTLINE_CC')
        compiler = compiler or next((shutil.which(name) for name in ('gcc', 'clang', 'cc') if shutil.which(name)), None)
        if not compiler:
            if os.environ.get('STRING_OUTLINE_REQUIRE_HOST') == '1':
                self.fail('host C compiler required; select ELF_BACKING_CC or STRING_OUTLINE_CC')
            self.skipTest('host C compiler unavailable; select ELF_BACKING_CC')
        payload = self.directory / 'payload.bin'
        payload.write_bytes(b'\x7fELF\x00\xff\x12\x80')
        empty = self.directory / 'empty.bin'
        empty.write_bytes(b'')
        missing = self.directory / 'missing.bin'
        for version in PINS:
            _, _, _, actual = profile(version)
            load = function_body(actual, 'gum_elf_module_load (GumElfModule * self,')
            end = load.index('\n\n  if (!gum_elf_module_load_elf_header')
            errors = load[load.index('unable_to_open:'):]
            unload = function_body(actual, 'gum_elf_module_unload (GumElfModule * self)\n{')
            cleanup = unload[unload.index('  if (self->file_mapped_range.base_address != 0'):]
            program = HARNESS.replace('@LOAD@', load[:end]).replace('@ERRORS@', errors).replace('@UNLOAD@', cleanup)
            source = self.directory / ('harness-' + version + '.c')
            source.write_text(program, encoding='utf-8', newline='\n')
            for android in (True, False):
                with self.subTest(version=version, android=android):
                    binary = self.directory / ('harness-' + version + ('-android' if android else '-other') + '.exe')
                    flags = ['-DHAVE_LINUX', *(['-DHAVE_ANDROID'] if android else [])]
                    command = [compiler, '-std=c99', '-Wall', '-Wextra', '-Werror', *flags, str(source), '-o', str(binary)]
                    built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
                    self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                    result = subprocess.run([str(binary), str(payload), str(empty), str(missing)], cwd=ROOT,
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('PASS backing success/errors/cache/lifetime/blob/vdso/APK', result.stdout)


if __name__ == '__main__':
    unittest.main()
