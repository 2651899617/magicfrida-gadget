#!/usr/bin/env python3
"""Source AST tests plus native host compiled behavior, not binary patch tests.

CI: install the three PARSER_PINS and run unittest discovery.  GCC/Clang host
execution is required when STRING_OUTLINE_REQUIRE_HOST=1.  Optional
STRING_OUTLINE_CC and STRING_OUTLINE_CXX select already installed compilers.
STRING_OUTLINE_ANDROID_CLANG selects an installed NDK clang for actual Bionic
C/C++ preprocessing and cross-compilation (required with REQUIRE_ANDROID=1).
"""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'outline_elf_strings.py'
spec = importlib.util.spec_from_file_location('string_outline', SCRIPT)
outline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(outline)

GLIB_HOST = r'''
typedef unsigned long gsize;
extern void *malloc(gsize);
extern void abort(void);
extern int strcmp(const char *, const char *);
extern int memcmp(const void *, const void *, gsize);
extern int snprintf(char *, gsize, const char *, ...);
static volatile unsigned long allocations;
static void *g_malloc(gsize n) {
  void *p = malloc(n);
  if (p == 0) abort();
  __atomic_add_fetch(&allocations, 1UL, 0);
  return p;
}
static int g_once_init_enter(volatile gsize *p) {
  gsize expected = 0;
  if (__atomic_compare_exchange_n(p, &expected, 2UL, 0,
      4, 2)) return 1;
  while (__atomic_load_n(p, 2) == 2UL) { }
  return 0;
}
static void g_once_init_leave(volatile gsize *p, gsize value) {
  __atomic_store_n(p, value, 3);
}
static void require(int ok) { if (!ok) abort(); }
'''


def c_string(value):
    if isinstance(value, str):
        value = value.encode()
    return '"' + ''.join('\\%03o' % byte for byte in value) + '"'


def compiler(language):
    env_name = 'STRING_OUTLINE_CXX' if language == 'cpp' else 'STRING_OUTLINE_CC'
    explicit = os.environ.get(env_name)
    if explicit:
        return explicit
    names = ('g++', 'clang++') if language == 'cpp' else ('gcc', 'clang', 'cc')
    return next((shutil.which(name) for name in names if shutil.which(name)), None)


class OutlineTests(unittest.TestCase):
    def transform(self, source, language='c'):
        return outline.outline_source(source, language)

    def compile_run(self, source, language='c', extra_flags=(), execute=True, input_language=None):
        cc = compiler(language)
        if cc is None:
            if os.environ.get('STRING_OUTLINE_REQUIRE_HOST') == '1':
                self.fail('native host compiler required; set STRING_OUTLINE_CC/CXX')
            self.skipTest('no native host C/C++ compiler available')
        if isinstance(source, str):
            source = source.encode()
        env = dict(os.environ)
        env['PATH'] = str(Path(cc).resolve().parent) + os.pathsep + env.get('PATH', '')
        with tempfile.TemporaryDirectory(prefix='nso-host-') as directory:
            root = Path(directory)
            unit = root / ('unit.ii' if language == 'cpp' else 'unit.i')
            binary = root / ('unit.exe' if os.name == 'nt' else 'unit')
            unit.write_bytes(source)
            args = [cc, '-std=gnu++11' if language == 'cpp' else '-std=gnu11',
                    '-x', input_language or ('c++-cpp-output' if language == 'cpp' else 'cpp-output'),
                    '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    str(unit), '-o', str(binary), *extra_flags]
            built = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr.decode(errors='replace'))
            if execute:
                result = subprocess.run([str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                return result.stdout
            return binary.read_bytes()

    def test_dynamic_original_bytes_and_determinism(self):
        source = GLIB_HOST + '\nconst char *name(void) { return "Frida:rpc"; }\n'
        expected = c_string('Frida:rpc')
        source += 'int main(void) { require(strcmp(name(), %s) == 0); require(name()==name()); return 0; }' % expected
        output, report = self.transform(source)
        self.assertTrue(report['ok'])
        self.assertNotIn(b'"Frida:rpc"', output)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 2)
        self.assertEqual(output, self.transform(source)[0])
        self.assertNotIn(b'#include', output)
        self.assertIn(b'const volatile unsigned char * s', output)
        self.compile_run(output)

    def test_file_enum_dbus_and_public_lookup_roundtrip(self):
        source = GLIB_HOST + r'''
typedef struct { int value; const char *value_name; const char *value_nick; } GEnumValue;
typedef struct { int ref_count; const char *key; const char *value; } Annotation;
typedef struct { int ref_count; const char *name; Annotation **annotations; } Interface;
static const GEnumValue values[] = {
  { 1, "FridaStopReason", "frida-stop-reason" }, {0, 0, 0}
};
static const Annotation annotation = { -1, "re.frida.Annotation", "frida:rpc" };
static Annotation *annotation_list[] = { (Annotation *) &annotation, 0 };
static const Interface iface = { -1, "re.frida.AgentSession", annotation_list };
static const char *const public_keys[] = { "frida:rpc", "re.frida.AgentSession" };
static const char *lookup(const char *name) {
  int i;
  for (i=0; i!=2; ++i) if (strcmp(public_keys[i],name)==0) return public_keys[i];
  return 0;
}
'''
        source += '''int main(void) {
 require(values[0].value == 1 && values[1].value_name == 0);
 require(strcmp(values[0].value_name, %s)==0);
 require(strcmp(values[0].value_nick, %s)==0);
 require(strcmp(iface.name, %s)==0);
 require(strcmp(iface.annotations[0]->key, %s)==0);
 require(strcmp(iface.annotations[0]->value, %s)==0);
 require(lookup(%s) == public_keys[0]);
 require(lookup(%s) == public_keys[1]);
 require(sizeof(values) == 2*sizeof(GEnumValue));
 return 0;
}''' % tuple(c_string(x) for x in ('FridaStopReason', 'frida-stop-reason', 're.frida.AgentSession',
                                        're.frida.Annotation', 'frida:rpc', 'frida:rpc', 're.frida.AgentSession'))
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['static_objects'], 4)
        self.assertEqual(report['summary']['expected_pointer_patches'], 7)
        self.assertTrue(all(obj['const_storage_removed'] for obj in report['static_objects']))
        self.assertIn('[0].value_name', str(report['static_objects']))
        self.assertNotIn(b'"re.frida.AgentSession"', output)
        self.compile_run(output)

    def test_function_local_enum_and_safe_vala_goto(self):
        source = GLIB_HOST + r'''
typedef struct { int value; const char *value_name; const char *value_nick; } GEnumValue;
const GEnumValue *local_values(int n) {
  static const GEnumValue values[]={{1,"FridaLocalValue","frida-local-value"},{0,0,0}};
  const GEnumValue *result = values;
  if (n) goto out;
  result = values;
out:
  return result;
}
'''
        source += '''int main(void) {
 const GEnumValue *p = local_values(1);
 unsigned long before = allocations;
 require(strcmp(p[0].value_name, %s)==0);
 require(strcmp(p[0].value_nick, %s)==0);
 require(local_values(0) == p);
 require(allocations == before);
 return 0;
}''' % (c_string('FridaLocalValue'), c_string('frida-local-value'))
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['static_objects'][0]['initialization'], 'declaration-following-g_once')
        self.assertIn(b'static volatile gsize', output)
        self.compile_run(output)

    def test_designated_nested_fields_do_not_scan_object_bytes(self):
        source = GLIB_HOST + r'''
typedef struct { const char *key; char inline_name[8]; } Inner;
typedef struct { int number; Inner inner; const char *name; } Outer;
static const Outer objects[3] = {
 [1] = { .number=42, .inner={ .key="FridaNested", .inline_name="safe" }, .name="re.frida.Outer" },
 [2].name = "frida:rpc"
};
'''
        source += '''int main(void) {
 require(objects[1].number==42 && objects[0].name==0);
 require(strcmp(objects[1].inner.inline_name,"safe")==0);
 require(strcmp(objects[1].inner.key,%s)==0);
 require(strcmp(objects[1].name,%s)==0);
 require(strcmp(objects[2].name,%s)==0);
 return 0;
}''' % tuple(c_string(x) for x in ('FridaNested', 're.frida.Outer', 'frida:rpc'))
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['static_objects'][0]['paths'], ['[1].inner.key', '[1].name', '[2].name'])
        self.assertNotIn(b'memcpy', output)
        self.compile_run(output)

    def test_task_diagnostic_keeps_function_source_tag_and_nonliteral_args(self):
        source = GLIB_HOST + r'''
static const char *task_name;
static const void *source_tag;
static int order;
static int next_arg(void) { return ++order; }
static void g_task_set_name(void *task, const char *name) { (void)task; task_name=name; }
static void g_task_set_source_tag(void *task, const void *tag) { (void)task; source_tag=tag; }
static void frida_agent_operation(void) {
 g_task_set_name(0, "FridaAgentOperation");
 g_task_set_source_tag(0, (const void *)frida_agent_operation);
}
static void format_runtime(char *dst, const char *fmt, const char *text, int value) {
 snprintf(dst,128,fmt,text,value);
}
'''
        source += '''int main(void) {
 char buffer[128]; const char *nonliteral_format="%%s/%%d";
 frida_agent_operation();
 require(source_tag==(const void *)frida_agent_operation);
 require(strcmp(task_name,%s)==0);
 format_runtime(buffer, nonliteral_format, "FridaArgument", next_arg());
 require(order==1);
 require(strcmp(buffer,%s)==0);
 return 0;
}''' % (c_string('FridaAgentOperation'), c_string('FridaArgument/1'))
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertIn(b'g_task_set_source_tag(0, (const void *)frida_agent_operation)', output)
        self.assertIn(b'format_runtime(buffer, nonliteral_format,', output)
        self.compile_run(output)

    def test_exact_numeric_resources_metadata_and_runtime_identifier(self):
        original = bytes([0, 255, 70, 114, 105, 100, 97, 0, 7, 8])
        source = GLIB_HOST + r'''
typedef struct { const char *name; const unsigned char *bytecode; gsize size; const char *source_map; } Module;
static const unsigned char gumjs_test_bytecode[12] = {0,255,70,114,105,100,97,0,7,8};
static const char gumjs_test_source_map[] = {123,34,102,114,105,100,97,34,125,0};
static const unsigned char untouched_sdk[] = {70,114,105,100,97,0};
static const Module modules[]={{"frida-runtime",gumjs_test_bytecode,sizeof(gumjs_test_bytecode),gumjs_test_source_map}};
static const unsigned char *resource(void) { return gumjs_test_bytecode; }
'''
        source += '''int main(void) {
 const unsigned char expected[12] = {0,255,70,114,105,100,97,0,7,8,0,0};
 require(sizeof(gumjs_test_bytecode)==12);
 require(sizeof(gumjs_test_source_map)==10);
 require(modules[0].size==12);
 require(modules[0].bytecode==resource());
 require(memcmp(resource(),expected,12)==0);
 require(resource()[1]==255 && gumjs_test_bytecode[2]==70);
 require(memcmp(modules[0].source_map,%s,10)==0);
 require(untouched_sdk[0]==70 && untouched_sdk[4]==97);
 return 0;
}''' % c_string(b'{"frida"}\0')
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['resources_transformed'], 2)
        self.assertIn(b'sizeof(gumjs_test_bytecode)', output)
        self.assertIn(b'untouched_sdk[] = {70,114,105,100,97,0}', output)
        resource_entry = next(e for e in report['entries'] if e['placeholder'] == 'gumjs_test_bytecode')
        self.assertEqual(resource_entry['byte_length'], len(original) + 2)
        self.compile_run(output)

    def test_thread_cache_and_local_static_once(self):
        source = GLIB_HOST + r'''
extern int pthread_create(unsigned long *, const void *, void *(*)(void *), void *);
extern int pthread_join(unsigned long, void **);
typedef struct { int value; const char *value_name; const char *value_nick; } GEnumValue;
static const GEnumValue *shared_values(void) {
 static const GEnumValue table[]={{1,"FridaThreadValue","frida-thread-value"},{0,0,0}};
 return table;
}
static const char *shared_name(void) { return "FridaThreadName"; }
static const void *thread_pointers[8];
static void *worker(void *arg) {
 unsigned long index=(unsigned long)arg;
 unsigned int i;
 for(i=0;i!=10000;++i) {
   const GEnumValue *p=shared_values();
   require(strcmp(p[0].value_name, EXPECTED_VALUE)==0);
   require(strcmp(p[0].value_nick, EXPECTED_NICK)==0);
   require(strcmp(shared_name(), EXPECTED_NAME)==0);
 }
 thread_pointers[index]=shared_name();
 return 0;
}
int main(void) {
 unsigned long threads[8]; unsigned long i; unsigned long before=allocations;
 for(i=0;i!=8;++i) require(pthread_create(&threads[i],0,worker,(void *)i)==0);
 for(i=0;i!=8;++i) require(pthread_join(threads[i],0)==0);
 for(i=0;i!=8;++i) require(thread_pointers[i]==shared_name());
 require(allocations==before);
 return 0;
}
'''
        source = source.replace('EXPECTED_VALUE', c_string('FridaThreadValue')).replace('EXPECTED_NICK', c_string('frida-thread-value')).replace('EXPECTED_NAME', c_string('FridaThreadName'))
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['heap_buffers'], 3)
        self.compile_run(output, extra_flags=('-pthread',))

    def test_concatenated_escape_utf8_and_embedded_nul(self):
        source = GLIB_HOST + r'''
static const char *text(void) { return "Fri" "da\0\x7f\377\u4e2d"; }
'''
        expected = b'Frida\0\x7f\xff' + '中'.encode() + b'\0'
        source += 'int main(void) {require(memcmp(text(),%s,%d)==0);return 0;}' % (c_string(expected[:-1]), len(expected))
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['heap_buffers'], 1)
        self.compile_run(output)

    def test_unsupported_contexts_are_preserved_with_reasons(self):
        source = GLIB_HOST + r'''
static char inline_array[]="frida-array";
typedef struct { char inline_name[16]; const char *const pointer; } Bad;
static const Bad aggregate={"frida-inline","FridaConstMember"};
static const char *day="Friday";
_Static_assert(sizeof("frida")==6,"frida assertion");
static void use(void) { __asm__ volatile("frida asm"); }
'''
        output, report = self.transform(source)
        reasons = {item['reason'] for item in report['skipped']}
        self.assertIn('char_array_literal', reasons)
        self.assertIn('immutable_aggregate_member', reasons)
        self.assertIn('ordinary_friday', reasons)
        self.assertIn('sizeof_or_alignment_context', reasons)
        self.assertIn('compile_time_builtin_context', reasons)
        self.assertIn('assembly_context', reasons)
        self.assertEqual(output, source.encode())
        self.assertEqual(report['summary']['heap_buffers'], 0)

    def test_packed_union_and_typedef_const_skip(self):
        source = GLIB_HOST + r'''
struct __attribute__((packed)) Packed {const char *name;};
static const struct Packed packed={"frida-packed"};
union U { const char *name; unsigned long bits; };
static const union U u={"frida-union"};
typedef struct {const char *name;} S;
typedef const S CS;
static CS immutable={"FridaConstTypedef"};
'''
        output, report = self.transform(source)
        reasons = {item['reason'] for item in report['skipped']}
        self.assertIn('aggregate_attributes_or_packing', reasons)
        self.assertIn('union_or_class_layout', reasons)
        self.assertIn('typedef_const_storage', reasons)
        self.assertEqual(output, source.encode())

    def test_local_goto_that_bypasses_once_is_explicit_skip(self):
        source = GLIB_HOST + r'''
const char *name(int skip) {
 if(skip) goto use;
 static const char *name="FridaUnsafeGoto";
use:
 return name;
}
'''
        output, report = self.transform(source)
        self.assertEqual(report['skipped'][0]['reason'], 'local_static_goto_can_bypass_initialization')
        self.assertEqual(output, source.encode())

    def test_resource_unsupported_reference_does_not_partially_encode(self):
        source = GLIB_HOST + r'''
static const unsigned char gumjs_test_bytecode[]={70,114,105,100,97};
static const unsigned char (*all)[5]=&gumjs_test_bytecode;
'''
        output, report = self.transform(source)
        self.assertEqual(report['summary']['resources_transformed'], 0)
        self.assertEqual(report['skipped'][0]['reason'], 'address_of_resource_array')
        self.assertEqual(output, source.encode())

    def test_nonparse_preprocessor_and_missing_glib_fail_closed(self):
        for source, reason in [('int main( { "frida";', 'input_does_not_parse'),
                               ('#define NAME "frida"\n', 'input_not_fully_preprocessed'),
                               ('const char *f(void){return "frida";}', 'missing_existing_glib_declarations')]:
            with self.subTest(reason=reason), self.assertRaises(outline.OutlineError) as caught:
                self.transform(source)
            self.assertEqual(caught.exception.report['failures'][-1]['reason'], reason)
            self.assertFalse(caught.exception.report['ok'])

    def test_cli_report_paths_and_stale_output_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='nso-cli-') as directory:
            root = Path(directory)
            input_path, output_path, report_path = root/'input.i', root/'output.i', root/'report.json'
            input_path.write_text(GLIB_HOST + '\nconst char *name(void){return "frida:rpc";}\n', encoding='utf-8')
            command = [sys.executable, '-I', str(SCRIPT), '--input', str(input_path), '--output', str(output_path), '--report', str(report_path), '--language', 'c']
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue(json.loads(report_path.read_text(encoding='utf-8'))['ok'])
            input_path.write_text('void f( { "frida";', encoding='utf-8')
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output_path.exists())
            self.assertFalse(json.loads(report_path.read_text(encoding='utf-8'))['ok'])

    def test_preprocessed_line_markers_are_not_touched(self):
        source = '# 1 "frida-source.c"\n' + GLIB_HOST + '\nconst char *f(void){return "frida:rpc";}\n'
        output, report = self.transform(source)
        self.assertTrue(report['ok'])
        self.assertIn(b'# 1 "frida-source.c"', output)

    def test_cpp_pointer_api_static_tables_and_raw_literal(self):
        size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
        host = GLIB_HOST.replace('typedef unsigned long gsize;', 'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
        source = host + r'''
namespace api {
struct Value {int number; const char *name;};
static const Value values[]={{1,"FridaCppValue"}};
static const char *accept(const char *p) {return p;}
static const char *name(void) {return accept(R"tag(frida:rpc)tag");}
}
'''
        source += '''int main(void) {
 require(strcmp(api::values[0].name,%s)==0);
 require(strcmp(api::name(),%s)==0);
 return 0;
}''' % (c_string('FridaCppValue'), c_string('frida:rpc'))
        output, report = self.transform(source, 'cpp')
        self.assertEqual(report['skipped'], [])
        self.compile_run(output, 'cpp')

    def test_runtime_call_inside_scalar_or_pointer_initializer(self):
        source = GLIB_HOST + r'''
static const char *identity(const char *p) {return p;}
static int frida_check(void) {
 int result=strcmp("frida:rpc", EXPECTED);
 const char *name=identity("FridaInitializer");
 require(strcmp(name, EXPECTED_NAME)==0);
 return result;
}
int main(void) {require(frida_check()==0);return 0;}
'''
        source = source.replace('EXPECTED_NAME', c_string('FridaInitializer')).replace('EXPECTED', c_string('frida:rpc'))
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['heap_buffers'], 2)
        self.compile_run(output)

    def test_casted_static_initializer_and_byte_typedef_resource(self):
        source = GLIB_HOST + r'''
typedef unsigned char guint8;
typedef struct {const char *name; const guint8 *data;} Resource;
static const guint8 gumjs_cast_bytecode[]={0,70,114,105,100,97,255};
static const Resource metadata={(const char *)"frida:rpc",(const guint8 *)gumjs_cast_bytecode};
'''
        source += 'int main(void){require(strcmp(metadata.name,%s)==0);require(metadata.data[6]==255);require(metadata.data[1]==70);return 0;}' % c_string('frida:rpc')
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['expected_pointer_patches'], 2)
        self.assertEqual(report['summary']['resources_transformed'], 1)
        self.compile_run(output)

    def test_cpp_numeric_char_arrays_no_narrowing_and_byte_identity(self):
        size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
        host = GLIB_HOST.replace('typedef unsigned long gsize;', 'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
        source = host + r'''
struct Resource {const unsigned char *code; const char *map;};
static const unsigned char gumjs_cpp_bytecode[]={0,255,70,114,105,100,97};
static const char gumjs_cpp_source_map[]={123,34,102,114,105,100,97,34,125,0};
static const Resource metadata={gumjs_cpp_bytecode,gumjs_cpp_source_map};
'''
        source += 'int main(void){require(metadata.code[1]==255);require(memcmp(metadata.map,%s,10)==0);require(gumjs_cpp_bytecode[2]==70);return 0;}' % c_string(b'{"frida"}\0')
        output, report = self.transform(source, 'cpp')
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['resources_transformed'], 2)
        self.compile_run(output, 'cpp')

    def test_qualified_cpp_resource_reference_fails_closed(self):
        source = GLIB_HOST + 'namespace n {static const unsigned char gumjs_cpp_bytecode[]={70,114,105,100,97};}\nconst unsigned char *f(void){return n::gumjs_cpp_bytecode;}\n'
        output, report = self.transform(source, 'cpp')
        self.assertEqual(output, source.encode())
        self.assertEqual(report['summary']['unsupported_resource_total'], 1)
        self.assertEqual(report['skipped'][0]['reason'], 'qualified_resource_reference')

    def test_array_bound_marker_is_not_retyped_to_pointer(self):
        source = GLIB_HOST + 'void f(void){static int a[(int)"frida"];(void)a;}\n'
        output, report = self.transform(source)
        self.assertEqual(output, source.encode())
        self.assertEqual(report['skipped'][0]['reason'], 'array_bound_compile_time_context')

    def test_compiler_function_names_original_diagnostic_and_source_pointer(self):
        source = GLIB_HOST + r'''
static const void *tag;
static const char *frida_function_name(void) {
 tag=(const void *)frida_function_name;
 require(strcmp(__func__,__FUNCTION__)==0);
 return __func__;
}
'''
        source += 'int main(void) {require(strcmp(frida_function_name(),%s)==0);require(tag==(const void *)frida_function_name);return 0;}' % c_string('frida_function_name')
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertNotIn(b'__func__', output)
        self.assertNotIn(b'__FUNCTION__', output)
        self.assertIn(b'tag=(const void *)frida_function_name;', output)
        self.compile_run(output)

    def test_cpp_pretty_function_is_not_guessed(self):
        source = GLIB_HOST + 'const char *frida_function(void){return __PRETTY_FUNCTION__;}\n'
        output, report = self.transform(source, 'cpp')
        self.assertEqual(output, source.encode())
        self.assertEqual(report['skipped'][0]['reason'], 'compiler_specific_function_name')
        self.assertEqual(report['summary']['unsupported_marker_total'], 1)

    def test_cpp_constexpr_array_reference_deduced_return_skip(self):
        source = GLIB_HOST + r'''
static constexpr const char *key="frida:rpc";
static constexpr char array[]="FridaArray";
template<unsigned long N> int size(const char (&a)[N]) {return N+(a[0]==0);}
static int consume(const char (&a)[6]) {return a[0];}
static int f(void) {return consume("frida");}
static auto inferred(void) {return "FridaInferred";}
'''
        output, report = self.transform(source, 'cpp')
        reasons = {item['reason'] for item in report['skipped']}
        self.assertIn('constexpr_or_constinit_context', reasons)
        self.assertIn('cpp_nonpointer_call_parameter', reasons)
        self.assertIn('cpp_nonpointer_or_deduced_return', reasons)
        self.assertEqual(output, source.encode())
    def test_compiler_shadow_offsets_and_original_semantic_tokens(self):
        extensions = r'''
typedef __signed__ char AndroidSignedByte;
typedef __signed__ int AndroidSignedInt;
typedef __signed__ __int128 AndroidSigned128;
const char * _Nullable android_api(const void * _Nonnull);
enum E { OLD __attribute__((__deprecated__("frida annotation"))) = 1, NEW = 2 };
extern int renamed(void) __asm__("frida_linker_name");
'''
        for language in ('c', 'cpp'):
            with self.subTest(language=language):
                source = (extensions + GLIB_HOST + r'''
static const char *name(void) { return "FridaParserOffset"; }
''').encode()
                transformer = outline.Transformer(source, language, 'android.i')
                self.assertEqual(len(transformer.shadow.view), len(source))
                self.assertEqual([i for i, c in enumerate(source) if c in (10, 13)],
                                 [i for i, c in enumerate(transformer.shadow.view) if c in (10, 13)])
                self.assertFalse(transformer.root.has_error)
                output, report = transformer.run()
                self.assertIn(extensions.encode(), output)
                occurrence = next(o for o in report['occurrences'] if o['kind'] == 'string')
                self.assertEqual(source[occurrence['start_byte']:occurrence['end_byte']], b'"FridaParserOffset"')
                self.assertEqual({s['reason'] for s in report['skipped']}, {'attribute_context', 'assembly_context'})
                self.assertTrue(report['parser_normalization']['byte_offsets_preserved'])
                self.assertEqual(report['parser_normalization']['kind_counts']['nullability'], 2)

    def test_shadow_lexer_does_not_touch_comments_literals_or_directives(self):
        source = r'''# 1 "__signed__ _Nullable frida-file.c"
/* __attribute__((packed)) _Nullable typeof(invalid +) */
const char *spelling = "__signed__ _Nullable __attribute__((packed))";
char token = '_';
const char *raw = R"tag(__signed__ _Nullable __attribute__((packed)) typeof(invalid +))tag";
'''.encode()
        transformer = outline.Transformer(source, 'cpp', 'tokens.ii')
        self.assertFalse(transformer.root.has_error)
        self.assertEqual(transformer.shadow.view, source)
        self.assertEqual(transformer.shadow.regions, [])
        output, report = transformer.run()
        self.assertEqual(output, source)
        self.assertTrue(report['ok'])

    def test_masked_attribute_type_static_resource_and_cleanup_safety(self):
        source = GLIB_HOST + r'''
typedef char AttributedByte __attribute__((may_alias));
struct __attribute__((packed)) Packed { const char *name; };
struct Suffix { const char *name; } __attribute__((packed));
static const struct Packed packed={"frida-packed"};
static const struct Suffix suffix={"frida-suffix-packed"};
__attribute__((section("custom"))) static const char *sectioned="frida-section";
static AttributedByte *attributed="frida-typedef";
static const unsigned char gumjs_annotated_bytecode[] __attribute__((aligned(16)))={70,114,105,100,97};
void clear(char **p) {(void)p;}
void f(void) {
  char *p __attribute__((cleanup(clear)))="FridaCleanup";
  (void)p;
}
'''
        output, report = self.transform(source)
        self.assertEqual(output, source.encode())
        self.assertEqual(report['summary']['heap_buffers'], 0)
        reasons = {s['reason'] for s in report['skipped']}
        self.assertIn('aggregate_attributes_or_packing', reasons)
        self.assertIn('static_storage_attributes', reasons)
        self.assertIn('type_or_field_attributes', reasons)
        self.assertIn('declaration_attributes', reasons)
        self.assertIn('resource_storage_attributes', reasons)

    def test_neon_typedef_shadow_preserves_attribute_bytes_and_offsets(self):
        source = r'''
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef int int32_t;
typedef unsigned char poly8_t;
typedef unsigned short poly16_t;
typedef __attribute__((neon_vector_type(8))) int8_t int8x8_t;
typedef __attribute__((__neon_vector_type__(16))) uint8_t uint8x16_t;
typedef __attribute__((neon_vector_type(4))) int16_t int16x4_t;
typedef __attribute__((neon_vector_type(2))) int32_t int32x2_t;
typedef __attribute__((neon_polyvector_type(8))) poly8_t poly8x8_t;
typedef __attribute__((__neon_polyvector_type__(4))) poly16_t poly16x4_t;
'''.replace('\n', '\r\n').encode()
        for language in ('c', 'cpp'):
            with self.subTest(language=language):
                transformer = outline.Transformer(source, language, 'neon.i')
                self.assertEqual(len(transformer.shadow.view), len(source))
                self.assertEqual([i for i, c in enumerate(source) if c in (10, 13)],
                                 [i for i, c in enumerate(transformer.shadow.view) if c in (10, 13)])
                self.assertFalse(transformer.root.has_error)
                output, report = transformer.run()
                self.assertEqual(output, source)
                self.assertEqual(report['parser_normalization']['kind_counts']['attribute'], 6)
                self.assertEqual(report['summary']['heap_buffers'], 0)

    def test_neon_typedef_slots_and_numeric_resource_references_remain_unsafe(self):
        source = GLIB_HOST + r'''
typedef signed char Byte;
typedef __attribute__((neon_vector_type(8))) Byte Vector;
typedef unsigned char PolynomialByte;
typedef __attribute__((neon_polyvector_type(8))) PolynomialByte Polynomial;
typedef Vector VectorAlias;
static const VectorAlias *vectors=(const VectorAlias *)"FridaVectorData";
static const Polynomial *polynomials=(const Polynomial *)"FridaPolynomialData";
static const unsigned char gumjs_neon_bytecode[]={70,114,105,100,97,0,0,0};
static const Vector *metadata=(const Vector *)gumjs_neon_bytecode;
const unsigned char *bytes(void){return gumjs_neon_bytecode;}
'''
        for language in ('c', 'cpp'):
            with self.subTest(language=language):
                output, report = self.transform(source, language)
                self.assertEqual(output, source.encode())
                self.assertEqual(report['summary']['heap_buffers'], 0)
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 0)
                self.assertEqual(report['summary']['resources_transformed'], 0)
                self.assertEqual({item['reason'] for item in report['skipped']},
                                 {'type_or_field_attributes',
                                  'resource_reference_type_or_field_attributes'})

    def test_malformed_neon_attribute_and_unrelated_syntax_fail_closed(self):
        samples = (
            'typedef __attribute__((neon_vector_type(8 +))) signed char V;',
            'typedef __attribute__((neon_polyvector_type(8 +))) unsigned char P;',
            'typedef __attribute__((neon_vector_type(8))) signed char V',
            'typedef __attribute__((unknown_neon_vector_type(8))) signed char V;',
            'typedef __attribute__((neon_vector_type(8))) signed char V; void f( {',
            'typedef __attribute__((neon_polyvector_type(8))) unsigned char P; int n=+;',
        )
        for language in ('c', 'cpp'):
            for source in samples:
                with self.subTest(language=language, source=source), self.assertRaises(outline.OutlineError) as caught:
                    self.transform(source, language)
                self.assertEqual(caught.exception.report['failures'][-1]['reason'], 'input_does_not_parse')

    def test_hidden_type_operands_resource_reference_and_unknown_types(self):
        source = GLIB_HOST + r'''
static const unsigned char gumjs_typed_bytecode[]={70,114,105,100,97};
void f(void) {
  __typeof__(gumjs_typed_bytecode) *p=0;
  __typeof__("FridaTypeOperand") label="FridaTypedArray";
  __typeof__(int *) typed=0;
  (void)p; (void)label; (void)typed;
}
'''
        output, report = self.transform(source)
        self.assertEqual(output, source.encode())
        reasons = {s['reason'] for s in report['skipped']}
        self.assertIn('compile_time_or_type_context', reasons)
        self.assertIn('compiler_inferred_type', reasons)
        self.assertIn('resource_reference_hidden_compiler_context', reasons)
        self.assertEqual(report['summary']['resources_transformed'], 0)

    def test_builtin_type_operands_do_not_hide_value_arguments(self):
        source = GLIB_HOST + r'''
void f(void *vl) {
  const char *p=__builtin_va_arg(vl,const char *);
  void *q=__builtin_va_arg(vl,void **);
  int same=__builtin_types_compatible_p(const char *,char *);
  (void)p; (void)q; (void)same;
}
const char *name(void){return "FridaBuiltinType";}
'''
        output, report = self.transform(source)
        self.assertIn(b'__builtin_va_arg(vl,const char *)', output)
        self.assertIn(b'__builtin_types_compatible_p(const char *,char *)', output)
        self.assertEqual(report['parser_normalization']['kind_counts']['builtin-type'], 4)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)

    def test_diagnostic_pragmas_allowed_but_unknown_or_macro_directives_fail(self):
        pragmas = '#pragma clang diagnostic push\n#pragma clang diagnostic ignored "-Wdeprecated-declarations"\n#pragma clang diagnostic pop\n'
        output, report = self.transform(pragmas + GLIB_HOST + 'const char *f(void){return "FridaPragma";}')
        self.assertTrue(report['ok'])
        self.assertIn(pragmas.encode(), output)
        for source in ('#pragma clang attribute push (__attribute__((packed)), apply_to=record)\n',
                       '#define _Nullable\n', '#pragma message("frida")\n'):
            with self.subTest(source=source), self.assertRaises(outline.OutlineError) as caught:
                self.transform(source)
            self.assertEqual(caught.exception.report['failures'][-1]['reason'], 'input_not_fully_preprocessed')

    def test_pack_pragmas_preserve_layout_and_skip_static_packed_types_after_pop(self):
        source = GLIB_HOST + r'''
#pragma pack (push, 1)
typedef struct Packed { unsigned char tag; const char *name; } Packed;
#pragma pack(pop)
static const Packed values[]={{7,"FridaPackedValue"}};
static const char *safe="FridaPackedSafe";
const char *name(void){return "FridaPackedRuntime";}
int main(void) {
  require(sizeof(Packed)==1+sizeof(const char *));
  require(__builtin_offsetof(Packed,name)==1);
  require(values[0].tag==7 && values[0].name[0]=='F' && values[0].name[5]=='P');
  require(safe[0]=='F' && safe[11]=='S');
  require(name()[0]=='F' && name()[11]=='R');
  return 0;
}
'''
        for language in ('c', 'cpp'):
            with self.subTest(language=language):
                if language == 'cpp':
                    size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
                    unit = source.replace('typedef unsigned long gsize;',
                                          'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
                else:
                    unit = source
                output, report = self.transform(unit, language)
                self.assertIn(b'#pragma pack (push, 1)\n', output)
                self.assertIn(b'#pragma pack(pop)\n', output)
                self.assertIn(b'static const Packed values[]={{7,"FridaPackedValue"}};', output)
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 2)
                self.assertEqual(report['summary']['expected_pointer_patches'], 1)
                self.assertEqual([obj['paths'] for obj in report['static_objects']], [['']])
                self.assertEqual([s['reason'] for s in report['skipped']], ['aggregate_pragma_packing'])
                self.assertEqual(report['pragma_pack']['final_alignment'], None)
                self.assertEqual(report['pragma_pack']['remaining_stack_depth'], 0)
                self.assertTrue(report['pragma_pack']['original_bytes_emitted'])
                self.compile_run(output, language)

    def test_nested_pack_restore_default_types_and_resource_metadata(self):
        source = GLIB_HOST + r'''
#pragma pack(push,1)
struct PackedOne { char tag; const char *name; };
#pragma pack(push,2)
struct PackedTwo { char tag; const char *name; };
#pragma pack(pop)
struct PackedAgain { char tag; const char *name; };
#pragma pack(pop)
struct Normal { char tag; const char *name; };
static const struct PackedOne one={1,"FridaPackOne"};
static const struct PackedTwo two={2,"FridaPackTwo"};
static const struct PackedAgain again={3,"FridaPackAgain"};
static const unsigned char gumjs_pack_bytecode[]={70,114,105,100,97};
static const struct Normal normal={4,"FridaPackNormal"};
struct Resource { unsigned long length; const unsigned char *bytes; };
static const struct Resource resource={sizeof(gumjs_pack_bytecode),gumjs_pack_bytecode};
int main(void) {
  require(__builtin_offsetof(struct PackedOne,name)==1);
  require(__builtin_offsetof(struct PackedTwo,name)==2);
  require(__builtin_offsetof(struct PackedAgain,name)==1);
  require(__builtin_offsetof(struct Normal,name)==sizeof(const char *));
  require(one.tag==1 && two.tag==2 && again.tag==3 && normal.tag==4);
  require(one.name[9]=='O' && two.name[9]=='T' && again.name[9]=='A' && normal.name[9]=='N');
  require(resource.length==5 && resource.bytes[0]==70 && resource.bytes[4]==97);
  return 0;
}
'''
        output, report = self.transform(source)
        self.assertEqual(report['summary']['resources_transformed'], 1)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
        self.assertEqual(report['summary']['expected_pointer_patches'], 2)
        self.assertEqual({obj['name']: obj['paths'] for obj in report['static_objects']},
                         {'normal': ['.name'], 'resource': ['.bytes']})
        self.assertEqual([s['reason'] for s in report['skipped']], ['aggregate_pragma_packing'] * 3)
        self.assertEqual([event['effective_alignment'] for event in report['pragma_pack']['events']], [1, 2, 1, None])
        self.compile_run(output)

    def test_pack_direct_settings_named_stack_and_reset_are_tracked(self):
        cases = (
            ('#pragma pack(1)\nstruct Packed{char tag;const char *name;};\n#pragma pack()\n', [1, None]),
            ('#pragma pack(push,outer,1)\n#pragma pack(push,inner,2)\n'
             'struct Packed{char tag;const char *name;};\n#pragma pack(pop,outer)\n', [1, 2, None]),
            ('#pragma pack(push)\n#pragma pack(1)\n'
             'struct Packed{char tag;const char *name;};\n#pragma pack(pop)\n', [None, 1, None]),
        )
        for pragmas, alignments in cases:
            with self.subTest(pragmas=pragmas):
                source = GLIB_HOST + pragmas + 'static const struct Packed value={1,"FridaPackSetting"};\n'
                output, report = self.transform(source)
                self.assertEqual(output, source.encode())
                self.assertEqual(report['skipped'][0]['reason'], 'aggregate_pragma_packing')
                self.assertEqual([event['effective_alignment'] for event in report['pragma_pack']['events']], alignments)
                self.assertEqual(report['pragma_pack']['remaining_stack_depth'], 0)

    def test_pack_unsafe_metadata_reference_skips_the_entire_numeric_resource(self):
        source = GLIB_HOST + r'''
static const unsigned char gumjs_pack_bytecode[]={70,114,105,100,97};
#pragma pack(push,1)
struct PackedResource{char tag;const unsigned char *bytes;};
#pragma pack(pop)
static const struct PackedResource metadata={1,gumjs_pack_bytecode};
const unsigned char *bytes(void){return gumjs_pack_bytecode;}
'''
        output, report = self.transform(source)
        self.assertEqual(output, source.encode())
        self.assertEqual(report['summary']['resources_transformed'], 0)
        self.assertEqual(report['skipped'][0]['reason'], 'resource_reference_aggregate_pragma_packing')

    def test_unknown_pack_forms_and_unmatched_stack_fail_closed(self):
        cases = (
            ('#pragma pack(3)\n', 'input_not_fully_preprocessed'),
            ('#pragma pack(push,,1)\n', 'input_not_fully_preprocessed'),
            ('#pragma pack(push,1,2)\n', 'input_not_fully_preprocessed'),
            ('#pragma pack(PACK_ALIGNMENT)\n', 'input_not_fully_preprocessed'),
            ('#pragma pack(pop,4)\n', 'input_not_fully_preprocessed'),
            ('#pragma pack(push,outer,1)\n#pragma pack(pop,outer,4)\n', 'input_not_fully_preprocessed'),
            ('#pragma pack(pop)\n', 'pragma_pack_unmatched_pop'),
            ('#pragma pack(push,outer,1)\n#pragma pack(pop,missing)\n', 'pragma_pack_unmatched_pop'),
        )
        for source, reason in cases:
            with self.subTest(source=source), self.assertRaises(outline.OutlineError) as caught:
                self.transform(source)
            self.assertEqual(caught.exception.report['failures'][-1]['reason'], reason)

    def test_pack_keyword_and_reserved_labels_fail_closed(self):
        labels = ('int', 'class', 'bool', 'restrict', 'typeof', '__signed__',
                  '__const__', '__typeof__', '_Nullable', '_Atomic', '__vendor')
        for label in labels:
            for language in ('c', 'cpp'):
                source = ('#pragma clang diagnostic ignored "-Wignored-pragmas"\n'
                          '#pragma clang diagnostic ignored "-Wpragma-pack"\n'
                          '#pragma pack(push,%s,1)\n#pragma pack(push,2)\n'
                          '#pragma pack(pop,%s)\n' % (label, label))
                with self.subTest(label=label, language=language), self.assertRaises(outline.OutlineError) as caught:
                    self.transform(source, language)
                self.assertEqual(caught.exception.report['failures'][-1]['reason'], 'input_not_fully_preprocessed')
        for label in ('outer', 'normal', '_lower'):
            source = '#pragma pack(push,%s,1)\n#pragma pack(pop,%s)\n' % (label, label)
            output, report = self.transform(source)
            self.assertEqual(output, source.encode())
            self.assertEqual([e['effective_alignment'] for e in report['pragma_pack']['events']], [1, None])

    def test_by_value_packing_dependency_crosses_aggregate_shells_and_arrays(self):
        wrappers = (
            ('typedef struct Wrapper{Child child;} Wrapper;', ('c', 'cpp')),
            ('typedef union Wrapper{Child child;} Wrapper;', ('c', 'cpp')),
            ('typedef struct Wrapper{Child children[2];} Wrapper;', ('c', 'cpp')),
            ('typedef Child Children[2];typedef struct Wrapper{Children children;} Wrapper;', ('c', 'cpp')),
            ('class Wrapper{public:Child child;};', ('cpp',)),
            ('struct Wrapper:Child{};', ('cpp',)),
        )
        for wrapper, languages in wrappers:
            for language in languages:
                with self.subTest(wrapper=wrapper, language=language):
                    source = GLIB_HOST + r'''
#pragma pack(push,1)
typedef struct Child{char tag;void *payload;} Child;
#pragma pack(pop)
''' + wrapper + r'''
typedef struct Outer{char prefix;Wrapper wrapper;const char *text;} Outer;
static const Outer value={1,{0},"FridaOuter"};
int main(void){
  require(sizeof(Child)==1+sizeof(void *));
  require(__alignof__(Wrapper)==1);
  require(__builtin_offsetof(Outer,wrapper)==1);
  require(__builtin_offsetof(Outer,text)==
      ((1+sizeof(Wrapper)+sizeof(void *)-1)/sizeof(void *))*sizeof(void *));
  require(value.prefix==1 && value.text[0]=='F' && value.text[5]=='O');
  return 0;
}
'''
                    if language == 'cpp':
                        size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
                        source = source.replace('typedef unsigned long gsize;',
                                                'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
                        source = source.replace('value={1,{0},', 'value={1,{},')
                    output, report = self.transform(source, language)
                    self.assertEqual(output, source.encode())
                    self.assertEqual(report['summary']['literal_occurrences_transformed'], 0)
                    self.assertEqual(report['summary']['expected_pointer_patches'], 0)
                    self.assertEqual([s['reason'] for s in report['skipped']], ['aggregate_pragma_packing'])
                    self.compile_run(output, language, extra_flags=('-Wno-missing-braces', '-Wno-missing-field-initializers'))

    def test_pointer_fields_do_not_propagate_packing_dependency(self):
        for field, value in (('Child *child;', '0'),
                             ('Child *children[2];', '{0,0}'),
                             ('Child (*children)[2];', '0')):
            for language in ('c', 'cpp'):
                with self.subTest(field=field, language=language):
                    source = GLIB_HOST + r'''
#pragma pack(push,1)
typedef struct Child{char tag;void *payload;} Child;
#pragma pack(pop)
''' + 'typedef struct Wrapper{' + field + 'const char *text;} Wrapper;\n'
                    source += 'static const Wrapper value={' + value + ',"FridaPointer"};\n'
                    source += r'''
static const unsigned char gumjs_pointer_bytecode[]={70,114,105,100,97};
struct Resource{Child *child;const unsigned char *bytes;};
static const struct Resource metadata={0,gumjs_pointer_bytecode};
int main(void){
  require(value.text[0]=='F' && value.text[5]=='P');
  require(metadata.bytes[0]==70 && metadata.bytes[4]==97);
  return 0;
}
'''
                    if language == 'cpp':
                        size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
                        source = source.replace('typedef unsigned long gsize;',
                                                'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
                    output, report = self.transform(source, language)
                    self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                    self.assertEqual(report['summary']['resources_transformed'], 1)
                    self.assertEqual(report['summary']['expected_pointer_patches'], 2)
                    self.assertEqual(report['skipped'], [])
                    self.assertEqual(sorted(obj['paths'] for obj in report['static_objects']), [['.bytes'], ['.text']])
                    self.compile_run(output, language)

    def test_by_value_packed_resource_consumer_skips_the_whole_resource(self):
        source = GLIB_HOST + r'''
#pragma pack(push,1)
typedef struct Child{char tag;void *payload;} Child;
#pragma pack(pop)
typedef union Wrapper{Child child;} Wrapper;
struct Resource{Wrapper wrapper;const unsigned char *bytes;};
static const unsigned char gumjs_outer_bytecode[]={70,114,105,100,97};
static const struct Resource metadata={{{1,0}},gumjs_outer_bytecode};
const unsigned char *bytes(void){return gumjs_outer_bytecode;}
int main(void){
  require(__alignof__(Wrapper)==1);
  require(metadata.bytes==bytes() && bytes()[4]==97);
  return 0;
}
'''
        for language in ('c', 'cpp'):
            with self.subTest(language=language):
                unit = source
                if language == 'cpp':
                    size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
                    unit = unit.replace('typedef unsigned long gsize;',
                                        'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
                output, report = self.transform(unit, language)
                self.assertEqual(output, unit.encode())
                self.assertEqual(report['summary']['resources_transformed'], 0)
                self.assertEqual([s['reason'] for s in report['skipped']], ['resource_reference_aggregate_pragma_packing'])
                self.compile_run(output, language)

    def test_unknown_compiler_syntax_keeps_by_value_packing_dependency(self):
        source = GLIB_HOST + r'''
#pragma pack(push,1)
typedef struct Child{char tag;__typeof__(0) number;} Child;
#pragma pack(pop)
typedef struct Wrapper{Child child;__typeof__(0) number;} Wrapper;
struct Outer{char prefix;Wrapper wrapper;const char *text;};
static const struct Outer value={1,{{2,3},4},"FridaTypeof"};
static const unsigned char gumjs_typeof_bytecode[]={70,114,105,100,97};
struct Metadata{char prefix;Child child;const unsigned char *bytes;};
static const struct Metadata metadata={1,{2,3},gumjs_typeof_bytecode};
const unsigned char *bytes(void){return gumjs_typeof_bytecode;}
int main(void){
  require(__builtin_offsetof(Child,number)==1);
  require(sizeof(Child)==1+sizeof(int));
  require(value.wrapper.child.number==3 && value.text[5]=='T');
  require(metadata.child.number==3 && metadata.bytes==bytes() && bytes()[4]==97);
  return 0;
}
'''
        for language in ('c', 'cpp'):
            with self.subTest(language=language):
                unit = source
                if language == 'cpp':
                    size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
                    unit = unit.replace('typedef unsigned long gsize;',
                                        'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
                output, report = self.transform(unit, language)
                self.assertEqual(output, unit.encode())
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 0)
                self.assertEqual(report['summary']['resources_transformed'], 0)
                self.assertEqual({s['reason'] for s in report['skipped']},
                                 {'aggregate_pragma_packing', 'resource_reference_aggregate_pragma_packing'})
                self.compile_run(output, language)

    def test_pack_forward_and_local_homonyms_keep_default_layout(self):
        source = GLIB_HOST + r'''
#pragma pack(push,1)
struct Normal;
struct Child{char tag;void *payload;};
#pragma pack(pop)
struct Normal{char tag;const char *text;};
static const struct Normal normal={1,"FridaForward"};
const char *local(void){
  struct Child{const char *text;};
  static const struct Child child={"FridaLocal"};
  return child.text;
}
int main(void){
  require(__builtin_offsetof(struct Normal,text)==sizeof(void *));
  require(normal.text[0]=='F' && local()[5]=='L');
  return 0;
}
'''
        for language in ('c', 'cpp'):
            with self.subTest(language=language):
                unit = source
                if language == 'cpp':
                    size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
                    unit = unit.replace('typedef unsigned long gsize;',
                                        'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
                output, report = self.transform(unit, language)
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 2)
                self.assertEqual(report['summary']['expected_pointer_patches'], 2)
                self.assertEqual(report['skipped'], [])
                self.compile_run(output, language)

    def test_pack_text_in_literals_and_comments_does_not_change_layout_state(self):
        source = GLIB_HOST + r'''
/* #pragma pack(push,1) */
const char *name(void){return "Frida #pragma pack(push,1)";}
static const char *slot="FridaNoPacking";
int main(void){require(name()[0]=='F' && slot[0]=='F');return 0;}
'''
        output, report = self.transform(source)
        self.assertNotIn('pragma_pack', report)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 2)
        self.assertEqual(report['summary']['expected_pointer_patches'], 1)
        self.compile_run(output)

    def test_malformed_or_unknown_extensions_never_hide_parse_errors(self):
        samples = [
            'enum E{A __attribute__((unknown_vendor_attribute))=1};',
            'enum E{A __attribute__((deprecated("x"))) += 1};',
            'enum E{A __attribute__((deprecated("x")) = 1};',
            'void f(void){typeof (int +) value;}',
            'void f(void){__builtin_va_arg(vl, int +);}',
            'int x __asm__("name", 1);',
            'int x __attribute__((unused)); void f( {',
        ]
        for source in samples:
            with self.subTest(source=source), self.assertRaises(outline.OutlineError) as caught:
                self.transform(source)
            report = caught.exception.report
            self.assertEqual(report['failures'][-1]['reason'], 'input_does_not_parse')
            for error in report['failures'][:-1]:
                self.assertLessEqual(len(error['context']), 440)
                self.assertIn('start_byte', error)

    def test_forward_typedef_and_recursive_header_structs(self):
        source = GLIB_HOST + r'''
typedef struct _Value Value;
struct _Value { int number; const char *name; struct _Value *next; };
static const Value values[]={{1,"FridaForward",0}};
'''
        source += 'int main(void){require(values[0].number==1);require(strcmp(values[0].name,%s)==0);return 0;}' % c_string('FridaForward')
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['expected_pointer_patches'], 1)
        self.compile_run(output)

    def test_host_compiler_enum_asm_typeof_semantics_preserved(self):
        source = GLIB_HOST + r'''
typedef __signed__ char SignedByte;
enum E { OLD __attribute__((deprecated))=7, CURRENT=7 };
static const char *alias_api(void) __asm__("outlined_alias_api");
static const char *alias_api(void) { return "FridaGNUAlias"; }
int main(void) {
  __typeof__(*alias_api()) byte=alias_api()[0];
  require(byte=='F' && CURRENT==7 && sizeof(SignedByte)==1);
  require(strcmp(alias_api(),EXPECTED)==0);
  return 0;
}
'''
        source = source.replace('EXPECTED', c_string('FridaGNUAlias'))
        output, report = self.transform(source)
        self.assertEqual(report['skipped'], [])
        self.assertIn(b'__asm__("outlined_alias_api")', output)
        self.assertIn(b'__typeof__(*alias_api())', output)
        self.compile_run(output)

    def test_cpp_deleted_and_member_pointer_metadata_fail_closed(self):
        source = GLIB_HOST + r'''
struct C {};
void deleted(const char *text="FridaDeletedDefault") = delete;
static const char * C::*member="FridaMemberPointerSlot";
static const char *ordinary="FridaOrdinaryPointer";
void use(void) { deleted("FridaDeletedArgument"); }
'''
        output, report = self.transform(source, 'cpp')
        reasons = {s['reason'] for s in report['skipped']}
        self.assertIn('lambda_default_or_field_context', reasons)
        self.assertIn('cpp_deleted_call_parameter', reasons)
        self.assertIn('cpp_member_pointer_type_context', reasons)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
        self.assertEqual(report['summary']['expected_pointer_patches'], 1)
        self.assertEqual(report['static_objects'][0]['name'], '::ordinary')
        self.assertIn(b'= delete;', output)
        self.assertIn(b'const char * C::*member="FridaMemberPointerSlot";', output)
        self.assertEqual(report['parser_normalization']['kind_counts']['deleted-function'], 1)
        self.assertEqual(report['parser_normalization']['kind_counts']['member-pointer'], 1)

    def test_cpp_member_pointer_template_cv_ref_noexcept_projection(self):
        suffixes = ('', 'const', 'volatile', 'const volatile', '&', 'const&',
                    'const volatile&', '&&', 'const volatile&&', 'noexcept')
        source = 'template<class>struct S;\n'
        for index, suffix in enumerate(suffixes):
            source += 'template<class R,class C,class...P> struct S<R (C::*)(P...,...) %s> { enum {value=%d}; };\n' % (suffix, index)
        source += 'template<class R,class C> struct S<R C::*> {};\n'
        source += 'template<class R,class C> struct S<R *> {};\n'
        transformer = outline.Transformer(source.encode(), 'cpp', 'member.ii')
        self.assertFalse(transformer.root.has_error)
        self.assertEqual(transformer.shadow.summary()['kind_counts']['member-pointer'], len(suffixes)+1)
        output, report = transformer.run()
        self.assertEqual(output, source.encode())
        self.assertTrue(report['ok'])
        for suffix in suffixes:
            self.assertIn(('(P...,...) %s>' % suffix).encode(), output)

    def test_cpp_explicit_operator_keeps_receiver_values_and_resources(self):
        source = GLIB_HOST + r'''
static const unsigned char gumjs_operator_bytecode[]={70,114,105,100,97};
void f(void) {
  receiver().operator()("FridaOperatorArgument",gumjs_operator_bytecode);
  receiver().operator[]("FridaOperatorIndex");
}
'''
        output, report = self.transform(source, 'cpp')
        self.assertEqual(output, source.encode())
        self.assertEqual(report['summary']['resources_transformed'], 0)
        reasons = {s['reason'] for s in report['skipped']}
        self.assertIn('cpp_explicit_operator_call', reasons)
        self.assertIn('resource_reference_cpp_explicit_operator_call', reasons)
        self.assertEqual(report['parser_normalization']['kind_counts']['operator-id'], 2)
        transformer = outline.Transformer(source.encode(), 'cpp', 'operators.ii')
        self.assertIn(b'receiver()._nso_op', transformer.shadow.view)
        self.assertIn(b'"FridaOperatorArgument",gumjs_operator_bytecode', transformer.shadow.view)

    def test_cpp_template_destructor_shadow_preserves_offsets_and_original_bytes(self):
        source = r'''
void f(void) {
  for (unsigned i=0; i!=3; i++) argv[i].~Local<Value> ();
  receiver()->~Local<Value>();
  (*argv[j]).~Local<ns::Value>();
  argv[j].~Local<::ns::Value, Other> ();
}
'''.replace('\n', '\r\n').encode()
        transformer = outline.Transformer(source, 'cpp', 'destructors.ii')
        self.assertFalse(transformer.root.has_error)
        self.assertEqual(len(transformer.shadow.view), len(source))
        self.assertEqual([i for i, byte in enumerate(transformer.shadow.view) if byte in (10, 13)],
                         [i for i, byte in enumerate(source) if byte in (10, 13)])
        regions = [r for r in transformer.shadow.regions if r['kind'] == 'template-destructor']
        self.assertEqual(len(regions), 4)
        expected = bytearray(source)
        for region in regions:
            raw = source[region['start']:region['end']]
            self.assertTrue(raw.startswith(b'<') and raw.endswith(b'>'))
            expected[region['start']:region['end']] = outline._padded(raw)
        self.assertEqual(transformer.shadow.view, bytes(expected))
        calls = [n for n in transformer.nodes if n.type == 'call_expression'
                 and transformer.shadow.attached(n, 'template-destructor')]
        self.assertEqual(len(calls), 4)
        output, report = transformer.run()
        self.assertEqual(output, source)
        self.assertTrue(report['ok'])
        self.assertEqual(report['summary']['heap_buffers'], 0)

    def test_cpp_template_destructor_receiver_and_hidden_resources_remain_unsafe(self):
        source = GLIB_HOST + r'''
static const Local<Value> *slot=(const Local<Value> *)"FridaTemplateSlot";
static const unsigned char gumjs_destructor_bytecode[]={70,114,105,100,97};
static const unsigned char gumjs_hidden_bytecode[]={70,114,105,100,97};
void f(void) {
  receiver("FridaDestructorReceiver",gumjs_destructor_bytecode)->~Local<Value>();
  object.~Local<gumjs_hidden_bytecode>();
}
const unsigned char *bytes(void){return gumjs_hidden_bytecode;}
'''
        output, report = self.transform(source, 'cpp')
        self.assertEqual(output, source.encode())
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 0)
        self.assertEqual(report['summary']['resources_transformed'], 0)
        reasons = {s['reason'] for s in report['skipped']}
        self.assertIn('unresolved_type', reasons)
        self.assertIn('cpp_template_destructor_call', reasons)
        self.assertIn('resource_reference_cpp_template_destructor_call', reasons)
        self.assertIn('resource_reference_hidden_compiler_context', reasons)
        self.assertEqual(report['parser_normalization']['kind_counts']['template-destructor'], 2)

    def test_cpp_template_destructor_complex_or_malformed_syntax_fail_closed(self):
        broken = (
            'void f(){obj.~Local<Value>(); int n=+;}',
            'void f(){obj.~Local<Value>(); broken( ;}',
            'void f(){obj.~Local<Value> (;}',
            'void f(){obj.~Local<Value,>();}',
            'void f(){obj.~Local<decltype("frida")>();}',
            'void f(){obj.~Local<sizeof(gumjs_data_bytecode)>();}',
            'void f(){obj.~Local<Other<Value>>();}',
            'void f(){obj.~Local<"frida">();}',
        )
        for source in broken:
            with self.subTest(source=source), self.assertRaises(outline.OutlineError) as caught:
                self.transform(source, 'cpp')
            self.assertEqual(caught.exception.report['failures'][-1]['reason'], 'input_does_not_parse')

    def test_host_cpp_template_destructor_calls_preserve_lifetime_and_runtime_bytes(self):
        size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
        host = GLIB_HOST.replace('typedef unsigned long gsize;', 'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
        source = host + r'''
void *operator new(gsize,void *p) noexcept {return p;}
static int destruction_count;
static int destruction_order[3];
struct Value {int id;};
template<class T> struct Local {
  T *value;
  explicit Local(T *v):value(v){}
  ~Local(){destruction_order[destruction_count++]=value->id;}
};
const char *name(void){return "FridaDestructorRuntime";}
int main(void){
  alignas(Local<Value>) unsigned char storage[3*sizeof(Local<Value>)];
  Local<Value> *argv=(Local<Value> *)storage;
  Value values[3]={{7},{8},{9}};
  for(unsigned i=0;i!=3;i++) new (argv+i) Local<Value>(&values[i]);
  for(unsigned i=0;i!=2;i++) argv[i].~Local<Value> ();
  (argv+2)->~Local<Value>();
  require(destruction_count==3);
  require(destruction_order[0]==7 && destruction_order[1]==8 && destruction_order[2]==9);
  require(strcmp(name(),EXPECTED)==0 && name()==name());
  return 0;
}
'''
        source = source.replace('EXPECTED', c_string('FridaDestructorRuntime'))
        self.compile_run(source, 'cpp', extra_flags=('-std=c++17',))
        output, report = self.transform(source, 'cpp')
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['parser_normalization']['kind_counts']['template-destructor'], 2)
        self.assertIn(b'argv[i].~Local<Value> ();', output)
        self.assertIn(b'(argv+2)->~Local<Value>();', output)
        self.assertEqual(report['summary']['heap_buffers'], 1)
        self.compile_run(output, 'cpp', extra_flags=('-std=c++17',))

    def test_cpp_anonymous_fixed_enum_shadow_preserves_anonymity_offsets_and_bytes(self):
        source = r'''
typedef __SIZE_TYPE__ size_t;
enum : size_t {
  BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE = -1UL,
  BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE = -2UL,
  BIONIC_MULTIBYTE_RESULT_NO_BYTES_CONSUMED = -3UL,
};
namespace owned {
enum:unsigned char { SMALL=3 };
void f(){enum
:
unsigned short { LOCAL=9 };}
}
'''.replace('\n', '\r\n').encode()
        transformer = outline.Transformer(source, 'cpp', 'anonymous-enums.ii')
        self.assertFalse(transformer.root.has_error)
        self.assertEqual(len(transformer.shadow.view), len(source))
        self.assertEqual([i for i, byte in enumerate(transformer.shadow.view) if byte in (10, 13)],
                         [i for i, byte in enumerate(source) if byte in (10, 13)])
        regions = [r for r in transformer.shadow.regions if r['kind'] == 'anonymous-enum-base']
        self.assertEqual(len(regions), 3)
        expected = bytearray(source)
        for region in regions:
            expected[region['start']:region['end']] = outline._padded(source[region['start']:region['end']])
        self.assertEqual(transformer.shadow.view, bytes(expected))
        enums = [n for n in transformer.nodes if n.type == 'enum_specifier']
        self.assertEqual(len(enums), 3)
        for node in enums:
            self.assertIsNone(node.child_by_field_name('name'))
            self.assertTrue(transformer.shadow.attached(node, 'anonymous-enum-base'))
        output, report = transformer.run()
        self.assertEqual(output, source)
        self.assertTrue(report['ok'])
        self.assertEqual(report['summary']['heap_buffers'], 0)

    def test_cpp_anonymous_fixed_enum_types_and_alias_slots_remain_unknown(self):
        source = GLIB_HOST + r'''
typedef enum : unsigned char { BYTE_VALUE=1 } ByteEnum;
typedef ByteEnum ByteAlias;
static const ByteAlias *slot=(const ByteAlias *)"FridaAnonymousEnumSlot";
'''
        output, report = self.transform(source, 'cpp')
        self.assertEqual(output, source.encode())
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 0)
        self.assertEqual(report['summary']['expected_pointer_patches'], 0)
        self.assertEqual({s['reason'] for s in report['skipped']}, {'cpp_fixed_underlying_anonymous_enum'})

    def test_cpp_enumerator_values_and_sizeof_resource_references_stay_compiletime(self):
        for declaration in ('enum : unsigned long', 'enum Named : unsigned long', 'enum'):
            source = GLIB_HOST + r'''
static const unsigned char gumjs_enum_bytecode[]={70,114,105,100,97};
DECLARATION {
  MARKER_SIZE=sizeof("FridaEnumeratorValue"),
  RESOURCE_SIZE=sizeof(gumjs_enum_bytecode)
};
const unsigned char *bytes(void){return gumjs_enum_bytecode;}
'''
            source = source.replace('DECLARATION', declaration)
            with self.subTest(declaration=declaration):
                output, report = self.transform(source, 'cpp')
                self.assertEqual(output, source.encode())
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 0)
                self.assertEqual(report['summary']['resources_transformed'], 0)
                reasons = {s['reason'] for s in report['skipped']}
                self.assertIn('enum_value_compile_time_context', reasons)
                self.assertIn('resource_reference_enum_value_compile_time_context', reasons)

    def test_cpp_anonymous_fixed_enum_malformed_or_unknown_base_fails_closed(self):
        broken = (
            'enum : size_t { X= };',
            'enum : size_t { X=1 }; void f( {',
            'enum : size_t { X=1;',
            'enum : size_t* { X=1 };',
            'enum : float { X=1 };',
            'enum : double { X=1 };',
            'enum : void { X=1 };',
            'enum : Alias { X=1 };',
            'enum : ns::Alias { X=1 };',
            'enum : decltype("frida") { X=1 };',
            'enum : __typeof__(gumjs_enum_bytecode) { X=1 };',
            'enum : unsigned + long { X=1 };',
            'enum : size_t { X=1 } bad( ;',
        )
        for source in broken:
            with self.subTest(source=source), self.assertRaises(outline.OutlineError) as caught:
                self.transform(source, 'cpp')
            self.assertEqual(caught.exception.report['failures'][-1]['reason'], 'input_does_not_parse')
        with self.assertRaises(outline.OutlineError):
            self.transform('enum : unsigned int { X=1 };', 'c')

    def test_host_cpp_anonymous_fixed_enum_width_signedness_and_runtime_bytes(self):
        size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
        host = GLIB_HOST.replace('typedef unsigned long gsize;', 'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
        source = host + r'''
typedef gsize size_t;
enum : size_t { ILLEGAL=-1UL, INCOMPLETE=-2UL, EMPTY=-3UL };
typedef enum : unsigned char { MAX_BYTE=255 } ByteEnum;
static_assert(sizeof(decltype(ILLEGAL))==sizeof(size_t),"fixed size width");
static_assert(ILLEGAL==(size_t)-1 && INCOMPLETE==(size_t)-2 && EMPTY==(size_t)-3,"fixed values");
static_assert(sizeof(ByteEnum)==1 && MAX_BYTE==255,"fixed byte width");
const char *name(void){return "FridaAnonymousEnumRuntime";}
int main(void){require(strcmp(name(),EXPECTED)==0 && name()==name());return 0;}
'''
        source = source.replace('EXPECTED', c_string('FridaAnonymousEnumRuntime'))
        self.compile_run(source, 'cpp', extra_flags=('-std=c++17',))
        output, report = self.transform(source, 'cpp')
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['parser_normalization']['kind_counts']['anonymous-enum-base'], 2)
        self.assertEqual(report['summary']['heap_buffers'], 1)
        self.assertIn(b'enum : size_t { ILLEGAL=-1UL', output)
        self.assertIn(b'enum : unsigned char { MAX_BYTE=255 }', output)
        self.compile_run(output, 'cpp', extra_flags=('-std=c++17',))

    def test_real_ndk_anonymous_fixed_enum_semantics_compile_both_architectures(self):
        clang = os.environ.get('STRING_OUTLINE_ANDROID_CLANG')
        if not clang:
            if os.environ.get('STRING_OUTLINE_REQUIRE_ANDROID') == '1':
                self.fail('set STRING_OUTLINE_ANDROID_CLANG to the installed NDK clang')
            self.skipTest('installed Android NDK clang not selected')
        source = r'''#include <stddef.h>
typedef __SIZE_TYPE__ gsize;
void *g_malloc(gsize);
int g_once_init_enter(volatile gsize *);
void g_once_init_leave(volatile gsize *,gsize);
enum : size_t { ILLEGAL=-1UL, INCOMPLETE=-2UL, EMPTY=-3UL };
typedef enum : unsigned char { MAX_BYTE=255 } ByteEnum;
static_assert(sizeof(decltype(ILLEGAL))==sizeof(size_t),"fixed size width");
static_assert(ILLEGAL==(size_t)-1 && INCOMPLETE==(size_t)-2 && EMPTY==(size_t)-3,"fixed values");
static_assert(sizeof(ByteEnum)==1 && MAX_BYTE==255,"fixed byte width");
const char *name(void){return "FridaAndroidAnonymousEnum";}
'''
        with tempfile.TemporaryDirectory(prefix='nso-anon-enum-') as directory:
            root = Path(directory)
            raw = root/'unit.cpp'
            raw.write_text(source, encoding='utf-8')
            for target, machine in (('aarch64-linux-android21', 183), ('armv7a-linux-androideabi19', 40)):
                with self.subTest(target=target):
                    semantic = [clang, '--target='+target, '-std=c++20', '-Oz', '-fPIC', '-Werror']
                    unit = root/(target+'.ii')
                    baseline = root/(target+'.baseline.o')
                    transformed = root/(target+'.outlined.ii')
                    outlined = root/(target+'.outlined.o')
                    preprocessed = subprocess.run([*semantic, '-E', '-P', str(raw), '-o', str(unit)],
                                                  capture_output=True, timeout=90)
                    self.assertEqual(preprocessed.returncode, 0, preprocessed.stderr.decode(errors='replace'))
                    original = unit.read_bytes()
                    built = subprocess.run([*semantic, '-x', 'c++-cpp-output', '-c', str(unit), '-o', str(baseline)],
                                           capture_output=True, timeout=90)
                    self.assertEqual(built.returncode, 0, built.stderr.decode(errors='replace'))
                    output, report = self.transform(original, 'cpp')
                    transformed.write_bytes(output)
                    self.assertTrue(report['ok'])
                    self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                    self.assertIn(b'enum : size_t { ILLEGAL=-1UL', output)
                    self.assertIn(b'enum : unsigned char { MAX_BYTE=255 }', output)
                    built = subprocess.run([*semantic, '-x', 'c++-cpp-output', '-c', str(transformed), '-o', str(outlined)],
                                           capture_output=True, timeout=90)
                    self.assertEqual(built.returncode, 0, built.stderr.decode(errors='replace'))
                    for obj in (baseline, outlined):
                        data = obj.read_bytes()
                        self.assertEqual(data[:4], b'\x7fELF')
                        self.assertEqual(int.from_bytes(data[18:20], 'little'), machine)

    def test_cpp_underlying_type_unknown_and_malformed_projection_rejected(self):
        source = GLIB_HOST + r'''
enum E { FIRST=1 };
typedef __underlying_type(E) Underlying;
static Underlying *p="FridaCompilerUnderlyingType";
'''
        output, report = self.transform(source, 'cpp')
        self.assertEqual(output, source.encode())
        self.assertEqual(report['skipped'][0]['reason'], 'compiler_inferred_type')
        for broken in ('int (*p)() = delete;', 'template<class R,class C>struct S<R C::*> {void f( { };',
                       'template<class R,class C>struct S<R (C::*)(int +)> {};',
                       'void f(){obj.operator()("frida", +);}',
                       'typedef __underlying_type(E +) T;'):
            with self.subTest(broken=broken), self.assertRaises(outline.OutlineError) as caught:
                self.transform(broken, 'cpp')
            self.assertEqual(caught.exception.report['failures'][-1]['reason'], 'input_does_not_parse')

    def test_host_cpp_standard_pointer_member_and_deleted_semantics(self):
        size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
        host = GLIB_HOST.replace('typedef unsigned long gsize;', 'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')
        source = host + r'''
struct Object { int value; int get(int amount) const { return value+amount; } };
int Object::*data_member=&Object::value;
int (Object::*function_member)(int) const=&Object::get;
template<class> struct IsMember { enum {value=0}; };
template<class R,class C>struct IsMember<R C::*> {enum {value=1};};
template<class T>T* address(const T&&)=delete;
enum Mode { VALUE=7 };
typedef __underlying_type(Mode) ModeType;
struct Operator { int operator&() const {return 9;} };
static const char *ordinary_name(void){return "FridaStdCpp";}
int main(void){
  Object o={3}; Operator op;
  require(o.*data_member==3 && (o.*function_member)(4)==7);
  require(IsMember<decltype(data_member)>::value==1);
  require(op.operator&()==9 && sizeof(ModeType)==sizeof(Mode));
  require(strcmp(ordinary_name(),EXPECTED)==0);
  return 0;
}
'''
        source = source.replace('EXPECTED', c_string('FridaStdCpp'))
        output, report = self.transform(source, 'cpp')
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['heap_buffers'], 1)
        self.assertIn(b'Object::*data_member', output)
        self.assertIn(b'Object::*function_member', output)
        self.assertIn(b'=delete;', output)
        self.assertIn(b'op.operator&()==9', output)
        self.compile_run(output, 'cpp')

    def test_real_ndk_neon_headers_and_vector_semantics_compile_c_and_cpp(self):
        clang = os.environ.get('STRING_OUTLINE_ANDROID_CLANG')
        if not clang:
            if os.environ.get('STRING_OUTLINE_REQUIRE_ANDROID') == '1':
                self.fail('set STRING_OUTLINE_ANDROID_CLANG to the installed NDK clang')
            self.skipTest('installed Android NDK clang not selected')
        source = r'''#include <arm_neon.h>
#include <stddef.h>
typedef __SIZE_TYPE__ gsize;
void *g_malloc(gsize);
int g_once_init_enter(volatile gsize *);
void g_once_init_leave(volatile gsize *,gsize);
#ifdef __cplusplus
static_assert(sizeof(uint8x16_t)==16,"NEON vector width");
static_assert(sizeof(poly8x8_t)==8,"NEON polynomial width");
#else
_Static_assert(sizeof(uint8x16_t)==16,"NEON vector width");
_Static_assert(sizeof(poly8x8_t)==8,"NEON polynomial width");
#endif
static const unsigned char gumjs_neon_bytecode[]={70,114,105,100,97,0,0,0};
static const uint8x8_t *metadata=(const uint8x8_t *)gumjs_neon_bytecode;
const uint8x8_t *vectors(void){return metadata;}
const unsigned char *bytes(void){return gumjs_neon_bytecode;}
const char *name(void){return "FridaNeonRuntime";}
int vector_operation(unsigned char *output){
  uint8x16_t vector=vdupq_n_u8(7);
  poly8x8_t polynomial=vdup_n_p8((poly8_t)3);
  vst1q_u8(output,vector);
  return output[15]+(int)vget_lane_p8(polynomial,0);
}
'''
        targets = (
            ('aarch64-linux-android21', (), 183),
            ('armv7a-linux-androideabi19', ('-mfpu=neon', '-mfloat-abi=softfp'), 40),
        )
        with tempfile.TemporaryDirectory(prefix='nso-neon-') as directory:
            root = Path(directory)
            raw = root/'unit.c'
            raw.write_text(source, encoding='utf-8')
            for target, target_flags, machine in targets:
                for language in ('c', 'cpp'):
                    with self.subTest(target=target, language=language):
                        stem = target+'-'+language
                        unit, baseline, obj = root/(stem+'.i'), root/(stem+'-baseline.o'), root/(stem+'.o')
                        standard = '-std=gnu99' if language == 'c' else '-std=gnu++17'
                        semantic = [clang, '--target='+target, standard, *target_flags,
                                    '-Oz', '-fPIC', '-Werror']
                        command = [*semantic, '-x', 'c' if language == 'c' else 'c++',
                                   '-E', '-P', str(raw), '-o', str(unit)]
                        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                        original = unit.read_bytes()
                        final_language = 'cpp-output' if language == 'c' else 'c++-cpp-output'
                        command = [*semantic, '-x', final_language, '-c', str(unit), '-o', str(baseline)]
                        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                        output, report = self.transform(original, language)
                        self.assertTrue(report['ok'])
                        self.assertGreater(report['parser_normalization']['kind_counts']['attribute'], 0)
                        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                        self.assertEqual(report['summary']['resources_transformed'], 0)
                        self.assertIn('resource_reference_type_or_field_attributes',
                                      {item['reason'] for item in report['skipped']})
                        self.assertIn(b'neon_vector_type', output)
                        self.assertIn(b'neon_polyvector_type', output)
                        self.assertEqual(original.count(b'neon_vector_type'), output.count(b'neon_vector_type'))
                        self.assertEqual(original.count(b'neon_polyvector_type'), output.count(b'neon_polyvector_type'))
                        unit.write_bytes(output)
                        command = [*semantic, '-x', final_language, '-c', str(unit), '-o', str(obj)]
                        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                        for object_path in (baseline, obj):
                            data = object_path.read_bytes()
                            self.assertEqual(data[:4], b'\x7fELF')
                            self.assertEqual(int.from_bytes(data[18:20], 'little'), machine)

    def test_real_ndk_libcpp_type_traits_preprocess_and_original_token_compile(self):
        clang = os.environ.get('STRING_OUTLINE_ANDROID_CLANG')
        if not clang:
            if os.environ.get('STRING_OUTLINE_REQUIRE_ANDROID') == '1':
                self.fail('set STRING_OUTLINE_ANDROID_CLANG to the installed NDK clang')
            self.skipTest('installed Android NDK clang not selected')
        source = r'''#include <type_traits>
typedef unsigned long gsize;
void *g_malloc(gsize);
int g_once_init_enter(volatile gsize *);
void g_once_init_leave(volatile gsize *,gsize);
struct Object { int value; int get(int n) const {return value+n;} };
template<class T>T* deleted_address(const T&&)=delete;
static_assert(std::is_member_pointer<int Object::*>::value,"member type");
static_assert(std::is_member_function_pointer<int(Object::*)(int)const>::value,"method type");
const char *name(void){return "FridaLibCpp";}
int run(void){Object o={3}; auto member=&Object::get; return (o.*member)(4);}
'''
        with tempfile.TemporaryDirectory(prefix='nso-libcpp-') as directory:
            root = Path(directory)
            raw, unit, obj = root/'unit.cpp', root/'unit.ii', root/'unit.o'
            raw.write_text(source, encoding='utf-8')
            command = [clang, '--target=aarch64-linux-android21', '-std=gnu++11', '-E', '-P', str(raw), '-o', str(unit)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            original = unit.read_bytes()
            output, report = self.transform(original, 'cpp')
            self.assertTrue(report['ok'])
            self.assertGreater(report['parser_normalization']['kind_counts']['member-pointer'], 0)
            self.assertGreater(report['parser_normalization']['kind_counts']['deleted-function'], 0)
            self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
            self.assertIn(b'T* deleted_address(const T&&)=delete;', output)
            self.assertIn(b'int(Object::*)(int)const', output)
            unit.write_bytes(output)
            command = [clang, '--target=aarch64-linux-android21', '-std=gnu++11', '-x', 'c++-cpp-output', '-c', str(unit), '-o', str(obj), '-Oz', '-fPIC']
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(obj.read_bytes()[:4], b'\x7fELF')

    def test_real_android_ndk_headers_preprocess_and_compile_c_and_cpp(self):
        clang = os.environ.get('STRING_OUTLINE_ANDROID_CLANG')
        if not clang:
            if os.environ.get('STRING_OUTLINE_REQUIRE_ANDROID') == '1':
                self.fail('set STRING_OUTLINE_ANDROID_CLANG to the installed NDK clang')
            self.skipTest('installed Android NDK clang not selected')
        source = r'''#define _GNU_SOURCE 1
#include <linux/types.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <jni.h>
typedef unsigned long gsize;
void *g_malloc(gsize);
int g_once_init_enter(volatile gsize *);
void g_once_init_leave(volatile gsize *,gsize);
typedef __signed__ __int128 AndroidSigned128;
enum AndroidCompat { OLD __attribute__((deprecated))=1, CURRENT=2 };
extern int alias_api(void) __asm__("android_alias_api");
struct Value { int number; const char *name; };
static const struct Value metadata[]={ {1,"FridaAndroidMetadata"} };
const char * _Nullable name(const void * _Nonnull arg) {
  __typeof__(*(const char **)arg) label=0;
  (void)label;
  return "frida:rpc";
}
'''
        with tempfile.TemporaryDirectory(prefix='nso-ndk-') as directory:
            root = Path(directory)
            raw = root/'unit.c'
            raw.write_text(source, encoding='utf-8')
            for language in ('c', 'cpp'):
                with self.subTest(language=language):
                    unit = root/('unit.i' if language == 'c' else 'unit.ii')
                    standard = '-std=gnu11' if language == 'c' else '-std=gnu++11'
                    preprocess = [clang, '--target=aarch64-linux-android21', standard, '-x', 'c' if language == 'c' else 'c++', '-E', '-P', str(raw), '-o', str(unit)]
                    result = subprocess.run(preprocess, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                    original = unit.read_bytes()
                    output, report = self.transform(original, language)
                    self.assertTrue(report['ok'])
                    self.assertEqual(report['summary']['static_objects'], 1)
                    self.assertEqual(report['summary']['literal_occurrences_transformed'], 2)
                    self.assertIn(b'typedef __signed__ __int128 AndroidSigned128;', output)
                    self.assertIn(b'_Nullable', output)
                    self.assertIn(b'__typeof__', output)
                    self.assertIn(b'__asm__("android_alias_api")', output)
                    unit.write_bytes(output)
                    obj = root/(language+'.o')
                    command = [clang, '--target=aarch64-linux-android21', standard, '-x', 'cpp-output' if language == 'c' else 'c++-cpp-output', '-c', str(unit), '-o', str(obj), '-Oz', '-fPIC']
                    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                    self.assertEqual(obj.read_bytes()[:4], b'\x7fELF')


class CppHeaderOriginBoundaryTests(unittest.TestCase):
    """Explicit physical header roots hide parser input, never compiler output."""

    def compile_run(self, source, language='cpp', extra_flags=(), execute=True):
        # GCC's preprocessed-input mode accepts numeric compiler line markers,
        # whereas these fixtures deliberately retain standard #line directives.
        # Use the native source language with no macros/includes added; the
        # Android product path is separately tested with Clang c++-cpp-output.
        return OutlineTests.compile_run(self, source, language, extra_flags,
                                        execute, input_language='c++')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='nso-cpp-origin-')
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name).resolve()
        self.header_root = self.workspace / 'external' / 'include' / 'c++' / 'v1'
        self.header_root.mkdir(parents=True)
        self.owned_path = self.workspace / 'owned.cpp'
        self.owned_path.write_bytes(b'/* physical owned translation unit */\n')
        self.header_count = 0
        size_type = 'unsigned int' if os.name == 'nt' else 'unsigned long'
        self.host = GLIB_HOST.replace('typedef unsigned long gsize;',
                                      'typedef %s gsize;' % size_type).replace('extern ', 'extern "C" ')

    @staticmethod
    def canonical(path):
        return os.path.normcase(str(Path(path).resolve())).replace('\\', '/')

    @staticmethod
    def line_marker(path, line=1, gnu=False):
        # Compiler filenames escape backslashes and encode non-ASCII UTF-8 bytes
        # as octal; they are not Python/JSON escapes or synthetic include roots.
        spelling = ''.join('\\%03o' % byte if byte >= 128 else
                           '\\\\' if byte == 92 else '\\"' if byte == 34 else chr(byte)
                           for byte in str(path).encode('utf-8'))
        return ('# %d "%s" 1 3\n' if gnu else '#line %d "%s"\n') % (line, spelling)

    def owned(self, body):
        if isinstance(body, str):
            body = body.encode('utf-8')
        return self.line_marker(self.owned_path).encode('ascii') + body

    def header(self, body, name=None, root=None, gnu=False):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.header_count += 1
        path = (self.header_root if root is None else root) / (name or 'header-%d.hpp' % self.header_count)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return self.line_marker(path, line=7, gnu=gnu).encode('ascii') + body, path

    def transform(self, source, roots=None, language='cpp'):
        return outline.outline_source(source, language, str(self.owned_path),
                                      cpp_opaque_roots=(self.header_root,) if roots is None else roots)

    def assert_failure(self, source, reason, roots=None, language='cpp'):
        with self.assertRaises(outline.OutlineError) as caught:
            self.transform(source, roots=roots, language=language)
        report = caught.exception.report
        self.assertFalse(report['ok'])
        expected = (reason,) if isinstance(reason, str) else reason
        self.assertIn(report['failures'][-1]['reason'], expected, report['failures'])
        return report

    def assert_exact_header(self, header, source, output):
        self.assertIn(header, output)
        self.assertEqual(output.count(header), source.count(header))

    def test_compiler_escaped_utf8_origins_use_physical_temporary_roots(self):
        for gnu in (False, True):
            with self.subTest(gnu_marker=gnu):
                body = b'static const char *header_name="FridaHeaderUtf8";\n'
                header, path = self.header(body, name='\u5b50\u76ee\u5f55/\u5916\u90e8-Frida.hpp', gnu=gnu)
                source = self.owned(self.host) + header + self.owned(
                    'const char *name(void){return "FridaOwnedUtf8";}\n')
                output, report = self.transform(source)
                self.assertTrue(self.header_root.is_dir())
                self.assertTrue(path.is_file())
                self.assertIn(b'\\345', header.splitlines()[0])
                if os.name == 'nt':
                    self.assertIn(b'\\\\', header.splitlines()[0])
                self.assertEqual(report['cpp_header_boundary']['roots'], [self.canonical(self.header_root)])
                self.assertEqual(report['cpp_header_boundary']['opaque_bytes'], len(body))
                self.assertTrue(report['cpp_header_boundary']['original_bytes_emitted'])
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                self.assertNotIn(b'"FridaOwnedUtf8"', output)
                skipped = next(s for s in report['skipped'] if s['reason'] == 'skipped_header_origin')
                self.assertIn(self.canonical(path), skipped['detail'])
                self.assert_exact_header(header, source, output)

    def test_consecutive_opaque_blocks_balance_namespace_and_extern_c(self):
        other_root = self.workspace / 'external' / 'alternate' / 'include'
        first, first_path = self.header('namespace sdk {\nextern "C" {\n')
        middle, middle_path = self.header(
            'int header_api(const char *);\nstatic const char *header_name="FridaConsecutiveHeader";\n',
            root=other_root, gnu=True)
        last, last_path = self.header('}\n}\n')
        headers = first + middle + last
        source = self.owned(self.host) + headers + self.owned(
            'const char *name(void){return "FridaConsecutiveOwned";}\n')
        transformer = outline.Transformer(source, 'cpp', str(self.owned_path), (self.header_root, other_root))
        self.assertFalse(transformer.root.has_error)
        output, report = transformer.run()
        self.assertEqual(report['cpp_header_boundary']['balanced_regions'], 1)
        self.assertEqual(transformer.shadow.origins.ranges[0]['origins'],
                         sorted(self.canonical(p) for p in (first_path, middle_path, last_path)))
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
        self.assertEqual(report['summary']['unsupported_marker_total'], 1)
        self.assert_exact_header(headers, source, output)

    def test_owned_extern_c_shell_and_namespace_survive_host_execution(self):
        header, _ = self.header('extern "C" {\nint header_api(void);\n}\n')
        declarations = ('static const char *slot="FridaOwnedSlot";\n'
                        'const char *origin_name(void){return "FridaOwnedLinkage";}\n')
        source = self.owned(self.host + '\nnamespace owned {\nextern "C" {\n') + header
        source += self.owned(declarations + '}\n}\n' + '''int main(void) {
 require(strcmp(owned::slot,%s)==0);
 require(strcmp(owned::origin_name(),%s)==0);
 require(owned::origin_name()==owned::origin_name());
 return 0;
}
''' % (c_string('FridaOwnedSlot'), c_string('FridaOwnedLinkage')))
        output, report = self.transform(source)
        self.assertTrue(report['ok'])
        self.assertEqual(report['skipped'], [])
        self.assertEqual(report['summary']['heap_buffers'], 2)
        self.assertEqual(report['static_objects'][0]['name'], '::owned::slot')
        self.assertIn(b'namespace owned {\nextern "C" {\n', output)
        self.assert_exact_header(header, source, output)
        self.compile_run(output, 'cpp')

    def test_header_bytes_are_emitted_exactly_and_owned_marker_converts(self):
        body = (b'// Frida comment: __signed__ _Nullable\r\n' +
                '/* \u5916\u90e8\u5b57\u8282\u4e0d\u5f97\u6539\u5199 */\r\n'.encode('utf-8') +
                b'namespace header_only {\r\n'
                b'static const char *label=R"tag(frida:opaque)tag";\r\n'
                b'static const unsigned char gumjs_header_source_map[]={70,114,105,100,97,0};\r\n'
                b'}\r\n')
        header, _ = self.header(body)
        source = self.owned(self.host) + header + self.owned(
            'const char *name(void){return "FridaOwnedBytes";}\n')
        transformer = outline.Transformer(source, 'cpp', str(self.owned_path), (self.header_root,))
        self.assertEqual(len(transformer.shadow.view), len(source))
        self.assertEqual([i for i, byte in enumerate(source) if byte in (10, 13)],
                         [i for i, byte in enumerate(transformer.shadow.view) if byte in (10, 13)])
        output, report = transformer.run()
        self.assert_exact_header(header, source, output)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
        self.assertEqual(report['summary']['resources_transformed'], 0)
        self.assertNotIn(b'"FridaOwnedBytes"', output)

    def test_skipped_header_origin_reports_marker_and_resource_offsets(self):
        marker = b'"Fri" "daHeaderMarker"'
        resource = b'gumjs_header_bytecode'
        header, path = self.header(b'static const char *label=' + marker + b';\n'
                                   b'static const unsigned char ' + resource + b'[]={70,114,105,100,97};\n')
        owned_marker = b'"FridaOwnedReport"'
        source = self.owned(self.host) + header + self.owned(
            b'const char *name(void){return ' + owned_marker + b';}\n')
        output, report = self.transform(source)
        skipped = [s for s in report['skipped'] if s['reason'] == 'skipped_header_origin']
        self.assertEqual({s['kind'] for s in skipped}, {'string', 'numeric-resource'})
        self.assertEqual({source[s['start_byte']:s['end_byte']] for s in skipped}, {marker, resource})
        for item in skipped:
            self.assertEqual(item['line'], source.count(b'\n', 0, item['start_byte']) + 1)
            self.assertEqual(item['column'], item['start_byte'] - source.rfind(b'\n', 0, item['start_byte']))
            self.assertIn(self.canonical(path), item['detail'])
        self.assertEqual(report['summary']['unsupported_reason_counts']['skipped_header_origin'], 2)
        self.assertEqual(report['summary']['unsupported_marker_total'], 1)
        self.assertEqual(report['summary']['unsupported_resource_total'], 1)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
        occurrence = next(o for o in report['occurrences'] if o['kind'] == 'string')
        self.assertEqual(source[occurrence['start_byte']:occurrence['end_byte']], owned_marker)
        self.assert_exact_header(header, source, output)

    def test_unknown_external_types_static_slots_are_conservative(self):
        header, _ = self.header('typedef const char *ExternalText;\n'
                                'struct ExternalRecord {const char *name;};\n')
        unknown = ('static ExternalText text="FridaExternalText";\n'
                   'static const ExternalRecord record={"FridaExternalRecord"};\n')
        source = self.owned(self.host) + header + self.owned(unknown +
            'static const char *known="FridaKnownSlot";\n'
            'const char *name(void){return "FridaKnownReturn";}\n')
        output, report = self.transform(source)
        self.assertIn(unknown.encode(), output)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 2)
        self.assertEqual(report['summary']['expected_pointer_patches'], 1)
        self.assertEqual([obj['name'] for obj in report['static_objects']], ['::known'])
        self.assertEqual({source[s['start_byte']:s['end_byte']] for s in report['skipped']},
                         {b'"FridaExternalText"', b'"FridaExternalRecord"'})
        self.assertTrue(all(s['reason'] for s in report['skipped']))
        self.assertNotIn(b'::text =', output)
        self.assertNotIn(b'::record.name =', output)

    def test_shadowed_external_typedef_and_external_static_consumers_do_not_patch(self):
        cases = (
            ('shadowed-typedef', self.host + 'typedef const char *Text;\n',
             'namespace N {typedef const char *const Text;}\n',
             'namespace N {static Text slot="frida-slot";}\n', b'"frida-slot"', '::N::slot'),
            ('external-consumer', self.host + 'static const char *slot="FridaExternalConsumer";\n',
             'static const char *saved=slot;\n', '', b'"FridaExternalConsumer"', '::slot'),
        )
        for name, before, external, after, marker, slot in cases:
            with self.subTest(case=name):
                header, _ = self.header(external)
                source = self.owned(before) + header + self.owned(after +
                    'const char *safe(void){return "FridaStillOwned";}\n')
                output, report = self.transform(source)
                self.assertIn(marker, output)
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                self.assertEqual(report['summary']['expected_pointer_patches'], 0)
                self.assertEqual(report['static_objects'], [])
                self.assertNotIn((slot + ' =').encode(), output)
                self.assertTrue(any(source[s['start_byte']:s['end_byte']] == marker and s['reason']
                                    for s in report['skipped']), report['skipped'])
                self.assert_exact_header(header, source, output)

    def test_external_resource_reference_skips_whole_resource(self):
        declaration = b'static const unsigned char gumjs_owned_bytecode[]={0,70,114,105,100,97,255};\n'
        reference = b'const unsigned char *resource(void){return gumjs_owned_bytecode;}\n'
        header, _ = self.header('inline const unsigned char *header_resource(void){return gumjs_owned_bytecode;}\n')
        source = self.owned(self.host.encode() + declaration) + header + self.owned(reference +
            b'const char *safe(void){return "FridaOwnedAfterResource";}\n')
        output, report = self.transform(source)
        self.assertIn(declaration, output)
        self.assertIn(reference, output)
        self.assert_exact_header(header, source, output)
        self.assertEqual(report['summary']['resources_transformed'], 0)
        self.assertFalse(any(e['kind'] == 'numeric-resource' for e in report['entries']))
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
        self.assertTrue(any(s['kind'] == 'numeric-resource' and s['reason'] == 'resource_reference_header_origin'
                            for s in report['skipped']), report['skipped'])

    def test_header_cannot_close_or_replace_owned_scope(self):
        for owned_scope, replacement in (('namespace owned {\n', '}\nnamespace replacement {\n'),
                                         ('extern "C" {\n', '}\nextern "C" {\n')):
            with self.subTest(scope=owned_scope):
                header, _ = self.header(replacement)
                source = self.owned(self.host + owned_scope) + header + self.owned('}\n')
                self.assert_failure(source, 'cpp_opaque_cross_origin_delimiter')

    def test_header_cannot_enter_owned_declaration_or_non_shell_scope(self):
        cases = (
            ('struct-field', 'struct S {\n', 'const char *hidden;\n',
             'const char *shown;\n};\nstatic const S value={"frida-hidden","plain"};\n'),
            ('enum-value', 'enum E {\n', 'HIDDEN=1,\n', 'SHOWN=2\n};\n'),
            ('function-body', 'const char *name(void){\n', 'const char *p="FridaHeaderLocal";\n',
             'return "FridaOwnedReturn";\n}\n'),
            ('initializer', 'static const char *names[]={\n', '"FridaHeaderElement",\n',
             '"FridaOwnedElement"\n};\n'),
        )
        for name, before, external, after in cases:
            with self.subTest(scope=name):
                header, _ = self.header(external)
                source = self.owned(self.host + before) + header + self.owned(after)
                self.assert_failure(source, ('cpp_opaque_cross_origin_declaration',
                                             'cpp_opaque_unsupported_owned_scope'))
        header, _ = self.header('namespace external {\n')
        source = self.owned(self.host) + header + self.owned(
            'const char *name(void){return "FridaCrossedNamespace";}\n}\n')
        self.assert_failure(source, 'cpp_opaque_cross_origin_delimiter')

    def test_header_cannot_cross_into_owned_declaration_without_delimiters(self):
        cases = (
            ('header-initializer', '', 'static const char *external=\n', '"FridaOwnedInitializer";\n'),
            ('owned-initializer', 'static const char *owned_slot=\n', '"FridaHeaderInitializer";\n',
             'const char *name(void){return "FridaOwnedAfter";}\n'),
            ('header-type', '', 'extern int\n', 'owned_value;\n'),
            ('owned-return-type', 'const char *\n', 'header_function(void);\n',
             'const char *name(void){return "FridaOwnedAfter";}\n'),
        )
        for name, before, external, after in cases:
            with self.subTest(case=name):
                header, _ = self.header(external)
                source = self.owned(self.host + before) + header + self.owned(after)
                self.assert_failure(source, 'cpp_opaque_cross_origin_declaration')

    def test_roots_require_real_narrow_physical_directories(self):
        not_directory = self.workspace / 'not-a-directory.hpp'
        not_directory.write_bytes(b'int value;\n')
        cases = ((self.header_root / 'missing', 'cpp_opaque_root_not_physical_directory'),
                 (not_directory, 'cpp_opaque_root_not_physical_directory'),
                 (Path('external/include'), 'cpp_opaque_root_not_physical_directory'),
                 (Path('<system-headers>'), 'cpp_opaque_root_not_physical_directory'),
                 (Path(self.workspace.anchor), 'cpp_opaque_root_too_broad'))
        source = self.owned(self.host + 'const char *name(void){return "FridaPhysicalRoots";}\n')
        for root, reason in cases:
            with self.subTest(root=str(root)):
                self.assert_failure(source, reason, roots=(root,))

    def test_explicit_roots_require_line_markers(self):
        source = (self.host + 'const char *name(void){return "FridaNoLineMarkers";}\n').encode()
        self.assert_failure(source, 'cpp_opaque_requires_line_markers')

    def test_nonphysical_and_nearby_origins_remain_owned_full_ast(self):
        bad = b'static_assert(__is_same(int, int), "header grammar");\n'
        sibling = self.header_root.parent / 'v1-other' / 'traits.hpp'
        sibling.parent.mkdir()
        sibling.write_bytes(bad)
        owned_header = self.workspace / 'owned-traits.hpp'
        owned_header.write_bytes(bad)
        origins = ('v1/traits.hpp', '<built-in>', '<nianchu-outline-generated>', sibling, owned_header)
        for origin in origins:
            with self.subTest(origin=str(origin)):
                source = self.owned(self.host) + self.line_marker(origin).encode('ascii') + bad
                source += self.owned('const char *name(void){return "FridaUnapprovedOrigin";}\n')
                self.assert_failure(source, 'input_does_not_parse')

    def test_c_policy_is_rejected_before_header_masking(self):
        header, _ = self.header('int header_declaration;\n')
        source = self.owned(GLIB_HOST) + header + self.owned(
            'const char *name(void){return "FridaCPolicy";}\n')
        self.assert_failure(source, 'cpp_opaque_policy_requires_cpp', language='c')

    def test_no_roots_full_ast_fails_closed_on_same_header_syntax(self):
        bad = b'static_assert(__is_same(int, int), "header grammar");\n'
        header, _ = self.header(bad)
        source = self.owned(self.host) + header + self.owned(
            'const char *name(void){return "FridaFullAst";}\n')
        with self.subTest(policy='no-roots'):
            report = self.assert_failure(source, 'input_does_not_parse', roots=())
            self.assertNotIn('cpp_header_boundary', report)
        with self.subTest(policy='explicit-physical-root'):
            output, report = self.transform(source)
            self.assertTrue(report['ok'])
            self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
            self.assert_exact_header(header, source, output)
        with self.subTest(policy='same-syntax-owned'):
            source = self.owned(self.host.encode() + bad) + header
            self.assert_failure(source, 'input_does_not_parse')

    def test_unknown_and_unmodeled_layout_pragmas_in_headers_are_rejected(self):
        directives = ('#pragma pack(3)\n',
                      '#pragma clang attribute push (__attribute__((packed)), apply_to=record)\n',
                      '#pragma message("frida")\n', '#pragma unknown_vendor layout\n',
                      '#define HEADER_NAME "frida"\n')
        for directive in directives:
            with self.subTest(directive=directive):
                header, _ = self.header(directive + 'int header_declaration;\n')
                source = self.owned(self.host) + header + self.owned(
                    'const char *name(void){return "FridaRejectedPragma";}\n')
                self.assert_failure(source, 'input_not_fully_preprocessed')

    def test_header_pack_state_applies_to_owned_definitions_and_restores(self):
        packed_header, _ = self.header('#pragma pack(push,1)\nint external_declaration;\n')
        pop_header, _ = self.header('#pragma pack(pop)\nint external_after;\n')
        source = self.owned(self.host) + packed_header + self.owned(
            'struct Packed {char tag;const char *name;};\n') + pop_header
        source += self.owned('struct Normal {char tag;const char *name;};\n'
            'static const Packed packed={1,"FridaHeaderPacked"};\n'
            'static const Normal normal={2,"FridaHeaderNormal"};\n'
            'int main(void){require(__builtin_offsetof(Packed,name)==1);'
            'require(__builtin_offsetof(Normal,name)==sizeof(const char *));'
            'require(packed.name[11]==\'P\' && normal.name[11]==\'N\');return 0;}\n')
        output, report = self.transform(source)
        self.assert_exact_header(packed_header, source, output)
        self.assert_exact_header(pop_header, source, output)
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
        self.assertEqual(report['summary']['expected_pointer_patches'], 1)
        self.assertEqual([s['reason'] for s in report['skipped']], ['aggregate_pragma_packing'])
        self.assertEqual(report['static_objects'][0]['name'], '::normal')
        self.assertEqual([event['effective_alignment'] for event in report['pragma_pack']['events']], [1, None])
        self.compile_run(output, 'cpp')

    def test_header_literal_and_comment_fake_directives_do_not_change_pack_or_origin(self):
        for body in ('const char *raw=R"tag(\n#pragma pack()\n#line 1 "fake-owned.cpp"\n)tag";\n',
                     '/*\n#pragma pack()\n#line 1 "fake-owned.cpp"\n*/\nint external_declaration;\n'):
            with self.subTest(header_body=body):
                header, _ = self.header(body)
                source = self.owned(self.host + '#pragma pack(push,1)\n') + header
                source += self.owned(
                    'struct Packed{char tag;const char *text;};\n'
                    'static const Packed packed={1,"FridaOpaquePacked"};\n'
                    '#pragma pack(pop)\n'
                    'struct Normal{char tag;const char *text;};\n'
                    'static const Normal normal={2,"FridaOpaqueNormal"};\n'
                    'int main(void){require(__builtin_offsetof(Packed,text)==1);'
                    'require(__builtin_offsetof(Normal,text)==sizeof(void *));'
                    'require(packed.text[0]==\'F\' && normal.text[0]==\'F\');return 0;}\n')
                transformer = outline.Transformer(source, 'cpp', str(self.owned_path), (self.header_root,))
                output, report = transformer.run()
                self.assert_exact_header(header, source, output)
                self.assertEqual([e['effective_alignment'] for e in report['pragma_pack']['events']], [1, None])
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                self.assertEqual(report['summary']['expected_pointer_patches'], 1)
                self.assertEqual([s['reason'] for s in report['skipped']], ['aggregate_pragma_packing'])
                self.assertEqual(report['static_objects'][0]['name'], '::normal')
                self.assertFalse(any(block['origin'] and 'fake-owned' in block['origin']
                                     for block in transformer.shadow.origins.blocks))
                self.compile_run(output, 'cpp')

    def test_header_fake_origin_cannot_hide_an_owned_declaration(self):
        for body in ('const char *raw=R"tag(\n#line 1 "%s"\n)tag";\n',
                     '/*\n#line 1 "%s"\n*/\n'):
            with self.subTest(body=body):
                fake_header, path = self.header('int external_declaration;\n')
                source = self.owned(self.host + (body % str(path).replace('\\', '/')))
                source += b'const char *name(void){return "FridaOwnedAfterFakeOrigin";}\n'
                source += fake_header
                output, report = self.transform(source)
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                self.assertEqual(report['skipped'], [])
                self.assertNotIn(b'"FridaOwnedAfterFakeOrigin"', output)
                self.assert_exact_header(fake_header, source, output)

    def test_header_lexical_directives_keep_comment_and_whitespace_prefixes(self):
        for prefix in ('/* prefix */ ', '\f', '\v'):
            with self.subTest(prefix=repr(prefix)):
                pack_header, _ = self.header(prefix + '#pragma pack(push,1)\nint external_declaration;\n')
                pop_header, _ = self.header(prefix + '#pragma pack(pop)\nint external_after;\n')
                source = self.owned(self.host) + pack_header
                source += self.owned('struct Packed{char tag;const char *text;};\n') + pop_header
                source += self.owned('static const Packed packed={1,"FridaLexicalPacked"};\n'
                                     'const char *name(void){return "FridaLexicalRuntime";}\n')
                output, report = self.transform(source)
                self.assert_exact_header(pack_header, source, output)
                self.assert_exact_header(pop_header, source, output)
                self.assertEqual([e['effective_alignment'] for e in report['pragma_pack']['events']], [1, None])
                self.assertEqual([s['reason'] for s in report['skipped']], ['aggregate_pragma_packing'])
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                bad_header, _ = self.header(prefix + '#define HIDDEN_MACRO 1\nint external_macro;\n')
                self.assert_failure(self.owned(self.host) + bad_header,
                                    'input_not_fully_preprocessed')

    def test_header_diagnostic_pragmas_preserve_bytes_and_owned_transform(self):
        body = ('#pragma clang diagnostic push\n'
                '#pragma clang diagnostic ignored "-Wdeprecated-declarations"\n'
                '#pragma once\n#pragma GCC system_header\n'
                'static_assert(__is_same(int, int), "header grammar");\n'
                '#pragma clang diagnostic pop\n')
        header, _ = self.header(body)
        source = self.owned(self.host) + header + self.owned(
            'const char *name(void){return "FridaDiagnosticPragma";}\n')
        output, report = self.transform(source)
        self.assertTrue(report['ok'])
        self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
        self.assert_exact_header(header, source, output)

    def test_synthetic_generated_helpers_are_owned_and_validated(self):
        header, _ = self.header('namespace trailing_header {\nint external;\n}\n')
        source = self.owned(self.host +
            'static const char *name(void){return "FridaGeneratedOwned";}\n' +
            'int main(void){require(strcmp(name(),%s)==0);return 0;}\n' % c_string('FridaGeneratedOwned')) + header
        output, report = self.transform(source)
        synthetic = b'#line 1 "<nianchu-outline-generated>"\n'
        self.assertTrue(output.startswith(synthetic))
        self.assertEqual(output.count(synthetic), 2)
        self.assert_exact_header(header, source, output)
        generated = outline.Transformer(output, 'cpp', str(self.owned_path), (self.header_root,))
        self.assertFalse(generated.root.has_error)
        getters = {entry['getter'] for entry in report['entries']}
        parsed_functions = {generated.text(node.child_by_field_name('declarator'))
                            for node in generated.nodes if node.type == 'function_definition'}
        for getter in getters:
            self.assertTrue(any(getter in declaration for declaration in parsed_functions), getter)
            start = output.index(('static const char * ' + getter + ' (void)\n{').encode())
            self.assertFalse(any(block['opaque'] and block['start'] <= start < block['end']
                                 for block in generated.shadow.origins.blocks))
        self.assertEqual(generated.shadow.origins.summary()['opaque_bytes'],
                         report['cpp_header_boundary']['opaque_bytes'] + 1)
        self.assertIn(header + b'\n' + synthetic, output)
        self.compile_run(output, 'cpp')
        original_runtime = outline.Transformer.runtime
        malformed = b'\nstatic void malformed_helper(void) { int = ; }\n'
        for location in ('prelude', 'suffix'):
            with self.subTest(corrupt=location):
                def corrupt_runtime(transformer, objects):
                    prelude, suffix = original_runtime(transformer, objects)
                    return (prelude + malformed, suffix) if location == 'prelude' else (prelude, suffix + malformed)
                with mock.patch.object(outline.Transformer, 'runtime', new=corrupt_runtime):
                    self.assert_failure(source, 'generated_source_does_not_parse')

    def test_hidden_same_name_overloads_skip_literals_and_whole_resources(self):
        external = ('namespace N {\nint pick(const char (&)[6]);\n'
                    'int pick(const unsigned char (&)[5]);\nint pick(const void *);\n}\n')
        resource = b'static const unsigned char gumjs_overload_bytecode[]={70,114,105,100,97};\n'
        cases = (('literal', b'', b'pick("frida")', 'cpp_header_origin_call_parameter'),
                 ('resource', resource, b'pick(gumjs_overload_bytecode)',
                  'resource_reference_cpp_header_origin_call_parameter'))
        for name, declaration, call, reason in cases:
            with self.subTest(argument=name):
                header, _ = self.header(external)
                source = self.owned((self.host + 'int pick(const char *);\n').encode() + declaration) + header
                source += self.owned(b'namespace N {int run(void){return ' + call + b';}}\n'
                                     b'const char *safe(void){return "FridaOverloadSafe";}\n')
                output, report = self.transform(source)
                self.assertIn(call, output)
                self.assert_exact_header(header, source, output)
                self.assertEqual(report['summary']['literal_occurrences_transformed'], 1)
                self.assertEqual(report['summary']['resources_transformed'], 0)
                self.assertTrue(any(s['reason'] == reason for s in report['skipped']), report['skipped'])
                if declaration:
                    self.assertIn(declaration, output)
                    self.assertFalse(any(e['kind'] == 'numeric-resource' for e in report['entries']))
                else:
                    self.assertIn(b'"frida"', output)


if __name__ == '__main__':
    unittest.main()
