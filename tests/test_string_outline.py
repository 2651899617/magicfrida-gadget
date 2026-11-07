#!/usr/bin/env python3
"""Source AST tests plus native host compiled behavior, not binary patch tests.

CI: install the three PARSER_PINS and run unittest discovery.  GCC/Clang host
execution is required when STRING_OUTLINE_REQUIRE_HOST=1.  Optional
STRING_OUTLINE_CC and STRING_OUTLINE_CXX select already installed compilers.
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

    def compile_run(self, source, language='c', extra_flags=(), execute=True):
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
                    '-x', 'c++-cpp-output' if language == 'cpp' else 'cpp-output',
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


if __name__ == '__main__':
    unittest.main()
