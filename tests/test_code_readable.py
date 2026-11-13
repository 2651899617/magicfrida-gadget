#!/usr/bin/env python3
"""Exercise the actual Frida16 code-readability function with permission fixtures."""
import hashlib,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REL='subprojects/frida-gum/gum/gummemory.c'
PIN='b04af3b6b0fd39cceb085f4c5934dc116059cc03509de3fd3eb72a047af111f8'
s=importlib.util.spec_from_file_location('readable_recipes',ROOT/'scripts/apply_patches.py');recipes=importlib.util.module_from_spec(s);s.loader.exec_module(recipes)
def source():
 recipe=json.loads((ROOT/'patches/16.7.19/spec.json').read_text(encoding='utf-8'));entry=next(x for x in recipe['files'] if x['path']==REL);base=(ROOT/'tests/fixtures/16.7.19'/REL).read_bytes()
 return recipe,entry,base,recipes.transform(base,entry['edits']).decode()
def body(text):
 start=text.index('void\ngum_ensure_code_readable (');end=text.index('\nvoid\ngum_mprotect (',start);return text[start:end]
HARNESS=r'''
#include <stdint.h>
#include <stddef.h>
typedef void *gpointer;typedef const void *gconstpointer;typedef size_t gsize;typedef int GumPageProtection;typedef int GHashTable;
#define HAVE_ANDROID 1
#define GUM_PAGE_READ 1
#define GUM_PAGE_WRITE 2
#define GUM_PAGE_EXECUTE 4
#define GUM_PAGE_RWX 7
#define G_LOCK(x) ((void)0)
#define G_UNLOCK(x) ((void)0)
#define GSIZE_TO_POINTER(x) ((void *)(uintptr_t)(x))
#define GPOINTER_TO_SIZE(x) ((uintptr_t)(x))
static GHashTable table,*gum_softened_code_pages;static int api=29,query_fail,change_fail;
static int protections[4],cached[4],calls,queries,last_requested;
static int index_of(gconstpointer p){return ((uintptr_t)p>>12)-1;}
static int gum_android_get_api_level(void){return api;}
static unsigned gum_query_page_size(void){return 4096;}
static GHashTable *g_hash_table_new(void*a,void*b){(void)a;(void)b;return &table;}
static int g_hash_table_contains(GHashTable*t,gconstpointer p){(void)t;return cached[index_of(p)];}
static void g_hash_table_add(GHashTable*t,gpointer p){(void)t;cached[index_of(p)]=1;}
static int gum_memory_query_protection(gconstpointer p,GumPageProtection*out){queries++;if(query_fail)return 0;*out=protections[index_of(p)];return 1;}
static int gum_try_mprotect(gpointer p,gsize n,GumPageProtection prot){(void)n;calls++;last_requested=prot;if(change_fail)return 0;protections[index_of(p)]=prot;return 1;}
@BODY@
static void reset(void){int i;for(i=0;i<4;i++){protections[i]=4;cached[i]=0;}calls=queries=last_requested=query_fail=change_fail=0;api=29;gum_softened_code_pages=0;}
int main(void){
 reset();gum_ensure_code_readable((void*)0x1000,16);if(protections[0]!=5||calls!=1||!cached[0])return 11;
 gum_ensure_code_readable((void*)0x1000,16);if(calls!=1||queries!=1)return 12;
 reset();protections[0]=5;gum_ensure_code_readable((void*)0x1000,16);if(calls!=0||protections[0]!=5)return 21;
 reset();protections[0]=6;gum_ensure_code_readable((void*)0x1000,16);if(protections[0]!=7)return 31;
 reset();protections[0]=0;gum_ensure_code_readable((void*)0x1000,16);if(protections[0]!=1)return 32;
 reset();query_fail=1;gum_ensure_code_readable((void*)0x1000,16);if(calls||cached[0]||protections[0]!=4)return 41;
 query_fail=0;gum_ensure_code_readable((void*)0x1000,16);if(protections[0]!=5||!cached[0])return 42;
 reset();change_fail=1;gum_ensure_code_readable((void*)0x1000,16);if(cached[0]||protections[0]!=4)return 51;
 change_fail=0;gum_ensure_code_readable((void*)0x1000,16);if(calls!=2||!cached[0]||protections[0]!=5)return 52;
 reset();protections[1]=6;gum_ensure_code_readable((void*)0x1ff8,16);if(protections[0]!=5||protections[1]!=7||calls!=2)return 61;
 reset();api=28;gum_ensure_code_readable((void*)0x1000,16);if(calls||queries||gum_softened_code_pages)return 71;
 return 0;
}
'''
class CodeReadableTests(unittest.TestCase):
 def test_exact_source_and_16_only(self):
  recipe,entry,base,actual=source();self.assertEqual(hashlib.sha256(base).hexdigest(),PIN);self.assertEqual(entry['upstream_sha256'],PIN);self.assertEqual(len(entry['edits']),1)
  self.assertEqual(actual.replace(entry['edits'][0]['new'],entry['edits'][0]['old']),base.decode());self.assertEqual(entry['optional'],{})
  self.assertEqual(recipes.profile_bytes(base,entry,recipe['features']),actual.encode())
  other=json.loads((ROOT/'patches/17.25.2/spec.json').read_text(encoding='utf-8'));self.assertFalse(any(x['path']==REL for x in other['files']))
 def test_native_permission_behavior_and_old_failure(self):
  cc=os.environ.get('CODE_READABLE_CC');ld=os.environ.get('CODE_READABLE_LD')
  if not cc:
   import shutil
   cc=next((shutil.which(n) for n in ('gcc','clang','cc') if shutil.which(n)),None)
  if not cc:
   if os.environ.get('STRING_OUTLINE_REQUIRE_HOST')=='1':self.fail('host compiler required for code readability regression')
   self.skipTest('host compiler unavailable')
  _,_,base,actual=source()
  with tempfile.TemporaryDirectory(prefix='gum-readable-') as temp:
   for fixed,text in ((False,base.decode()),(True,actual)):
    src=Path(temp)/('case'+str(fixed)+'.c');exe=src.with_suffix('.exe');src.write_text(HARNESS.replace('@BODY@',body(text)),encoding='utf-8')
    argv=[cc,'-std=gnu99','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function',str(src),'-o',str(exe)]
    if ld:
     obj=src.with_suffix('.obj');argv=[cc,'--target=x86_64-pc-windows-msvc','-ffreestanding','-fno-stack-protector','-mno-stack-arg-probe','-std=gnu99','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-c',str(src),'-o',str(obj)]
    built=subprocess.run(argv,capture_output=True,text=True,timeout=25);self.assertEqual(built.returncode,0,built.stdout+built.stderr)
    if ld:
     linked=subprocess.run([ld,'-flavor','link','/entry:main','/subsystem:console','/nodefaultlib','/out:'+str(exe),str(obj)],capture_output=True,text=True,timeout=15);self.assertEqual(linked.returncode,0,linked.stdout+linked.stderr)
    ran=subprocess.run([str(exe)],capture_output=True,timeout=5);self.assertEqual(ran.returncode,0 if fixed else 11)
if __name__=='__main__':unittest.main()
