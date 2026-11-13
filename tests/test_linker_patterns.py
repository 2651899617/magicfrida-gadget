#!/usr/bin/env python3
"""Check linker pattern spelling against the actual pinned Gum hex parser."""
import hashlib, importlib.util, json, os, re, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REL='subprojects/frida-gum/gum/backend-linux/gumandroid.c'
PIN='4a48a4b32cd93335440cc5c05e01ee93ea877b15ab5da0e7ee04d783a8f81dcd'
s=importlib.util.spec_from_file_location('linker_recipes',ROOT/'scripts/apply_patches.py')
recipes=importlib.util.module_from_spec(s);s.loader.exec_module(recipes)
ARRAYS=['gum_dlopen_signatures_api245','gum_dlopen_signatures_api26p','gum_dlsym_signatures_api26p']
def patterns(text):
    out=[]
    for name in ARRAYS:
        block=text.split('static const GumFunctionSignature '+name+'[]',1)[1].split('\n};',1)[0]
        block=block.split('#ifdef HAVE_ARM64',1)[1].split('#endif',1)[0]
        out.append(''.join(json.loads('"'+x+'"') for x in re.findall(r'"([^"\n]*)"',block)))
    return out
HARNESS=r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef char gchar; typedef int gint; typedef int gboolean; typedef unsigned char guint8;
#define FALSE 0
#define TRUE 1
#define GUM_MATCH_EXACT 1
#define GUM_MATCH_WILDCARD 2
#define GUM_MATCH_MASK 3
typedef struct {int type; unsigned char value,mask;} Entry;
typedef struct {int type;} GumMatchToken;
typedef struct {int count;Entry entries[512];GumMatchToken tokens[512];int token_count;} GumMatchPattern;
static GumMatchPattern *active;
static char *copy_part(const char*p,size_t n){char*r=malloc(n+1);memcpy(r,p,n);r[n]=0;return r;}
static gchar **g_strsplit(const char*s,const char*sep,int max){char**r=calloc(3,sizeof(char*));const char*p=strchr(s,sep[0]);(void)max;r[0]=copy_part(s,p?(size_t)(p-s):strlen(s));if(p)r[1]=copy_part(p+1,strlen(p+1));return r;}
static void g_strfreev(char**s){int i;for(i=0;s[i];i++)free(s[i]);free(s);}
static int g_ascii_xdigit_value(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static GumMatchPattern *gum_match_pattern_new(void){active=calloc(1,sizeof(*active));return active;}
static GumMatchToken *gum_match_pattern_push_token(GumMatchPattern*p,int type){GumMatchToken*t=&p->tokens[p->token_count++];t->type=type;return t;}
static void gum_match_token_append_with_mask(GumMatchToken*t,guint8 v,int mask){Entry*e=&active->entries[active->count++];e->type=t->type;e->value=v;e->mask=mask;}
static void gum_match_token_append(GumMatchToken*t,guint8 v){gum_match_token_append_with_mask(t,v,t->type==GUM_MATCH_WILDCARD?0:255);}
static int gum_match_pattern_seal(GumMatchPattern*p){return p->count>0;}
static void gum_match_pattern_unref(GumMatchPattern*p){free(p);}
@PARSER@
int main(void){
 const char *old[]={@OLD@};const char *fixed[]={@NEW@};int i;
 for(i=0;i<3;i++){GumMatchPattern*a=gum_match_pattern_new_from_hexstring(old[i]);GumMatchPattern*b=gum_match_pattern_new_from_hexstring(fixed[i]);if(!a||!b)return 10+i;if(a->count!=b->count||a->token_count!=b->token_count||memcmp(a->entries,b->entries,a->count*sizeof(Entry)))return 20+i;printf("%d %d %d\n",i,a->count,a->token_count);free(a);free(b);}
 return 0;
}
'''
class LinkerPatternTests(unittest.TestCase):
    def source(self):
        spec=json.loads((ROOT/'patches/16.7.19/spec.json').read_text())
        entry=next(x for x in spec['files'] if x['path']==REL)
        raw=(ROOT/'tests/fixtures/16.7.19'/REL).read_bytes()
        return spec,entry,raw,recipes.transform(raw,entry['edits'])
    def test_only_three_spelling_bytes_and_16_only(self):
        spec,entry,raw,fixed=self.source()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),PIN)
        self.assertEqual(entry['upstream_sha256'],PIN)
        self.assertEqual(len(entry['edits']),3)
        self.assertEqual(len(raw),len(fixed))
        diffs=[(a,b) for a,b in zip(raw,fixed) if a!=b]
        self.assertEqual(diffs,[(ord('f'),ord('F'))]*3)
        self.assertEqual(entry['optional'],{})
        self.assertEqual(recipes.profile_bytes(raw,entry,recipes.selected_features(spec)),fixed)
        other=json.loads((ROOT/'patches/17.25.2/spec.json').read_text())
        self.assertFalse(any(x['path']==REL for x in other['files']))
    def test_old_literal_needles_absent_and_patterns_equivalent(self):
        _,_,raw,fixed=self.source()
        before,after=patterns(raw.decode()),patterns(fixed.decode())
        for old,new in zip(before,after):
            self.assertEqual(old.lower(),new.lower())
            self.assertNotIn(old.strip(),new)
            self.assertEqual(old[1:],new[1:])
            self.assertEqual((old[0],new[0]),('f','F'))
    def test_actual_gum_parser_preserves_tokens_masks_and_order(self):
        _,_,raw,fixed=self.source()
        memory=(ROOT/'tests/fixtures/16.7.19/subprojects/frida-gum/gum/gummemory.c').read_text()
        start=memory.index('static GumMatchPattern *\ngum_match_pattern_new_from_hexstring (const gchar * match_combined_str)\n{')
        end=memory.index('\nstatic GumMatchPattern *\ngum_match_pattern_new_from_regex',start)
        parser=memory[start:end]
        self.assertIn('g_ascii_xdigit_value (ch[0])',parser)
        self.assertIn('g_ascii_xdigit_value (ch[1])',parser)
        self.assertIn('mask &= 0x0f',parser)
        harness=HARNESS.replace('@PARSER@',parser).replace('@OLD@',','.join(json.dumps(x) for x in patterns(raw.decode()))).replace('@NEW@',','.join(json.dumps(x) for x in patterns(fixed.decode())))
        cc=os.environ.get('CODE_READABLE_CC')
        if not cc:
            import shutil
            cc=shutil.which('gcc') or shutil.which('clang')
        if not cc:
            self.skipTest('host compiler unavailable')
        with tempfile.TemporaryDirectory(prefix='gum-linker-') as tmp:
            source=Path(tmp)/'patterns.c';exe=Path(tmp)/'patterns.exe'
            source.write_text(harness,encoding='utf-8')
            built=subprocess.run([cc,'-std=gnu99','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(exe)],capture_output=True,text=True,timeout=25)
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            ran=subprocess.run([str(exe)],capture_output=True,text=True,timeout=5)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertEqual(len(ran.stdout.splitlines()),3)
if __name__=='__main__':unittest.main()
