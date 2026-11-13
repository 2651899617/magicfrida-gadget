#!/usr/bin/env python3
"""Execute the pinned maps iterator across short reads and complete-line boundaries."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
REL='subprojects/frida-gum/gum/backend-linux/gumprocess-linux.c'
PIN='7a9f4120eb724d2611a558ddd91db9dabc69e3c82c2ee937111291ce7ac0e935'
s=importlib.util.spec_from_file_location('maps_recipes',ROOT/'scripts/apply_patches.py');recipes=importlib.util.module_from_spec(s);s.loader.exec_module(recipes)
def source():
    spec=json.loads((ROOT/'patches/16.7.19/spec.json').read_text(encoding='utf-8'))
    entry=next(x for x in spec['files'] if x['path']==REL)
    base=(ROOT/'tests/fixtures/16.7.19'/REL).read_bytes()
    return spec,entry,base,recipes.profile_bytes(base,entry,recipes.selected_features(spec))
def body(text):
    start=text.index('gboolean\ngum_proc_maps_iter_next (');end=text.index('\n}',start)+2
    return text[start:end]
HARNESS=r'''
#include <stddef.h>
#include <string.h>
typedef char gchar;typedef unsigned guint;typedef int gboolean;typedef ptrdiff_t gssize;
#define TRUE 1
#define FALSE 0
#define GUM_TEMP_FAILURE_RETRY(x) (x)
typedef struct {int fd;char buffer[8193];char *read_cursor,*write_cursor;} GumProcMapsIter;
static const char *data;static size_t cursor,chunk,reads;static int fail_read;
static gssize gum_libc_read(int fd,void*out,size_t n){size_t left=strlen(data)-cursor;(void)fd;reads++;if(fail_read)return -1;if(n>left)n=left;if(chunk&&n>chunk)n=chunk;memcpy(out,data+cursor,n);cursor+=n;return n;}
@BODY@
static void setup(GumProcMapsIter*it,const char*input,size_t limit){memset(it,0,sizeof(*it));it->fd=1;it->read_cursor=it->write_cursor=it->buffer;data=input;cursor=0;chunk=limit;reads=fail_read=0;}
static const char first[]="79510000-79511000 rw-p 00001000 00:00 0 /data/app/pkg/lib/arm64/libexec.so";
static const char pair[]="79510000-79511000 rw-p 00001000 00:00 0 /data/app/pkg/lib/arm64/libexec.so\n79511000-79512000 r-xp 00000000 00:00 0\n";
int main(void){GumProcMapsIter it;const char*line=NULL;size_t limits[]={0,1,20,75};unsigned i;char longline[8200],boundary[8193];
 for(i=0;i<4;i++){setup(&it,pair,limits[i]);if(!gum_proc_maps_iter_next(&it,&line)||strcmp(line,first))return 11;if(!gum_proc_maps_iter_next(&it,&line)||strcmp(line,"79511000-79512000 r-xp 00000000 00:00 0"))return 12;if(gum_proc_maps_iter_next(&it,&line))return 13;if(reads>strlen(pair)+2)return 14;}
 setup(&it,"",1);if(gum_proc_maps_iter_next(&it,&line))return 21;
 setup(&it,first,20);if(gum_proc_maps_iter_next(&it,&line))return 22;
 setup(&it,pair,20);fail_read=1;if(gum_proc_maps_iter_next(&it,&line)||reads!=1)return 23;
 setup(&it,pair,20);it.fd=-1;if(gum_proc_maps_iter_next(&it,&line)||reads)return 24;
 memset(longline,'a',sizeof(longline)-2);longline[sizeof(longline)-2]='\n';longline[sizeof(longline)-1]=0;setup(&it,longline,20);if(gum_proc_maps_iter_next(&it,&line)||reads>500)return 31;
 memset(boundary,'a',8191);boundary[8191]='\n';boundary[8192]=0;setup(&it,boundary,20);if(!gum_proc_maps_iter_next(&it,&line)||strlen(line)!=8191)return 32;if(gum_proc_maps_iter_next(&it,&line))return 33;
 return 0;}
'''
class ProcMapsReadTests(unittest.TestCase):
    def test_exact_source_16_only_and_no_filter(self):
        spec,entry,base,actual=source()
        self.assertEqual(hashlib.sha256(base).hexdigest(),PIN);self.assertEqual(entry['upstream_sha256'],PIN)
        self.assertEqual(len(entry['edits']),1);self.assertEqual(entry['optional'],{})
        self.assertEqual(actual.decode().replace(entry['edits'][0]['new'],entry['edits'][0]['old']),base.decode())
        self.assertNotIn('nianchu',actual.decode())
        other=json.loads((ROOT/'patches/17.25.2/spec.json').read_text(encoding='utf-8'))
        self.assertFalse(any(x['path']==REL for x in other['files']))
    def test_actual_function_native_short_reads_and_old_failure(self):
        cc=os.environ.get('STRING_OUTLINE_CC') or shutil.which('gcc') or shutil.which('clang')
        if not cc:
            if os.environ.get('STRING_OUTLINE_REQUIRE_HOST')=='1':self.fail('host C compiler required for maps reader regression')
            self.skipTest('host compiler unavailable')
        _,_,base,actual=source()
        with tempfile.TemporaryDirectory(prefix='gum-maps-') as temp:
            for fixed,text in ((False,base.decode()),(True,actual.decode())):
                src=Path(temp)/('case'+str(fixed)+'.c');exe=src.with_suffix('.exe')
                src.write_text(HARNESS.replace('@BODY@',body(text)),encoding='utf-8')
                ran=subprocess.run([cc,'-std=gnu99','-O2','-Wall','-Wextra','-Werror',str(src),'-o',str(exe)],capture_output=True,timeout=25)
                self.assertEqual(ran.returncode,0,(ran.stdout+ran.stderr).decode(errors='replace'))
                ran=subprocess.run([str(exe)],capture_output=True,timeout=5)
                if fixed:self.assertEqual(ran.returncode,0)
                else:self.assertNotEqual(ran.returncode,0)
if __name__=='__main__':unittest.main()
