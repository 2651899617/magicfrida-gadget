#!/usr/bin/env python3
"""Exercise actual pinned Thumb LDR relocation; no device operations."""
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
ROOT=Path(__file__).resolve().parents[1]
RELATIVE='subprojects/frida-gum/gum/arch-arm/gumthumbrelocator.c'
PIN='52db2f355ddf39e347c79b8b5322cc64e9bc6a94d2564be102b3fefa8ea6da09'
spec=importlib.util.spec_from_file_location('thumb_patches',ROOT/'scripts/apply_patches.py')
patches=importlib.util.module_from_spec(spec);spec.loader.exec_module(patches)
def profile(version):
 recipe=json.loads((ROOT/'patches'/version/'spec.json').read_text(encoding='utf-8'))
 entry=next(x for x in recipe['files'] if x['path']==RELATIVE)
 base=(ROOT/'tests/fixtures'/version/RELATIVE).read_bytes()
 return recipe,entry,base,patches.transform(base,entry['edits']).decode()
def body(text):
 start=text.index('static gboolean\ngum_thumb_relocator_rewrite_ldr (GumThumbRelocator * self,\n')
 end=text.index('\nstatic gboolean\ngum_thumb_relocator_rewrite_vldr',start)
 return text[start:end]
HARNESS=r'''
typedef int gboolean;
typedef unsigned long long GumAddress;
typedef int arm_reg;
#define TRUE 1
#define FALSE 0
#define ARM_OP_MEM 1
#define ARM_OP_REG 2
#define ARM_REG_INVALID -1
#define ARM_REG_R0 0
#define ARM_REG_R1 1
#define ARM_REG_R2 2
#define ARM_REG_SP 13
#define ARM_REG_PC 15
#define g_assert_not_reached() do { failure = 99; } while (0)
typedef struct {int type,reg;struct {int base,index,disp;} mem;} cs_arm_op;
typedef struct {cs_arm_op operands[2];} Details;
typedef struct {unsigned short code[32];unsigned n;unsigned regs[16],stack[2];GumAddress literal;} Writer;
typedef struct {Details *detail;GumAddress pc;Writer *output;} GumCodeGenCtx;
typedef struct {int dummy;} GumThumbRelocator;
static int failure;
static void emit(Writer*w,unsigned x){w->code[w->n++]=(unsigned short)x;}
static void gum_thumb_writer_put_push_regs(Writer*w,int n,int a,int b){
 (void)n;
 if(a<8&&b<8)emit(w,0xb400|(1u<<a)|(1u<<b));
 else {emit(w,0xe92d);emit(w,(1u<<a)|(1u<<b));failure=1;}
 w->stack[0]=w->regs[a];w->stack[1]=w->regs[b];
}
static void gum_thumb_writer_put_ldr_reg_address(Writer*w,int r,GumAddress a){w->literal=a;emit(w,0x4801);w->regs[r]=(unsigned)a;}
static void gum_thumb_writer_put_ldr_reg_reg(Writer*w,int dst,int src){(void)src;emit(w,0x6800);w->regs[dst]=0x12345679;}
static void gum_thumb_writer_put_str_reg_reg_offset(Writer*w,int r,int base,int off){if(base!=13||off!=4)failure=2;emit(w,0x9001);w->stack[1]=w->regs[r];}
static void gum_thumb_writer_put_pop_regs(Writer*w,int n,int a,int b){(void)n;if(a!=0||b!=15)failure=3;emit(w,0xbd01);w->regs[a]=w->stack[0];w->regs[b]=w->stack[1];}
@BODY@
int main(void){
 GumThumbRelocator self={0};Details d={0};Writer w={0};GumCodeGenCtx ctx={&d,0x1007,&w};
 unsigned short expected[]={0xb403,0x4801,0x6800,0x9001,0xbd01};unsigned i;
 d.operands[0].reg=ARM_REG_PC;d.operands[1].type=ARM_OP_MEM;d.operands[1].mem.base=ARM_REG_PC;d.operands[1].mem.index=ARM_REG_INVALID;d.operands[1].mem.disp=12;
 w.regs[0]=0xaabbccdd;w.regs[1]=0x11223344;
 if(!gum_thumb_relocator_rewrite_ldr(&self,&ctx)||failure)return 10+failure;
 if(w.n!=5||w.literal!=0x1010||w.regs[0]!=0xaabbccdd||w.regs[1]!=0x11223344||w.regs[15]!=0x12345679)return 20;
 for(i=0;i<5;i++)if(w.code[i]!=expected[i])return 30;
 w.n=0;d.operands[0].reg=ARM_REG_R2;
 if(!gum_thumb_relocator_rewrite_ldr(&self,&ctx)||w.n!=2||w.regs[2]!=0x12345679)return 40;
 w.n=0;d.operands[1].mem.base=ARM_REG_R1;
 if(gum_thumb_relocator_rewrite_ldr(&self,&ctx)||w.n!=0)return 50;
 d.operands[1].mem.base=ARM_REG_PC;d.operands[1].type=ARM_OP_REG;
 if(gum_thumb_relocator_rewrite_ldr(&self,&ctx)||w.n!=0)return 60;
 return 0;
}
'''
class ThumbRelocatorTests(unittest.TestCase):
 def test_pinned_both_versions_and_all_profiles(self):
  for version in ('16.7.19','17.25.2'):
   recipe,entry,base,actual=profile(version)
   self.assertEqual(hashlib.sha256(base).hexdigest(),PIN)
   self.assertEqual(entry['upstream_sha256'],PIN)
   self.assertEqual(entry['optional'],{})
   self.assertEqual(len(entry['edits']),1)
   self.assertEqual(actual.replace(entry['edits'][0]['new'],entry['edits'][0]['old']),base.decode())
   self.assertEqual(patches.profile_bytes(base,entry,recipe['features']),actual.encode())
   self.assertNotIn('target, ARM_REG_PC);',body(actual).split('gum_thumb_writer_put_ldr_reg_address')[0])
   self.assertIn('2, target, ARM_REG_R1);',body(actual))
   self.assertIn('2, target, ARM_REG_PC);',body(actual).split('gum_thumb_writer_put_pop_regs')[1])
 def test_native_actual_function_fixed_and_old_failure(self):
  compiler=os.environ.get('THUMB_RELOCATOR_CC') or os.environ.get('STRING_OUTLINE_CC') or next((shutil.which(x) for x in ('gcc','clang','cc') if shutil.which(x)),None)
  if not compiler:
   if os.environ.get('STRING_OUTLINE_REQUIRE_HOST')=='1':self.fail('host compiler required for Thumb relocator regression')
   self.skipTest('host compiler unavailable; cloud host runs native fixture')
  with tempfile.TemporaryDirectory(prefix='thumb-relocator-') as directory:
   directory=Path(directory)
   for version in ('16.7.19','17.25.2'):
    _,_,base,actual=profile(version)
    for repaired,text in ((False,base.decode()),(True,actual)):
     source=directory/('fixture-'+version+str(repaired)+'.c');binary=source.with_suffix('.exe')
     source.write_text(HARNESS.replace('@BODY@',body(text)),encoding='utf-8')
     linker=os.environ.get('THUMB_RELOCATOR_LD')
     if linker:
      obj=source.with_suffix('.obj')
      command=[compiler,'--target=x86_64-pc-windows-msvc','-ffreestanding','-fno-stack-protector','-mno-stack-arg-probe','-O2','-std=c99','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-c',str(source),'-o',str(obj)]
     else:
      command=[compiler,'-std=c99','-Wall','-Wextra','-Werror','-Wno-unused-parameter',str(source),'-o',str(binary)]
     built=subprocess.run(command,capture_output=True,text=True,timeout=30)
     self.assertEqual(built.returncode,0,built.stdout+built.stderr)
     if linker:
      linked=subprocess.run([linker,'-flavor','link','/entry:main','/subsystem:console','/nodefaultlib','/out:'+str(binary),str(obj)],capture_output=True,text=True,timeout=20)
      self.assertEqual(linked.returncode,0,linked.stdout+linked.stderr)
     run=subprocess.run([str(binary)],capture_output=True,timeout=10)
     self.assertEqual(run.returncode,0 if repaired else 11)
if __name__=='__main__':unittest.main()
