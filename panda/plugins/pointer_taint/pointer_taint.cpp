
#define __STDC_FORMAT_MACROS


#include <map>


#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif


#include "panda/plugin.h"
#include "panda/plugin_plugin.h"


#include "callstack_instr/callstack_instr.h"

extern "C" {
#include "callstack_instr/callstack_instr_ext.h"
bool init_plugin(void *);
void uninit_plugin(void *);
}


csh cs_handle_32;
csh cs_handle_64;

std::map<target_ulong, unsigned int> pc_to_mnemonic;

int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
  static unsigned char *buf = NULL;
  static buf_len = 0;
  if (buf == NULL) {
    buf_len = 256;
    buf = (unsigned char *) malloc(buf_len);
  }
  if (buf_len < tb->size) {
    buf_len = 2 * tb->size;
    buf = (unsigned char *) realloc(buf, buf_len);
  }
  assert(buf);
  panda_virtual_memory_read(ENV_GET_CPU(env), tb->pc, buf, tb->size);

  cs_insn *start;
  cs_insn *end;
  size_t count = cs_disasm(handle, buf, size, pc, 0, &start);
  if (count <= 0) goto done2;

  i_pc = tb->pc;
  for (cs_insn *i = start; i != end; i++) {
    pc_to_mnemonic[i_pc] = i->id;
    i_pc += i->size;
  }

  return 1;    
}




uint32_t label_num = 1;

// pc_func - of the function we are returning from
void label_pointer(CPUState *cpu, target_ulong pc_func) {
  // we are about to execute a bb that is return addr for
  // call site that is pc_func.

  // assume EAX contains a return value
  target_ulong ptr = ((CPUArchState*)cpu->env_ptr)->regs[R_EAX];

  if (ptr > 0x7800000) {
    // probably a ptr
    target_ulong pc = panda_current_pc(cpu);
    for (uint32_t i=0; i<4; i++) 
      taint2_label_reg(R_EAX, i, label_num);
    label_num ++;
  }  
}


void taint_change(Addr a, size_t sz) {
  uint32_t num_tainted = 0;
  uinr32_t num_unique_labels = std::set<uint32_t>();
  for (uint32_t i=0; i<sz) {
    a.off = i;
    num_tainted += (taint2_query(a) != 0);
  }
  if (num_tainted > 0) {
    
  }
}

bool init_plugin(void *self) {

  
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#elif defined(TARGET_X86_64)
    printf ("pointer_taint: X64 not supported\n");
    return false;
#elif defined(TARGET_ARM)
    printf ("pointer_taint: ARM not supported\n");
    return false;
#elif defined(TARGET_PPC)
    printf ("pointer_taint: PPC not supported\n");
    return false;
#endif
  
  
    panda_require("callstack_instr");
    assert(init_callstack_instr_api());
    //    panda_enable_memcb();
    PPP_REG_CB("callstack_instr", on_ret, label_pointer);

    panda_cb pcb;

    panda_enable_precise_pc();

    pcb.after_block_translate = get_instr_types;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    return true;
}


void uninit_plugin(void *self) {
}
