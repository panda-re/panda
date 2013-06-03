/* PANDABEGINCOMMENT PANDAENDCOMMENT */
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

bool init_plugin(void *);
void uninit_plugin(void *);

// This is where we'll write u the syscall data
FILE *plugin_log;

// Check if the instruction is sysenter (0F 34)
bool translate_callback(CPUState *env, target_ulong pc) {
    unsigned char buf[2];
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
    if (buf[0] == 0x0F && buf[1] == 0x34)
        return true;
    else
        return false;
}

bool arm_translate_callback(CPUState* env, target_ulong pc) {
    unsigned char buf[4];
    panda_virtual_memory_rw(env, pc, buf, 4, 0);
    // Check for ARM mode syscall
    if(env->thumb == 0){
    // little-endian
	if(buf[3] & 0xF){
	    return true;
	}
    } else { 
    // check for Thumb mode syscall
      if (buf[1] == 0xDF)
	return true;
    }
    return false;
}

#include <stack>
#include <unordered_map>
//std::map<target_ulong, std::stack<target_ulong>> callstacks;
// Stacks don't let us read their contents
#include <vector>
std::unordered_map<target_ulong, std::vector<target_ulong>> callstacks;
#include <algorithm>

#include <cstdlib>
template<class T>
static bool near(T p1, T p2, T threshold){
    if(p1 > p2) 
        return abs(p1 - p2) < threshold;
    return abs(p2 - p1) < threshold;
    
}
/* check for llvm pc*/
int block_find_PC(CPUState *env, TranslationBlock *tb){
  /* Keep track of the PCs we've seen.
     This will totally excise records of recursion.
     If the PC of the last block was near the PC of this block, cull it.
     If we've seen the PC a long time ago, lose all in between. We may have lots of dumb jumps in there.
     */
    auto astack = callstacks[env->cr[3]];
    /*Case 1: stack is empty*/
    if(astack.empty()){
        astack.push_back(tb->pc);
    }
    /*Case 2: last element of stack looks to be in the current fun ction */
    else if (near(astack.back(), tb->pc, 500)){
        astack.back() = tb->pc;
    }
    /*Case 3: We've seen this PC before in the stack. we returned!*/
    else {
        auto firsthit = std::find_if(astack.crbegin(), astack.crend(),
            [&tb](target_ulong oldpc) -> bool{
                return near(oldpc, tb->pc, 500);
        });
        if (firsthit != astack.crend()){ 
            // We have found something
            astack.erase(firsthit, astack.end());
        }
        // do this whether or not we found one to replace
        astack.push_back(tb->pc);
        /*while(!astack.empty()){
            auto val = astack.top();
            astack.pop();
            if(val==tb->pc)
                break;
        } */
    }
    return 0;
    
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    // On Windows, the system call id is in EAX
    fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx "\n", pc, env->regs[R_EAX]);
#endif
    return 0;
}

bool init_plugin(void *self) {
// Don't bother if we're not on x86
#if  defined(TARGET_I386) || defined(TARGET_ARM)
    panda_cb pcb;

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
#endif

    plugin_log = fopen("syscalls.txt", "w");    
    if(!plugin_log) return false;
    else return true;
}

void uninit_plugin(void *self) {
    fflush(plugin_log);
    fclose(plugin_log);
}
