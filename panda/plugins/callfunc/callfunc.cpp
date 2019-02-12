/* PANDABEGINCOMMENT
 *
 *  Authors:
 *  Brendan Dolan-Gavitt    brendandg@gatech.edu
 *  tnballo                 N/A
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include<vector>
#include<iostream>
#include<string>
#include "panda/plugin.h"
#include "panda/common.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef TARGET_ARM
#define REG_ARG_CNT 4
#define SP_REG_NUM  13
#else   // TODO: support all archs
#define REG_ARG_CNT 0
#define SP_REG_NUM  0
#endif

// TODO: Use  panda_virtual_memory_rw and incrementfor injection instead of qemu's mem map from file
std::vector<target_ulong> func_args_vec;
target_ulong when;
target_ulong target_func;
bool in_call = false;

// Parse string of delimited arguments to vector
void args_to_vec(const char *arg_list_str, std::vector<target_ulong> & out)
{
    size_t pos_start;
    size_t pos_end;
    std::string s(arg_list_str);
    std::string delim("-");
    size_t len = 0;

    out.clear();
    if (!arg_list_str) {
        return;
    }

    pos_start = 0;
    pos_end = s.find(delim);

    // 1 arg, no delim
    if (pos_end == std::string::npos) {
        out.push_back((target_ulong)std::stoul(s, nullptr, 16));
        return;
    }

    // Delimited args
    while (pos_end != std::string::npos) {
        len = (pos_end - pos_start);
        out.push_back((target_ulong)std::stoul(s.substr(pos_start, len), nullptr, 16));
        pos_start = (pos_end + delim.size());
        pos_end = s.find(delim, pos_start);
    }

    // No delim after last arg
    if (pos_start < (s.size() - 1)) {
        out.push_back((target_ulong)std::stoul(s.substr(pos_start), nullptr, 16));
    }
}

// Pass first n args via registers, remainder via stack in reverse order
void init_args(CPUState *env, int reg_arg_cnt, int sp_reg_num, const std::vector<target_ulong> & args) {
#ifdef TARGET_ARM

    CPUArchState *envp = (CPUArchState *)env->env_ptr;
    auto it = args.begin();
    target_ulong sp = envp->regs[sp_reg_num];
    target_ulong val = 0;
    int reg_max = (args.size() < reg_arg_cnt) ? args.size() : reg_arg_cnt;
    int err_ret = 0;

    // Register load initial args
    for (int i = 0; i <= reg_max; i = std::distance(args.begin(), it)) {
        val = *it;
        std::cout << std::hex << "[TEMP DEBUG] Loading 0x" << val << " in reg 0x" << i << std::endl;
        envp->regs[i] = val;
        it++;
    }

    // Stack write/push remaining args
    for (auto rev_it = --args.end(); rev_it >= it; rev_it--) {
        val = *rev_it;
        std::cout << std::hex << "[TEMP DEBUG] Pushing 0x" << val << " @ stack addr 0x" << sp << std::endl;
        err_ret = panda_virtual_memory_rw(env, sp, (uint8_t*)&val, sizeof(val), true);
        if (err_ret) {
            std::cerr << std::hex << "Failed to write 0x" << val << " @ stack addr 0x" << sp << std::endl;
        } else {
            sp += sizeof(val);
            envp->regs[sp_reg_num] = sp;
        }
    }
#endif
}

// Make a function call (arbitrary callsite, callee, params)
bool call_function(CPUState *env, TranslationBlock *tb) {
#ifdef TARGET_ARM
    CPUArchState *envp = (CPUArchState *)env->env_ptr;
    static char pre_call_state[offsetof(CPUArchState, end_reset_fields)];
    if (in_call) {
        if (tb->pc == when) {
            // print out R0 (return value)
            std::cout << std::hex << "Called function 0x" << target_func << " returned 0x" << envp->regs[0] << std::endl;
            // restore pre-call CPU state
            memcpy(envp, pre_call_state, sizeof(pre_call_state));
            in_call = false;
            return false;
        }
        else {
            return false;
        }
    }
    else {
        if (tb->pc == when) {
            in_call = true;
            // save pre-call CPU state
            memcpy(pre_call_state, envp, sizeof(pre_call_state));
            // set up args
            init_args(env, REG_ARG_CNT, SP_REG_NUM, func_args_vec);
            // set LR = when
            envp->regs[14] = when;
            // set PC = target_func
            envp->regs[15] = target_func;
            return true;
        }
        else {
            return false;
        }
    }
#else
    return false;
#endif
}

// Not handled:
//  - What if target_func tries to call "when"
//  - What about recursive calls
//  - What if when is not the start of a basic block
//  - Guest and host have opposite endianess
bool init_plugin(void* self) {

    panda_cb pcb;
    panda_arg_list* panda_args = nullptr;
    const char* func_args_str = nullptr;

    pcb.before_block_exec_invalidate_opt = call_function;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);

    panda_args = panda_get_args("callfunc");
    when = panda_parse_ulong_req(panda_args, "when", "PC at which to call our function.");
    target_func = panda_parse_ulong_req(panda_args, "func", "Function to call.");
    func_args_str = panda_parse_string_req(panda_args, "args", "Hexidecimal, dash delimited arguments for the function to call.");

    args_to_vec(func_args_str, func_args_vec);

    return true;
}

void uninit_plugin(void *self) { }