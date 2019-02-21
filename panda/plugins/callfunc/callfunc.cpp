/* PANDABEGINCOMMENT
 *
 *  Authors:
 *  Brendan Dolan-Gavitt    brendandg@gatech.edu
 *  Tiemoko Ballo           N/A
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
#include<iomanip>
#include<fstream>
#include<string>
#include<algorithm>
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

std::vector<target_ulong> func_args_vec;
target_ulong when;
target_ulong target_func;
bool rev_push;
target_ulong mm_dst;
const char* mm_fn_str;

// Parse string of delimited arguments to vector
void args_to_vec(const char *arg_list_str, std::vector<target_ulong> & out) {

    if ((!arg_list_str)) { return; }    // Pre-condition

    size_t pos_start;
    size_t pos_end;
    std::string s(arg_list_str);
    std::string delim("-");
    size_t len = 0;

    out.clear();
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

// Pass first n args via registers, remainder via stack, optionally in reverse order
void init_args(CPUState *env, int reg_arg_cnt, int sp_reg_num, bool rev_push, const std::vector<target_ulong> & args) {
#ifdef TARGET_ARM

    if (args.empty()) { return; }   // Pre-condition

    std::vector<target_ulong> remaining_args;
    CPUArchState *envp = (CPUArchState *)env->env_ptr;
    auto it = args.begin();
    target_ulong sp = envp->regs[sp_reg_num];
    int reg_max = (args.size() < reg_arg_cnt) ? args.size() : reg_arg_cnt;
    int err_ret = 0;

    // Register load initial args
    for (int i = 0; i <= reg_max; i = std::distance(args.begin(), it)) {
        envp->regs[i] = *it;
        it++;
    }

    // Optionally reverse stack arg order
    remaining_args = {--it, args.end()};
    if (rev_push) {
        std::reverse(remaining_args.begin(), remaining_args.end());
    }

    // Stack write/push remaining args
    for (auto val : remaining_args) {
        err_ret = panda_virtual_memory_rw(env, sp, (uint8_t*)&val, sizeof(val), true);
        if (err_ret) {
            std::cerr << std::hex << "Failed to write 0x" << val << " @ stack addr 0x" << sp << std::endl;
        } else {
            sp += sizeof(val);
            //envp->regs[sp_reg_num] = sp; // Testing kernel prink() implies SP update isn't required?
        }
    }
#endif
}

// Write file contents to guest virtual memory location
void mm_file(CPUState *env, target_ulong dst, const char* fn) {

    if (!(mm_fn_str && mm_dst)) { return; } // Pre-condition

    std::ifstream data(fn, std::ios::binary);
    std::vector<char> vec_buf(std::istreambuf_iterator<char>(data), {});
    std::string s(fn);
    int err_ret;

    if (!data.good()) {
        std::cerr << "Couldn't read " << s << std::endl;
        return;
    }

    err_ret = panda_virtual_memory_rw(env, dst, (uint8_t*)vec_buf.data(), vec_buf.size(), true);
    if (err_ret) {
        std::cerr << std::hex << "Failed to write contents of " << s << " @ 0x" << dst << std::endl;
    }
}

// Make a function call (arbitrary callsite, callee, params)
bool call_function(CPUState *env, TranslationBlock *tb) {
#ifdef TARGET_ARM

    CPUArchState *envp = (CPUArchState *)env->env_ptr;
    static char pre_call_state[offsetof(CPUArchState, end_reset_fields)];
    static bool in_call = false;

    if (in_call) {

        if (tb->pc == when) {

            // print out R0 (return value)
            std::cout << std::hex << std::setw(sizeof(target_ulong) * 2)
                << "Called function 0x" << target_func << " returned 0x" << envp->regs[0] << std::endl;

            // restore pre-call CPU state
            memcpy(envp, pre_call_state, sizeof(pre_call_state));
            in_call = false;

            return false;
        } else {
            return false;
        }

    } else {

        if (tb->pc == when) {

            in_call = true;

            // save pre-call CPU state
            memcpy(pre_call_state, envp, sizeof(pre_call_state));

            // set up args (if any)
            init_args(env, REG_ARG_CNT, SP_REG_NUM, rev_push, func_args_vec);
            mm_file(env, mm_dst, mm_fn_str);

            // set LR = when
            envp->regs[14] = when;

            // set PC = target_func
            envp->regs[15] = target_func;

            return true;
        } else {
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

    // Required args
    when = panda_parse_ulong_req(panda_args, "when", "PC at which to call our function.");
    target_func = panda_parse_ulong_req(panda_args, "func", "Function to call.");

    // Optional args
    func_args_str = panda_parse_string_opt(panda_args, "args", nullptr, "Hexidecimal, dash delimited arguments for the function to call.");
    rev_push = panda_parse_bool_opt(panda_args, "rev_push", "Push stack arguments in reverse order, if any.");
    mm_fn_str = panda_parse_string_opt(panda_args, "mm_file", nullptr, "File to memory map.");
    mm_dst = panda_parse_ulong_opt(panda_args, "mm_dst", 0, "Memory location to map file.");

    if (func_args_str) {
        args_to_vec(func_args_str, func_args_vec);
    }

    if ((!mm_fn_str) != (!mm_dst)) {
        std::cerr << "Mapping a file in memory requires both \'mm_file\' and \'mm_dst\' args" << std::endl;
    }

    return true;
}

void uninit_plugin(void *self) { }