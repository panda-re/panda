/* PANDABEGINCOMMENT
 *
 *  Authors:
 *  Tiemoko Ballo           N/A
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "ioctl.h"

#include "osi_linux/osi_linux_ext.h"
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include <tuple>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

const char* fn_str;
AllIoctlsByPid pid_to_all_ioctls;
NameByPid pid_to_name;

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// CALLBACKS -----------------------------------------------------------------------------------------------------------

INLINE void update_proc_ioctl_mapping(CPUState* cpu, uint32_t cmd, uint64_t arg_ptr) {

    ioctl_cmd_t* new_ioc_cmd = new ioctl_cmd_t;
    decode_ioctl_cmd(new_ioc_cmd, cmd);

    // Update all IOCTLs by process
    OsiProc* proc = get_current_process(cpu);
    pid_to_name.emplace(proc->pid, proc->name);

    auto entry = pid_to_all_ioctls.find(proc->pid);
    if (entry == pid_to_all_ioctls.end()) {
        pid_to_all_ioctls.emplace(proc->pid, AllIoctls{Ioctl{new_ioc_cmd, arg_ptr}});
    } else {
        entry->second.push_back(Ioctl{new_ioc_cmd, arg_ptr});
    }
}

void linux_32_ioctl_enter(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg) {
    update_proc_ioctl_mapping(cpu, cmd, (uint64_t)arg);
}

void linux_32_ioctl_return(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg) {
    // TODO
}

void linux_64_ioctl_enter(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg) {
    update_proc_ioctl_mapping(cpu, cmd, arg);
}

void linux_64_ioctl_return (CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg) {
    // TODO
}

// FILE I/O ------------------------------------------------------------------------------------------------------------

// File I/O inside of a callback would be horridly slow, so we delay log flush until uninit_plugin()
void flush_to_ioctl_log_file() {

    if (!fn_str) { return; }    // Pre-condition

    std::ofstream out_log_file(fn_str);
    int hex_width = (sizeof(target_ulong) << 1);
    auto delim = ",\n";
    auto optional_delim = "";

    out_log_file << "[" << std::endl;

    printf("ioctl: dumping log for %lu processes to %s\n", pid_to_all_ioctls.size(), fn_str);
    for (auto const& pid_to_ioctls : pid_to_all_ioctls) {

        auto pid = pid_to_ioctls.first;
        auto ioctls = pid_to_ioctls.second;
        assert(pid_to_name.find(pid) != pid_to_name.end());
        auto name = pid_to_name.find(pid)->second;

        for (auto const& request : ioctls) {

            auto ioctl = request.first;
            auto arg_ptr = request.second;

            // Write log line, hacky JSON
            out_log_file
                << optional_delim
                << std::hex << std::setfill('0') << "{ "
                << "\"proc_pid\": \"" << pid << "\", "
                << "\"proc_name\": \"" << name << "\", "
                //<< "\"raw_cmd\": \"0x" << std::setw(hex_width) << encode_ioctl_cmd(ioctl) << "\", "
                << "\"type\": \""  << ioctl_type_to_str(ioctl->type) << "\", "
                << "\"arg_size\": \"0x" << std::setw(hex_width) << ioctl->arg_size << "\", "
                << "\"code\": \"0x" << std::setw(hex_width) << ioctl->code << "\", "
                << "\"func_num\": \"0x" << std::setw(hex_width) << ioctl->func_num << "\", "
                << "\"arg_ptr\": \"0x" << std::setw(hex_width) << arg_ptr
                << " }";

            // Validate write
            if (!out_log_file.good()) {
                std::cerr << "Error writing to " << fn_str << std::endl;
                return;
            }

            optional_delim = delim;
        }
    }

    out_log_file << std::endl << "]" << std::endl;
    out_log_file.close();
}

// EXPORTS -------------------------------------------------------------------------------------------------------------

// TODO Decode

// TODO Command callbacks

// PLUGIN --------------------------------------------------------------------------------------------------------------

bool init_plugin(void* self) {

    //panda_cb pcb;
    panda_arg_list* panda_args = panda_get_args("ioctl");

    fn_str = panda_parse_string_opt(panda_args, "out_log", nullptr, "JSON file to log unique IOCTLs by process.");
    if (!fn_str) {
        std::cerr << "No \'out_log\' specified, unique IOCTLs py process will not be logged!" << std::endl;
    }

    // Setup dependencies
    panda_enable_precise_pc();
    panda_require("syscalls2");
    assert(init_syscalls2_api());
    panda_require("osi");
    assert(init_osi_api());

    // TODO: ARM support
    #if defined(TARGET_I386) && !defined(TARGET_X86_64)
        printf("ioctl: setting up 32-bit Linux.\n");
        PPP_REG_CB("syscalls2", on_sys_ioctl_enter, linux_32_ioctl_enter);
        PPP_REG_CB("syscalls2", on_sys_ioctl_return, linux_32_ioctl_return);

   #elif defined(TARGET_X86_64)
        printf("ioctl: setting up 64-bit Linux.\n");
        PPP_REG_CB("syscalls2", on_sys_ioctl_enter, linux_64_ioctl_enter);
        PPP_REG_CB("syscalls2", on_sys_ioctl_return, linux_64_ioctl_return);

    #else
        fprintf(stderr, "ERROR: Only x86 Linux currently suppported!\n");
        return false;
    #endif

    return true;
}

void uninit_plugin(void *self) {
    flush_to_ioctl_log_file();
}