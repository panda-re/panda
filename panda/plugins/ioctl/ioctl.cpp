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

#include <byteswap.h>
#include <tuple>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

bool swap_endianness;
const char* fn_str;
AllIoctlsByPid pid_to_all_ioctls;
NameByPid pid_to_name;

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// CALLBACKS -----------------------------------------------------------------------------------------------------------

// Update all IOCTLs by process
void update_proc_ioctl_mapping(uint32_t fd, CPUState* cpu, uint32_t cmd, uint64_t arg_ptr) {

    if (swap_endianness) {
        cmd = bswap32(cmd);
    }

    // Command decode
    ioctl_cmd_t* new_cmd = new ioctl_cmd_t;
    decode_ioctl_cmd(new_cmd, cmd);

    // Process name
    OsiProc* proc = get_current_process(cpu);
    pid_to_name.emplace(proc->pid, proc->name);

    // File name
    char* file_name = osi_linux_fd_to_filename(cpu, proc, fd);
    ioctl_t* new_ioctl = new ioctl_t{file_name, new_cmd, arg_ptr};

    // Log
    auto entry = pid_to_all_ioctls.find(proc->pid);
    if (entry == pid_to_all_ioctls.end()) {
        pid_to_all_ioctls.emplace(proc->pid, AllIoctls{new_ioctl});
    } else {
        entry->second.push_back(new_ioctl);
    }

    free(proc);
}

void linux_32_ioctl_enter(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg) {
    update_proc_ioctl_mapping(fd, cpu, cmd, (uint64_t)arg);
}

void linux_32_ioctl_return(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg) {
    // TODO
}

void linux_64_ioctl_enter(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg) {
    update_proc_ioctl_mapping(fd, cpu, cmd, arg);
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
        auto ioctl_list = pid_to_ioctls.second;
        assert(pid_to_name.find(pid) != pid_to_name.end());
        auto name = pid_to_name.find(pid)->second;

        for (auto const& ioctl : ioctl_list) {

            // Write log line, hacky JSON
            out_log_file
                << optional_delim
                << std::hex << std::setfill('0') << "{ "
                << "\"proc_pid\": \"" << pid << "\", "
                << "\"proc_name\": \"" << name << "\", "
                << "\"file_name\": \"" << ioctl->file_name << "\", "
                //<< "\"raw_cmd\": \"0x" << std::setw(hex_width) << encode_ioctl_cmd(ioctl->cmd) << "\", "
                << "\"type\": \""  << ioctl_type_to_str(ioctl->cmd->type) << "\", "
                << "\"code\": \"0x" << std::setw(hex_width) << ioctl->cmd->code << "\", "
                << "\"func_num\": \"0x" << std::setw(hex_width) << ioctl->cmd->func_num << "\" ";

            if (ioctl->cmd->arg_size) {

                out_log_file
                    << ", "
                    << "\"arg_ptr\": \"0x" << std::setw(hex_width) << ioctl->arg_ptr << "\", "
                    << "\"arg_size\": \"0x" << std::setw(hex_width) << ioctl->cmd->arg_size << "\" "
                    << "}";

            } else {

                out_log_file
                    << "}";

            }

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
    panda_require("osi_linux");
    assert(init_osi_linux_api());

    // TODO: ARM support
    swap_endianness = false;
    #if defined(TARGET_I386) && !defined(TARGET_X86_64)
        printf("ioctl: setting up 32-bit Linux.\n");
        PPP_REG_CB("syscalls2", on_sys_ioctl_enter, linux_32_ioctl_enter);
        PPP_REG_CB("syscalls2", on_sys_ioctl_return, linux_32_ioctl_return);
        swap_endianness = true;

   #elif defined(TARGET_X86_64)
        printf("ioctl: setting up 64-bit Linux.\n");
        PPP_REG_CB("syscalls2", on_sys_ioctl_enter, linux_64_ioctl_enter);
        PPP_REG_CB("syscalls2", on_sys_ioctl_return, linux_64_ioctl_return);
        swap_endianness = true;

    #else
        fprintf(stderr, "ERROR: Only x86 Linux currently suppported!\n");
        return false;
    #endif

    return true;
}

void uninit_plugin(void *self) {
    flush_to_ioctl_log_file();
}