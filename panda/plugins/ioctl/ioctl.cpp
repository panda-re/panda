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

#include <byteswap.h>
#include <tuple>
#include <algorithm>
#include <iomanip>
#include <limits>

#include "ioctl.h"
#include "ioctl_optional_json.h"

#include "osi_linux/osi_linux_ext.h"
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

bool swap_endianness;
const char* json_fn;
PidToAllIoctls pid_to_all_ioctls;
PidToName pid_to_name;
HyperSuccessDevices hyper_success_devices;
NamedIoctlHooks named_ioctl_hooks;
AllIoctlHooks all_ioctl_hooks;

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA, which is written in C
extern "C" {
    #include "panda/plog.h"
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// VMI -----------------------------------------------------------------------------------------------------------------

// Update all IOCTLs by process
// Keying maps by PID for request/response consistency regardless of kthread context-switch/interweave
ioctl_t* update_proc_ioctl_mapping(uint32_t fd, CPUState* cpu, uint32_t cmd, uint64_t guest_arg_ptr, bool is_request) {

    if (swap_endianness) {
        cmd = bswap32(cmd);
    }

    // Command decode
    ioctl_cmd_t* new_cmd = new ioctl_cmd_t;
    decode_ioctl_cmd(new_cmd, cmd);

    // OSI book keeping
    OsiProc* proc = get_current_process(cpu);
    pid_to_name.emplace(proc->pid, proc->name);
    auto pid_entry = pid_to_all_ioctls.find(proc->pid);
    char* file_name = osi_linux_fd_to_filename(cpu, proc, fd);

    // IOCTL struct
    uint8_t* guest_arg_buf;
    if (new_cmd->arg_size) {
        guest_arg_buf = (uint8_t*)malloc(new_cmd->arg_size);
        if ((!guest_arg_buf) || panda_virtual_memory_read(cpu, guest_arg_ptr, guest_arg_buf, new_cmd->arg_size)) {
            std::cerr << "Failed to read " << new_cmd->arg_size
                << " bytes from guest 0x" << std::setw(hex_width) << guest_arg_ptr << std::endl;
        }
    } else {
        guest_arg_buf = nullptr;
    }
    ioctl_t* new_ioctl = new ioctl_t{file_name, new_cmd, guest_arg_ptr, guest_arg_buf};

    // Request - log a new pair
    if (is_request) {
        IoctlReqRet new_ioctl_req_ret = std::make_pair(new_ioctl, nullptr);
        if (pid_entry == pid_to_all_ioctls.end()) {
            pid_to_all_ioctls.emplace(proc->pid, AllIoctls{new_ioctl_req_ret});
        } else {
            pid_entry->second.push_back(new_ioctl_req_ret);
        }
    // Response - update last pair
    } else {
        assert(pid_entry != pid_to_all_ioctls.end());       // Record for process must exist
        assert(pid_entry->second.back().second == nullptr); // Process's latest pair shouldn't have a response yet
        pid_entry->second.back().second = new_ioctl;        // Log response corresponding to request
    }

    free(proc);
    return new_ioctl;
}

// Multi-arch return overwrite
void force_return(CPUState* cpu, target_ulong val) {

    #if (defined(TARGET_I386) || defined(TARGET_X86_64) || defined(TARGET_ARM) || defined(TARGET_AARCH64))
        ((CPUArchState*)cpu->env_ptr)->regs[0] = val;
    #elif defined(TARGET_MIPS)
        ((CPUArchState*)cpu->env_ptr)->regs[2] = val;
    #else
        std::cerr << "Cannot modify return value on unsupported architecture!" << std::endl;
    #endif
}

// Dispatch any registered hooks or return overwrites
void dispatch_hooks_and_overwrites(ioctl_t* ioctl) {

    // Forced success
    if (hyper_success_devices.find(new_ioctl->file_name) != hyper_success_devices.end()) {
        force_return(cpu, 0);
    }

    // Named hooks
    auto named_entry = named_ioctl_hooks.find(new_ioctl->file_name);
    if (named_entry != named_ioctl_hooks.end()) {
        for (auto &hook : named_entry->second) {
            (*hook)(cpu, ioctl);
        }
    }

    // All hooks
    for (auto &hook : all_ioctl_hooks) {
        (*hook)(cpu, ioctl);
    }
}

// CALLBACKS -----------------------------------------------------------------------------------------------------------

void linux_32_ioctl_enter(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg) {
    update_proc_ioctl_mapping(fd, cpu, cmd, (uint64_t)arg, true);
}

void linux_32_ioctl_return(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg) {
    ioctl_t* new_ioctl = update_proc_ioctl_mapping(fd, cpu, cmd, (uint64_t)arg, false);
    dispatch_hooks_and_overwrites(new_ioctl);
}

void linux_64_ioctl_enter(CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg) {
    update_proc_ioctl_mapping(fd, cpu, cmd, arg, true);
}

void linux_64_ioctl_return (CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg) {
    ioctl_t* new_ioctl = update_proc_ioctl_mapping(fd, cpu, cmd, (uint64_t)arg, false);
    dispatch_hooks_and_overwrites(new_ioctl);
}

// PANDA LOG -----------------------------------------------------------------------------------------------------------

// Entry init helper
void init_plog_ioctl(Panda__Ioctl* pli, ioctl_t* ioctl, target_pid_t pid, std::string name, bool is_request) {

    if (!pandalog) { return; }    // Pre-condition

    // TODO: these should be optional if OSI enabled
    pli->has_proc_pid = 1;
    //pli->has_proc_name = 1;
    //pli->has_file_name = 1;
    pli->proc_pid = pid;
    pli->proc_name = (char*)name.c_str();
    pli->file_name = ioctl->file_name;

    pli->data_flow = is_request;
    pli->raw_cmd = encode_ioctl_cmd(ioctl->cmd);
    pli->direction = ioctl->cmd->direction;
    pli->cmd_num = ioctl->cmd->cmd_num;
    pli->type_num = ioctl->cmd->type_num;

    if (ioctl->cmd->arg_size) {
        pli->has_guest_arg_ptr = 1;
        pli->has_guest_arg_buf = 1;
        pli->guest_arg_ptr = ioctl->guest_arg_ptr;
        pli->guest_arg_buf.data = ioctl->guest_arg_buf;
        pli->guest_arg_buf.len = ioctl->cmd->arg_size;
    } else {
        pli->has_guest_arg_ptr = 0;
        pli->has_guest_arg_buf = 0;
    }
}

// Entry alloc helper
Panda__Ioctl* alloc_plog_ioctl() {
    Panda__Ioctl* entry = (Panda__Ioctl*)malloc(sizeof(Panda__Ioctl));
    assert(entry);
    *(entry) = PANDA__IOCTL__INIT;
    return entry;
}

// Write PANDALOG
void flush_plog() {

    int recorded_ioctl_cnt = 0;
    int i = 0;

    Panda__RecordedIoctls *recorded_ioctls = (Panda__RecordedIoctls*)malloc(sizeof(Panda__RecordedIoctls));
    assert(recorded_ioctls);
    *recorded_ioctls = PANDA__RECORDED_IOCTLS__INIT;

    // Compute total captured
    for (auto const& pid_to_ioctls : pid_to_all_ioctls) {
        auto ioctl_pair_list = pid_to_ioctls.second;
        for (auto const& ioctl_pair : ioctl_pair_list) {
            assert(ioctl_pair.first);
            assert(ioctl_pair.second);
            recorded_ioctl_cnt += 2;
        }
    }

    // Allocate memory for singular array of pointers to individual ioctl captures
    Panda__Ioctl **ioctl_arr = (Panda__Ioctl**)malloc(sizeof(Panda__Ioctl*) * recorded_ioctl_cnt);
    assert(ioctl_arr);

    // Buffer data
    for (auto const& pid_to_ioctls : pid_to_all_ioctls) {

        auto pid = pid_to_ioctls.first;
        auto ioctl_pair_list = pid_to_ioctls.second;
        assert(pid_to_name.find(pid) != pid_to_name.end());
        auto name = pid_to_name.find(pid)->second;

        for (auto const& ioctl_pair : ioctl_pair_list) {
            assert((i + 1) <= recorded_ioctl_cnt);

            ioctl_arr[i] = alloc_plog_ioctl();
            ioctl_arr[i + 1] = alloc_plog_ioctl();

            init_plog_ioctl(ioctl_arr[i], ioctl_pair.first, pid, name, true);
            init_plog_ioctl(ioctl_arr[i + 1], ioctl_pair.second, pid, name, false);

            i += 2;
        }
    }

    // Write data
    recorded_ioctls->ioctls = ioctl_arr;
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.plog_ioctls = recorded_ioctls;
    pandalog_write_entry(&ple);

    // Cleanup
    for (i = 0; i < recorded_ioctl_cnt; ++i) {
        free(ioctl_arr[i]);
    }
    free(ioctl_arr);
}

// EXPORTS -------------------------------------------------------------------------------------------------------------

// Force ioctls to the device at the given path to always return success (0)
void force_success(const char* path) {
    hyper_success_devices.insert(std::string(path));
}

// Register a callback for all ioctls whose file descripter resolves to a path
void add_ioctl_hook_by_path(const char* path, ioctl_hook_t hook) {
    auto named_entry = named_ioctl_hooks.find(path);
    if (named_entry != named_ioctl_hooks.end()) {
        named_entry->second.push_back(hook);
    } else {
        named_ioctl_hooks.insert(std::string(path), {hook});
    }
}

// Register a callback for all ioctls
void add_all_ioctls_hook(ioctl_hook_t hook) {
    all_ioctl_hooks.push_back(hook);
}

// PLUGIN --------------------------------------------------------------------------------------------------------------

bool init_plugin(void* self) {

    const char* rehost_dev_path;
    panda_arg_list* panda_args_list = panda_get_args("ioctl");
    json_fn = panda_parse_string_opt(panda_args_list, "out_json", nullptr, "JSON file to log unique IOCTLs by process.");

    // TODO: this could be a list of devices to allow more than one!
    rehost_dev_path = panda_parse_string_opt(panda_args_list, "rehost_device_path", nullptr,
        "Mount point for device (e.g. \'/dev/special_device\' whose ioctls should always return success (0)");
    if (rehost_dev_path != nullptr) {
        std::cout << "Rehost toggled: all ioctls to dev " << rehost_dev_path << " will return 0" << std::endl;
    }
    hyper_success_devices.insert(std::string(rehost_dev_path));

    swap_endianness = false;

    // Setup dependencies
    panda_enable_precise_pc();
    panda_require("syscalls2");
    assert(init_syscalls2_api());
    panda_require("osi");
    assert(init_osi_api());
    panda_require("osi_linux");
    assert(init_osi_linux_api());

    #if (defined(TARGET_I386) && !defined(TARGET_X86_64)) || (defined(TARGET_ARM) && !defined(TARGET_AARCH64))
        printf("ioctl: setting up 32-bit Linux.\n");
        PPP_REG_CB("syscalls2", on_sys_ioctl_enter, linux_32_ioctl_enter);
        PPP_REG_CB("syscalls2", on_sys_ioctl_return, linux_32_ioctl_return);
        swap_endianness = true;

   #elif defined(TARGET_X86_64) || defined(TARGET_ARM)
        printf("ioctl: setting up 64-bit Linux.\n");
        PPP_REG_CB("syscalls2", on_sys_ioctl_enter, linux_64_ioctl_enter);
        PPP_REG_CB("syscalls2", on_sys_ioctl_return, linux_64_ioctl_return);
        swap_endianness = true;

    #else
        fprintf(stderr, "ERROR: Only I386/x86_64/ARM/AARCH64 Linux currently suppported!\n");
        return false;
    #endif

    return true;
}

void uninit_plugin(void *self) {
    if (json_fn) {
        flush_json(json_fn, pid_to_all_ioctls, pid_to_name);
    }

    if (pandalog){
        flush_plog();
    }

    // Cleanup globals
    for (auto const& pid_to_ioctls : pid_to_all_ioctls) {
        auto ioctl_pair_list = pid_to_ioctls.second;
        for (auto const& ioctl_pair : ioctl_pair_list) {
            free(ioctl_pair.first);
            free(ioctl_pair.second);
        }
        ioctl_pair_list.clear();
    }
    pid_to_all_ioctls.clear();
    pid_to_name.clear();
    hyper_success_devices.clear();
}