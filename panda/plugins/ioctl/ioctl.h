#ifndef __IOCTL_H__
#define __IOCTL_H__

#include "panda/plugin.h"
#include "panda/common.h"

#include<osi/osi_types.h>
#include<osi/osi_ext.h>

#include <vector>
#include <unordered_map>
#include <unordered_set>

const int hex_width = (sizeof(target_ulong) << 1);

// https://www.kernel.org/doc/html/latest/userspace-api/ioctl/ioctl-decoding.html
// https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/ioctl.h

#if defined(TARGET_PPC)
    #define IOC_SIZE_BITS 13
    #define IOC_DIR_BITS  3
#else
    #define IOC_SIZE_BITS 14
    #define IOC_DIR_BITS  2
#endif

#define IOC_CODE_BITS 8
#define IOC_FUNC_BITS 8

static const char* ioctl_direction_strs[] {
    "IO",   // ioctl with no parameters
    "IOW",  // ioctl with read parameters  (copy_to_user)
    "IOR",  // ioctl with write parameters (copy_from_user)
    "IOWR", // ioctl with both write and read parameters
};

const char* ioctl_direction_to_str(uint32_t direction) {
    assert(direction <= 0x3);
    return ioctl_direction_strs[direction];
}

typedef struct ioctl_cmd_t {
    uint32_t direction : IOC_DIR_BITS;
    uint32_t arg_size : IOC_SIZE_BITS;
    uint32_t cmd_num : IOC_CODE_BITS;
    uint32_t type_num : IOC_FUNC_BITS;
} ioctl_cmd_t;

typedef struct ioctl_t {
    char* file_name;
    ioctl_cmd_t* cmd;
    uint64_t guest_arg_ptr;
    uint8_t* guest_arg_buf;
} ioctl_t;

void decode_ioctl_cmd(ioctl_cmd_t* cmd, uint32_t val) {
    cmd->direction  = val & ((1 << IOC_DIR_BITS) - 1);
    cmd->arg_size   = (val >> IOC_DIR_BITS) & ((1 << IOC_SIZE_BITS) - 1);
    cmd->cmd_num    = (val >> (IOC_DIR_BITS + IOC_SIZE_BITS)) & ((1 << IOC_CODE_BITS) - 1);
    cmd->type_num   = (val >> (IOC_DIR_BITS + IOC_SIZE_BITS + IOC_CODE_BITS)) & ((1 << IOC_FUNC_BITS) - 1);
}

uint32_t encode_ioctl_cmd(ioctl_cmd_t* cmd) {
    return cmd->direction
        | cmd->arg_size << IOC_DIR_BITS
        | cmd->cmd_num << (IOC_DIR_BITS + IOC_SIZE_BITS)
        | cmd->type_num << (IOC_DIR_BITS + IOC_SIZE_BITS + IOC_CODE_BITS);
}

bool operator==(const ioctl_cmd_t &cmd_1, const ioctl_cmd_t &cmd_2) {
    return (cmd_1.direction == cmd_2.direction) &&
            (cmd_1.arg_size == cmd_2.arg_size) &&
            (cmd_1.cmd_num == cmd_2.cmd_num) &&
            (cmd_1.type_num == cmd_2.type_num);
}


// Map device path strings to ioctl return hook functions
typedef std::unordered_map<std::string, std::vector<ioctl_hook_t>> NamedIoctlHooks;

// List of hooks functions to call on every ioctl return
typedef std::vector<ioctl_hook_t>> AllIoctlHooks;

// List of devices to force success for
typedef std::unordered_set<std::string> HyperSuccessDevices;

// Pair of ioctl request and corresponding response
typedef std::pair<ioctl_t*, ioctl_t*> IoctlReqRet;

// List of request/response pairs
typedef std::vector<IoctlReqRet> AllIoctls;

// Map of PID to request/response lists
typedef std::unordered_map<target_pid_t, AllIoctls> PidToAllIoctls;

// Map PID to process name
typedef std::unordered_map<target_pid_t, std::string> PidToName;

#endif // __IOCTL_H__