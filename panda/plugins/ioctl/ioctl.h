#include "panda/plugin.h"
#include "panda/common.h"

#include <vector>
#include <unordered_map>
#include <unordered_set>

// https://www.kernel.org/doc/html/latest/userspace-api/ioctl/ioctl-decoding.html

#if defined(TARGET_PPC)
    #define IOCTL_SIZE_BITS 13
    #define IOCTL_ACCS_BITS  3
#else
    #define IOCTL_SIZE_BITS 14
    #define IOCTL_ACCS_BITS  2
#endif

#define IOCTL_CODE_BITS 8
#define IOCTL_FUNC_BITS 8

static const char* ioctl_access_strs {
    "IO",   // ioctl with no parameters
    "IOW",  // ioctl with read parameters  (copy_to_user)
    "IOR",  // ioctl with write parameters (copy_from_user)
    "IOWR", // ioctl with both write and read parameters
};

const char* ioctl_access_to_str(uint32_t access) {
    assert((0x0 <= access) && (access <= 0x3));
    return ioctl_access_strs[ia];
}

typedef struct ioctl_cmd_t {
    uint32_t access : IOCTL_ACCS_BITS,
    uint32_t arg_size : IOCTL_SIZE_BITS,
    uint32_t code : IOCTL_CODE_BITS,
    uint32_t func_num : IOCTL_FUNC_BITS,
} ioctl_cmd_t;

inline void decode_ioctl_cmd(ioctl_cmd_t* cmd, uint32_t val) {
    cmd->access     = val & ((1 << IOCTL_ACCS_BITS) - 1);
    cmd->arg_size   = (val >> IOCTL_ACCS_BITS) & ((1 << IOCTL_SIZE_BITS) - 1);
    cmd->code       = (val >> (IOCTL_ACCS_BITS + IOCTL_SIZE_BITS)) & ((1 << IOCTL_CODE_BITS) - 1);
    cmd->func_num   = (val >> (IOCTL_ACCS_BITS + IOCTL_SIZE_BITS + IOCTL_CODE_BITS)) & ((1 << IOCTL_FUNC_BITS) - 1);
}

uint32_t inline encode_ioctl_cmd(ioctl_cmd_t* cmd) {
    return cmd->access
        | cmd->arg_size << IOCTL_ACCS_BITS
        | cmd->code << (IOCTL_ACCS_BITS + IOCTL_SIZE_BITS)
        | cmd->func_num << (IOCTL_ACCS_BITS + IOCTL_SIZE_BITS + IOCTL_CODE_BITS);
}

bool operator==(const ioctl_cmd_t &cmd_1, const ioctl_cmd_t &cmd_2) {

    return (cmd_1.ioctl_type == cmd_2.ioctl_type) &&
            (cmd_1.arg_size == cmd_2.arg_size) &&
            (cmd_1.code == cmd_2.code) &&
            (cmd_1.func_num == cmd_2.func_num);
}

// TODO: implement has function for ioctl_cmd_t


typedef std::vector<ioctl_cmd_t> AllIoctls;
typedef std::unordered_set<ioctl_cmd_t> UniqueIoctls;
typedef std::unordered_map<target_ptr_t, UniqueIoctls> UniqueIoctlsByPid;
typedef std::unordered_map<target_ptr_t, AllIoctls> AllIoctlsByPid;