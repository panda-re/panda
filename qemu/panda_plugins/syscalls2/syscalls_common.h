#ifndef __SYSCALLS_COMMON_HPP
#define __SYSCALLS_COMMON_HPP

#include <functional>
#include <memory>
#include <limits>
#include <string>

extern "C" {
// get definitions of QEMU types
#include "cpu.h"

extern int panda_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);

}

enum class Callback_RC : int {
    NORMAL = 0,
    ERROR,
    INVALIDATE,
};


target_long get_return_val(CPUState *env);
target_ulong mask_retaddr_to_pc(target_ulong retaddr);
target_ulong calc_retaddr(CPUState* env, target_ulong pc) ;

target_ulong get_32 (CPUState *env, uint32_t argnum);
int32_t get_s32(CPUState *env, uint32_t argnum);
uint64_t get_64(CPUState *env, uint32_t argnum);
uint32_t get_pointer(CPUState *env, uint32_t argnum);



struct ReturnPoint {
    target_ulong ordinal;
    target_ulong retaddr;
    target_ulong proc_id;
};

typedef void (*pre_exec_callback_t)(CPUState*, target_ulong);

namespace syscalls {
    class string {
        /**
         * Magically/lazily resolves a char* to a string when initialized or accessed,
         * since from empirical data we can't rely on the data being mapped into
         * RAM before the syscall starts.
         */
    private:
        std::string data;
        target_ulong vaddr;
        CPUState* env;
        target_ulong pc;

        bool resolve() {
            // TARGET_PAGE_SIZE doesn't account for large pages, but most of QEMU doesn't anyway
            char buff[TARGET_PAGE_SIZE + 1];
            buff[TARGET_PAGE_SIZE] = 0;
            unsigned short len = TARGET_PAGE_SIZE - (vaddr &  (TARGET_PAGE_SIZE -1));
            if (len == 0) len = TARGET_PAGE_SIZE;
            do {
                // keep copying pages until the string terminates
                int ret = panda_virtual_memory_rw(env, vaddr, (uint8_t*)buff, len, 0);
                if (ret < 0) { // not mapped
                    return false;
                }
                if (strlen(buff) > len) {
                    data.append(buff, len);
                    vaddr += len;
                    len = TARGET_PAGE_SIZE;
                } else {
                    data += buff;
                    break;
                }
            } while (true);

            return true;
        }

    public:
        target_ulong get_vaddr(void) {return vaddr;}
        string(CPUState* env, target_ulong pc, target_ulong vaddr)
                : vaddr(vaddr), env(env), pc(pc) { resolve(); }
        string() : vaddr(-1), env(nullptr), pc(-1) {}
        std::string& value() {
            if(data.empty()) resolve();
            return data;
        }
    };

};

#endif
