#ifndef __SYSCALLS_HPP
#define __SYSCALLS_HPP

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

typedef target_ulong target_asid;

target_asid get_asid(CPUState *env, target_ulong addr);
target_long get_return_val(CPUState *env);

static inline target_ulong mask_retaddr_to_pc(target_ulong retaddr){
    target_ulong mask = std::numeric_limits<target_ulong>::max() -1;
    return retaddr & mask;
}

static target_ulong calc_retaddr(CPUState* env, target_ulong pc){
#if defined(TARGET_ARM)
    // Normal syscalls: return addr is stored in LR
    // Except that we haven't run the SWI instruction yet! LR is where libc will return to!
    //return mask_retaddr_to_pc(env->regs[14]);

    // Fork, exec
    uint8_t offset = 0;
    if(env->thumb == 0){
        offset = 4;
    } else {
        offset = 2;
    }
    return mask_retaddr_to_pc(pc + offset);
#elif defined(TARGET_I386)
    // syscall and sysenter x86 instructions are both 2 bytes
    // on linux this is true. different for different systems.
    return pc+11;

    /*// ABI from http://wiki.osdev.org/SYSENTER
    // Return address is set by user code before the syscall/sysenter instr is executed
    unsigned char buf[2];
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
    // Check if the instruction is syscall (0F 05)
    if (buf[0]== 0x0F && buf[1] == 0x05) {
        return ECX;
    }
    // Check if the instruction is sysenter (0F 34)
    else if (buf[0]== 0x0F && buf[1] == 0x34) {
        return EDX;
    }
    else {
        // Not a syscall or sysenter!?
        assert(0);
    }*/
#else
#error "return address calculation not implemented for this architecture in fdtracker"
#endif
}

class CallbackData {
public:
    virtual ~CallbackData() { }
};

//ReturnPoints contain a contuation that does something

typedef std::unique_ptr<CallbackData> CallbackDataPtr;

static CallbackDataPtr make_callbackptr(CallbackData* data){
    return CallbackDataPtr(data);
}

static Callback_RC null_callback(CallbackData*, CPUState*, target_asid){
    return Callback_RC::NORMAL;
}

struct ReturnPoint {
    ReturnPoint() = delete;
    ReturnPoint(target_ulong retaddr, target_asid process_id,
                CallbackData* data = nullptr,
                std::function<Callback_RC(CallbackData*, CPUState*, target_asid)> callback = null_callback){
        this->retaddr = retaddr;
        this->process_id = process_id;
        opaque = make_callbackptr(data);
        this->callback = callback;
    }
    target_ulong retaddr;
    target_asid process_id;
    CallbackDataPtr opaque;
    std::function<Callback_RC(CallbackData*, CPUState*, target_asid)> callback;
};

void appendReturnPoint(ReturnPoint&& rp);

void registerExecPreCallback(std::function<void(CPUState*, target_ulong)> callback);

extern void* syscalls_plugin_self;

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
        bool resolve();
    public:
        target_ulong get_vaddr(void) {return vaddr;}
        string(CPUState* env, target_ulong pc, target_ulong vaddr);
        string() : vaddr(-1), env(nullptr), pc(-1) {}
        std::string& value();
    };

};

#endif
