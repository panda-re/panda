
#ifndef __MEM_HOOKS_INT_FNS_H__
#define __MEM_HOOKS_INT_FNS_H__

extern "C" {

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.


struct memory_hooks_region;
struct memory_access_desc {
    target_ptr_t pc;
    target_ulong addr;
    size_t size;
    uint8_t* buf;
    bool on_before;
    bool on_after;
    bool on_read;
    bool on_write;
    bool on_virtual;
    bool on_physical;
    struct memory_hooks_region* hook;
};
// Hook functions must be of this type
typedef void (*mem_hook_func_t)(CPUState *cpu, struct memory_access_desc* mad);
struct memory_hooks_region{
    target_ulong start_address;
    target_ulong stop_address;
    bool enabled;
    bool on_before;
    bool on_after;
    bool on_read;
    bool on_write;
    bool on_virtual;
    bool on_physical;
    mem_hook_func_t cb;
};

struct memory_hooks_region* add_mem_hook(struct memory_hooks_region* a);
void disable_mem_hooking(void);
void enable_mem_hooking(void);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

}

#endif
