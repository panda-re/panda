extern "C" {

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// Hook functions must be of this type
typedef void (*mem_hook_func_t)(CPUState *cpu, target_ptr_t pc, target_ulong addr, size_t size, uint8_t *buf, bool is_write, bool is_before);

struct memory_hooks_region{
    target_ulong start_address;
    target_ulong stop_address;
    bool enabled;
    bool on_before;
    bool on_after;
    bool on_read;
    bool on_write;
    mem_hook_func_t cb;
};

struct memory_hooks_region* add_mem_hook(struct memory_hooks_region* a);
void disable_mem_hooking(void);
void enable_mem_hooking(void);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

}
