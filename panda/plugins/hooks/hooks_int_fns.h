extern "C" {

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

    // Hook functions must be of this type
    typedef bool (*hook_func_t)(CPUState *, TranslationBlock *);

    void add_hook(target_ulong addr, hook_func_t hook);
    void add_hook_asid(target_ulong addr, hook_func_t hook, target_ulong cr3);
    void update_hook(hook_func_t hook, target_ulong value);
    void update_hook_asid(hook_func_t hook, target_ulong value, target_ulong asid);
    void enable_hook(hook_func_t hook, target_ulong value);
    void disable_hook(hook_func_t hook);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

}
