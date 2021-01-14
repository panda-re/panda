extern "C" {

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

    #define MAX_PROCNAME_LENGTH 256
    struct hook;

    // Hook functions must be of this type
    typedef bool (*hook_func_t)(CPUState *, TranslationBlock *, struct hook* h);

    struct hook{
        target_ulong start_addr;
        target_ulong end_addr;
        target_ulong asid;
        char procname[MAX_PROCNAME_LENGTH];
        char libname[MAX_PROCNAME_LENGTH];
        hook_func_t cb;
        bool enabled;
        bool is_address_library_offset;
    };

    struct hook* add_hook(target_ulong addr, struct hook* h);
    void enable_hooking();
    void disable_hooking();
// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

}
