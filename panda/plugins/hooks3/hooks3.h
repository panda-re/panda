#ifndef HOOKS_3_ONCE
#define HOOKS_3_ONCE
// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
typedef uint32_t PluginReg;
typedef bool (*FnCb)(CPUState*, TranslationBlock*, const struct Hook*);

struct Hook {
    target_ulong pc;
    target_ulong asid;
    PluginReg plugin_num;
    FnCb cb;
    bool always_starts_block;
};


void add_hook3(PluginReg num,
              target_ulong pc,
              target_ulong asid,
              bool always_starts_block,
              FnCb fun);

void unregister_plugin(PluginReg num);

PluginReg register_plugin(void);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif