#pragma once

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

typedef uint32_t PluginNum;

typedef bool (*FaultHookCb)(CPUState *cpu, target_ulong asid, target_ulong page_addr);

PluginNum fault_hooks_register_plugin(void);

void fault_hooks_unregister_plugin(PluginNum num);

void fault_hooks_add_hook(PluginNum plugin_num, target_ulong page_addr, target_ulong asid, FaultHookCb cb);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
