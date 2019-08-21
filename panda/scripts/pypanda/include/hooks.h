// Hook functions must be of this type
typedef bool (*hook_func_t)(CPUState *, TranslationBlock *);

void add_hook(target_ulong addr, hook_func_t hook);
